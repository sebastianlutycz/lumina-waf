#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <modsecurity/intervention.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rule_message.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

#include "luminawaf.h"

namespace {

std::string default_rules_path() {
    const char *path = std::getenv("LUMINA_BENCH_V1_MODSEC_CONFIG");
    return path == nullptr ? std::string() : std::string(path);
}

struct Options {
    std::string dataset_path;
    std::string rules_path = default_rules_path();
    int limit = 1000000;
    bool json = false;
    bool benign = false;
};

struct Sample {
    std::string id;
    std::string category = "UNKNOWN";
    std::string payload;
};

struct MatrixCell {
    int lb_mb = 0;
    int lb_ma = 0;
    int la_mb = 0;
    int la_ma = 0;
};

void discard_modsec_log(void *, const void *) {}

std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex << std::uppercase;
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << static_cast<char>(c);
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(c);
        }
    }
    return escaped.str();
}

std::string sanitize(const std::string &s, size_t max_len) {
    std::string out = s.substr(0, max_len);
    for (char &c : out) {
        if (c == '\n' || c == '\r' || c == '|') c = ' ';
    }
    return out;
}

std::string json_escape(const std::string &s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c) << std::dec << std::setfill(' ');
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void append_utf8(std::string &out, unsigned int cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

bool extract_json_string_field(const std::string &line, const std::string &field, std::string &out) {
    const std::string key = "\"" + field + "\"";
    size_t pos = line.find(key);
    if (pos == std::string::npos) return false;
    pos = line.find(':', pos + key.size());
    if (pos == std::string::npos) return false;
    pos = line.find('"', pos + 1);
    if (pos == std::string::npos) return false;
    ++pos;

    out.clear();
    while (pos < line.size()) {
        char c = line[pos++];
        if (c == '"') return true;
        if (c != '\\') {
            out.push_back(c);
            continue;
        }
        if (pos >= line.size()) break;
        char esc = line[pos++];
        switch (esc) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                if (pos + 4 > line.size()) return false;
                unsigned int cp = 0;
                for (int i = 0; i < 4; ++i) {
                    int v = hex_value(line[pos++]);
                    if (v < 0) return false;
                    cp = (cp << 4) | static_cast<unsigned int>(v);
                }
                append_utf8(out, cp);
                break;
            }
            default:
                out.push_back(esc);
        }
    }
    return false;
}

Sample parse_sample_line(const std::string &line, int index) {
    Sample sample;
    sample.id = "line-" + std::to_string(index);
    sample.payload = line;

    if (!line.empty() && line[0] == '{') {
        std::string payload;
        if (extract_json_string_field(line, "payload", payload)) {
            sample.payload = payload;
        }
        std::string category;
        if (extract_json_string_field(line, "category", category) && !category.empty()) {
            sample.category = category;
        }
        std::string id;
        if (extract_json_string_field(line, "id", id) && !id.empty()) {
            sample.id = id;
        }
    }
    return sample;
}

bool parse_options(int argc, char **argv, Options &opt) {
    opt.json = std::getenv("LUMINA_PARITY_JSON") != nullptr;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            opt.json = true;
        } else if (arg == "--benign") {
            opt.benign = true;
        } else if (arg == "--rules" && i + 1 < argc) {
            opt.rules_path = argv[++i];
        } else if (arg == "--limit" && i + 1 < argc) {
            opt.limit = std::stoi(argv[++i]);
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        } else {
            opt.dataset_path = arg;
        }
    }
    if (opt.dataset_path.empty()) {
        std::cerr << "Usage: parity_audit [--json] [--benign] [--rules file] [--limit N] <dataset_file>\n";
        return false;
    }
    if (opt.rules_path.empty()) {
        std::cerr << "Provide --rules or set LUMINA_BENCH_V1_MODSEC_CONFIG\n";
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char **argv) {
    Options opt;
    if (!parse_options(argc, argv, opt)) return 1;

    modsecurity::ModSecurity modsec;
    modsec.setServerLogCb(discard_modsec_log);
    modsecurity::RulesSet rules;
    const int load_rc = rules.loadFromUri(opt.rules_path.c_str());
    if (load_rc < 0) {
        std::cerr << "Failed to load ModSecurity rules from " << opt.rules_path
                  << ": " << rules.m_parserError.str() << "\n";
        return 1;
    }

    std::ifstream file(opt.dataset_path);
    if (!file) {
        std::cerr << "Failed to open dataset: " << opt.dataset_path << "\n";
        return 1;
    }

    int samples = 0;
    int matches = 0;
    int mismatches = 0;
    int lumina_blocks = 0;
    int modsec_blocks = 0;
    long long lumina_us_total = 0;
    long long modsec_us_total = 0;
    std::map<std::string, MatrixCell> matrix;

    std::string line;
    while (std::getline(file, line) && samples < opt.limit) {
        if (line.empty()) continue;
        ++samples;
        Sample sample = parse_sample_line(line, samples);
        std::string uri_path = "/test?args=" + url_encode(sample.payload);
        LuminaResult lumina_result{};
        auto l0 = std::chrono::steady_clock::now();
        LuminaRuleState state; memset(&state, 0, sizeof(state));
        luminawaf_inspect_buffer(reinterpret_cast<const unsigned char *>(sample.payload.data()),
                                 sample.payload.size(), LUMINA_SCOPE_URI, LUMINA_VAR_ARGS, &state, &lumina_result);
        auto l1 = std::chrono::steady_clock::now();
        const int lumina_block = (lumina_result.threat_level != 0) ? 1 : 0;
        lumina_us_total += std::chrono::duration_cast<std::chrono::microseconds>(l1 - l0).count();

        modsecurity::Transaction trans(&modsec, &rules, nullptr);
        auto m0 = std::chrono::steady_clock::now();
        trans.processConnection("127.0.0.1", 12345, "127.0.0.1", 80);
        trans.addRequestHeader("Host", "localhost");
        trans.addRequestHeader("User-Agent", "LuminaIronBenchmark/9");
        trans.processURI(uri_path.c_str(), "GET", "1.1");
        trans.processRequestHeaders();
        trans.processRequestBody();
        modsecurity::ModSecurityIntervention intervention;
        modsecurity::intervention::clean(&intervention);
        trans.intervention(&intervention);
        auto m1 = std::chrono::steady_clock::now();
        const int modsec_block = (intervention.disruptive != 0) ? 1 : 0;
        modsec_us_total += std::chrono::duration_cast<std::chrono::microseconds>(m1 - m0).count();

        lumina_blocks += lumina_block;
        modsec_blocks += modsec_block;
        MatrixCell &cell = matrix[sample.category];
        if (lumina_block && modsec_block) cell.lb_mb++;
        else if (lumina_block && !modsec_block) cell.lb_ma++;
        else if (!lumina_block && modsec_block) cell.la_mb++;
        else cell.la_ma++;

        if (lumina_block == modsec_block) {
            ++matches;
        } else {
            ++mismatches;
            std::string rule_ids;
            for (auto &rm : trans.m_rulesMessages) {
                if (!rule_ids.empty()) rule_ids += ",";
                rule_ids += std::to_string(rm.m_ruleId);
            }
            if (rule_ids.empty()) rule_ids = "NO_RULE";
            std::cerr << "PARITY_MISMATCH|ID:" << sample.id
                      << "|CATEGORY:" << sanitize(sample.category, 80)
                      << "|RULE:" << rule_ids
                      << "|MODSEC:" << (modsec_block ? "BLOCK" : "ALLOW")
                      << "|LUMINA:" << (lumina_block ? "BLOCK" : "ALLOW")
                      << "|LUMINA_THREAT:" << lumina_result.threat_level
                      << "|PAYLOAD:" << sanitize(sample.payload, 200) << "\n";
        }

        modsecurity::intervention::free(&intervention);
        if (!opt.json && samples % 1000 == 0) {
            std::cerr << "count=" << samples << " matches=" << matches
                      << " mismatches=" << mismatches << "\n";
        }
    }

    const double parity_pct = samples ? (100.0 * static_cast<double>(matches) / samples) : 0.0;
    const double lumina_avg_us = samples ? static_cast<double>(lumina_us_total) / samples : 0.0;
    const double modsec_avg_us = samples ? static_cast<double>(modsec_us_total) / samples : 0.0;

    if (opt.json) {
        std::cout << "{\n";
        std::cout << "  \"samples\": " << samples << ",\n";
        std::cout << "  \"matches\": " << matches << ",\n";
        std::cout << "  \"mismatches\": " << mismatches << ",\n";
        std::cout << "  \"parity_pct\": " << std::fixed << std::setprecision(4) << parity_pct << ",\n";
        std::cout << "  \"benign\": " << (opt.benign ? "true" : "false") << ",\n";
        std::cout << "  \"rules_path\": \"" << json_escape(opt.rules_path) << "\",\n";
        std::cout << "  \"threshold\": " << LUMINA_ANOMALY_THRESHOLD << ",\n";
        std::cout << "  \"lumina_blocks\": " << lumina_blocks << ",\n";
        std::cout << "  \"modsec_blocks\": " << modsec_blocks << ",\n";
        std::cout << "  \"latency_us\": {\"lumina_avg\": " << std::setprecision(3) << lumina_avg_us
                  << ", \"modsec_avg\": " << modsec_avg_us << "},\n";
        std::cout << "  \"matrix\": {\n";
        bool first = true;
        for (const auto &kv : matrix) {
            if (!first) std::cout << ",\n";
            first = false;
            const MatrixCell &c = kv.second;
            std::cout << "    \"" << json_escape(kv.first) << "\": {"
                      << "\"LB_MB\": " << c.lb_mb << ", "
                      << "\"LB_MA\": " << c.lb_ma << ", "
                      << "\"LA_MB\": " << c.la_mb << ", "
                      << "\"LA_MA\": " << c.la_ma << "}";
        }
        std::cout << "\n  }\n";
        std::cout << "}\n";
    } else {
        std::cout << "Audit Complete. Samples: " << samples
                  << ", Matches: " << matches
                  << ", Mismatches: " << mismatches
                  << ", Parity: " << std::fixed << std::setprecision(2) << parity_pct << "%\n";
    }

    return 0;
}
