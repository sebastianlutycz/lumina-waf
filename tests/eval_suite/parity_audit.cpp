#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

extern "C" {
    int lumina_waf_scan(const unsigned char *str, size_t len);
}

std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << int((unsigned char)c);
        }
    }
    return escaped.str();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: parity_audit <dataset_file> <limit>\n";
        return 1;
    }
    std::string filepath = argv[1];
    int limit = argc > 2 ? std::stoi(argv[2]) : 1000000;

    modsecurity::ModSecurity *modsec = new modsecurity::ModSecurity();
    modsecurity::RulesSet *rules = new modsecurity::RulesSet();
    if (rules->loadFromUri("/home/sebastian/workspace/lumina-waf/tests/eval_suite/modsec_1000_rules.conf") < 0) {
        std::cerr << "Failed to load ModSec rules\n";
        return 1;
    }

    std::ifstream file(filepath);
    std::string line;
    int matches = 0;
    int mismatches = 0;
    int count = 0;

    while (std::getline(file, line) && count < limit) {
        int lumina_verdict = lumina_waf_scan(reinterpret_cast<const unsigned char*>(line.c_str()), line.size());
        
        modsecurity::Transaction *trans = new modsecurity::Transaction(modsec, rules, nullptr);
        trans->processConnection("127.0.0.1", 12345, "127.0.0.1", 80);
        
        std::string uri = "http://localhost/test?args=" + url_encode(line);
        trans->processURI(uri.c_str(), "GET", "1.1");
        trans->processRequestHeaders();
        trans->processRequestBody();
        
        modsecurity::ModSecurityIntervention intervention;
        trans->intervention(&intervention);
        int modsec_verdict = (intervention.status == 403) ? 1 : 0;
        int l_verdict = (lumina_verdict > 0) ? 1 : 0;

        if (l_verdict == modsec_verdict) {
            matches++;
        } else {
            mismatches++;
        }
        delete trans;
        count++;
    }

    std::cout << "Audit Complete. Matches: " << matches << ", Mismatches: " << mismatches << "\n";
    return 0;
}
