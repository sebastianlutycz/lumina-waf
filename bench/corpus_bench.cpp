#include <benchmark/benchmark.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include "luminawaf.h"

// Memory mapped dataset
struct MappedDataset {
    char* data = nullptr;
    size_t size = 0;
    std::vector<std::string_view> lines;

    bool load(const char* filepath) {
        int fd = open(filepath, O_RDONLY);
        if (fd < 0) return false;

        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            return false;
        }
        size = st.st_size;

        data = (char*)mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);

        if (data == MAP_FAILED) return false;

        // Parse lines
        size_t start = 0;
        for (size_t i = 0; i < size; ++i) {
            if (data[i] == '\n') {
                lines.emplace_back(data + start, i - start);
                start = i + 1;
            }
        }
        if (start < size) {
            lines.emplace_back(data + start, size - start);
        }
        return true;
    }

    ~MappedDataset() {
        if (data && data != MAP_FAILED) {
            munmap(data, size);
        }
    }
};

static MappedDataset dataset;

static void BM_Corpus_Throughput(benchmark::State& state) {
    if (dataset.lines.empty()) {
        state.SkipWithError("Dataset not loaded");
        return;
    }

    luminawaf_init_worker(1);

    size_t line_idx = 0;
    LuminaResult res;

    for (auto _ : state) {
        std::string_view line = dataset.lines[line_idx];
        luminawaf_inspect_request(reinterpret_cast<const unsigned char*>(line.data()), line.length(), &res);
        benchmark::DoNotOptimize(res);

        line_idx++;
        if (line_idx >= dataset.lines.size()) {
            line_idx = 0;
        }
    }

    state.SetBytesProcessed(int64_t(state.iterations()) * int64_t(dataset.size / dataset.lines.size()));
}

int main(int argc, char** argv) {
    // Attempt to load the dataset
    if (!dataset.load("tests/eval_suite/dataset_1m_seclists.txt")) {
        std::cerr << "Warning: Could not load tests/eval_suite/dataset_1m_seclists.txt. Benchmark may fail." << std::endl;
    }

    benchmark::Initialize(&argc, argv);
    benchmark::RegisterBenchmark("BM_Corpus_Throughput", BM_Corpus_Throughput);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
