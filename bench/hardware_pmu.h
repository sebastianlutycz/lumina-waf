#ifndef HARDWARE_PMU_H
#define HARDWARE_PMU_H

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdexcept>
#include <benchmark/benchmark.h>

class PmuProfiler {
private:
    int fd_cycles;
    int fd_instr;
    int fd_branches;
    int fd_branch_misses;

    long long val_cycles = 0;
    long long val_instr = 0;
    long long val_branches = 0;
    long long val_branch_misses = 0;

    int perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
        return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
    }

    int open_counter(uint32_t type, uint64_t config, int group_fd = -1) {
        struct perf_event_attr pe;
        memset(&pe, 0, sizeof(struct perf_event_attr));
        pe.type = type;
        pe.size = sizeof(struct perf_event_attr);
        pe.config = config;
        pe.disabled = 1;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;
        pe.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;

        int fd = perf_event_open(&pe, 0, -1, group_fd, 0);
        if (fd == -1) {
            // Silently ignore if PMU is not available (e.g. inside Docker without --privileged)
        }
        return fd;
    }

public:
    PmuProfiler() {
        fd_cycles = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
        fd_instr = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
        fd_branches = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS);
        fd_branch_misses = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES);
    }

    ~PmuProfiler() {
        if (fd_cycles != -1) close(fd_cycles);
        if (fd_instr != -1) close(fd_instr);
        if (fd_branches != -1) close(fd_branches);
        if (fd_branch_misses != -1) close(fd_branch_misses);
    }

    void start() {
        if (fd_cycles != -1) {
            ioctl(fd_cycles, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
        }
        if (fd_instr != -1) {
            ioctl(fd_instr, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd_instr, PERF_EVENT_IOC_ENABLE, 0);
        }
        if (fd_branches != -1) {
            ioctl(fd_branches, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd_branches, PERF_EVENT_IOC_ENABLE, 0);
        }
        if (fd_branch_misses != -1) {
            ioctl(fd_branch_misses, PERF_EVENT_IOC_RESET, 0);
            ioctl(fd_branch_misses, PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    void stop() {
        if (fd_cycles != -1) {
            ioctl(fd_cycles, PERF_EVENT_IOC_DISABLE, 0);
            if(read(fd_cycles, &val_cycles, sizeof(long long))){}
        }
        if (fd_instr != -1) {
            ioctl(fd_instr, PERF_EVENT_IOC_DISABLE, 0);
            if(read(fd_instr, &val_instr, sizeof(long long))){}
        }
        if (fd_branches != -1) {
            ioctl(fd_branches, PERF_EVENT_IOC_DISABLE, 0);
            if(read(fd_branches, &val_branches, sizeof(long long))){}
        }
        if (fd_branch_misses != -1) {
            ioctl(fd_branch_misses, PERF_EVENT_IOC_DISABLE, 0);
            if(read(fd_branch_misses, &val_branch_misses, sizeof(long long))){}
        }
    }

    void report_to_benchmark(benchmark::State& state) {
        if (fd_cycles != -1 && val_cycles > 0) {
            state.counters["IPC"] = (double)val_instr / val_cycles;
        }
        if (fd_branch_misses != -1 && val_branches > 0) {
            state.counters["BranchMissRate"] = (double)val_branch_misses / val_branches;
        }
    }
};

#endif // HARDWARE_PMU_H
