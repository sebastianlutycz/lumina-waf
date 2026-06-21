#include <stdint.h>
#include <stddef.h>
#include "luminawaf.h"

// One-time initialization state for libFuzzer
static bool initialized = false;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!initialized) {
        // Initialize the WAF arenas for a single concurrent connection thread during fuzzing
        luminawaf_init_worker(1);
        initialized = true;
    }

    // We pass the raw fuzzer payload to the inspect request function
    LuminaResult res;
    luminawaf_inspect_request(data, size, &res);

    // Fuzzer goal is just to ensure no crashes/OOM/UB, so we don't assert on `res` fields
    // Returning 0 tells libFuzzer that the input was successfully processed without crashing
    return 0;
}
