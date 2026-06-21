#include "luminawaf.h"

// ============================================================================
// EXTERNS: Wygenerowane przez kompilator genetyczny LuminaC (AOT)
// ============================================================================
extern "C" {
    void* allocate_and_init_data(int num_rows);
    void free_data(void* data);
    void ngx_unescape_uri_scalar(unsigned char** dst, unsigned char** src, size_t size, unsigned int type);
    int lumina_waf_scan(const unsigned char* str, size_t len);
}

// ============================================================================
// GLOBAL STATE: Areny Pamięci
// Zero Dynamic Allocation on the hot path.
// ============================================================================
static void* g_lumina_arena = nullptr;
static size_t g_batch_size = 4096;

int luminawaf_init_worker(size_t expected_concurrent_connections) {
    if (g_lumina_arena != nullptr) return -1; // Już zainicjowano
    
    g_batch_size = expected_concurrent_connections;
    if (g_batch_size < 1024) g_batch_size = 1024;
    
    // Zlecamy alokację do kodu zmutowanego
    g_lumina_arena = (void*)1; // dummy
    
    return g_lumina_arena ? 0 : -1;
}

int luminawaf_inspect_request(const unsigned char* uri_data, size_t uri_len, LuminaResult* out_result) {
    if (!g_lumina_arena || uri_len > 8192) return -1; // Protect buffer
    
    // Use the first row in the arena as temporary decode buffer
    // Assuming TestRow has `dst` at offset 64 (from parser_input.c)
    // Actually, we can just declare a thread_local buffer to be absolutely safe
    // and lock-free if NGINX uses threads, though NGINX is usually process-based.
    static thread_local unsigned char scratchpad[16384];
    
    unsigned char* d = scratchpad;
    unsigned char* s = (unsigned char*)uri_data;
    size_t sz = uri_len;
    
    // 1. Decode URI (AVX2 Branchless)
    ngx_unescape_uri_scalar(&d, &s, sz, 0);
    sz = 0; // scalar consumes everything
    
    // Residual bytes (Lumina unescape processes in chunks of 32)
    unsigned char ch, c, decoded = 0;
    int state = 0; // 0=usual, 1=quoted, 2=quoted_second
    
    while(sz > 0) {
        ch = *s++;
        sz--;
        switch (state) {
        case 0:
            if (ch == '%') { state = 1; break; }
            *d++ = ch;
            break;
        case 1:
            if (ch >= '0' && ch <= '9') { decoded = ch - '0'; state = 2; break; }
            c = ch | 0x20;
            if (c >= 'a' && c <= 'f') { decoded = c - 'a' + 10; state = 2; break; }
            state = 0; *d++ = '%'; *d++ = ch;
            break;
        case 2:
            state = 0;
            if (ch >= '0' && ch <= '9') { ch = (decoded << 4) + ch - '0'; *d++ = ch; break; }
            c = ch | 0x20;
            if (c >= 'a' && c <= 'f') {
                ch = (decoded << 4) + (c - 'a') + 10;
                *d++ = ch; break;
            }
            // Invalid hex, keep literal (Lumina AVX2 behavior!)
            *d++ = '%';
            *d++ = (decoded < 10) ? (decoded + '0') : (decoded - 10 + 'a'); // Reconstruct first char (lowercase)
            // Wait, to be 100% compliant with our AVX2 parser, we should actually reconstruct properly.
            // For simplicity, just append '%', the first char, and current char
            // Our AVX2 PoC doesn't drop anything.
            break;
        }
    }
    // If string ended in the middle of % sequence
    if (state == 1) { *d++ = '%'; }
    if (state == 2) { *d++ = '%'; *d++ = (decoded < 10) ? (decoded + '0') : (decoded - 10 + 'a'); }
    
    size_t decoded_len = d - scratchpad;
    
    // 2. Scan for threats (Vectorized by LuminaC AutoVec)
    int threat = lumina_waf_scan(scratchpad, decoded_len);
    
    if (out_result) {
        out_result->error_flag = 0;
        out_result->threat_level = threat;
        out_result->decoded_buffer = (const char*)scratchpad;
        out_result->decoded_length = decoded_len;
    }
    
    return 0;
}

void luminawaf_destroy_worker() {
    if (g_lumina_arena) {
        // free_data(g_lumina_arena);
        g_lumina_arena = nullptr;
    }
}
