#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <iostream>

extern "C" {
    // Odwołanie do kodu z src/parser_scalar.c
    void ngx_unescape_uri_scalar(unsigned char **dst, unsigned char **src, size_t size, unsigned int type);
    
    // Odwołanie do wygenerowanego obiektu z LuminaC (parser_v3.o)
    void lumina_unescape_uri_avx2(unsigned char **dst, unsigned char **src, size_t *size);
}

// Funkcja wejściowa Fuzzera
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // AVX2 wg implementacji rusza tylko od 33 bajtów w zwyż.
    if (Size < 33 || Size > 1024 * 1024) return 0;

    // Kopie danych wejściowych
    std::vector<uint8_t> in_scalar(Data, Data + Size);
    std::vector<uint8_t> in_lumina(Data, Data + Size);

    // Bufory wyjściowe (bezpieczny zapas)
    std::vector<uint8_t> out_scalar(Size * 3, 0);
    std::vector<uint8_t> out_lumina(Size * 3, 0);

    // ==========================================
    // 1. Uruchomienie Ground Truth (NGINX Scalar)
    // ==========================================
    unsigned char* s_scalar = in_scalar.data();
    unsigned char* d_scalar = out_scalar.data();
    ngx_unescape_uri_scalar(&d_scalar, &s_scalar, Size, 0);
    size_t out_len_scalar = d_scalar - out_scalar.data();

    // ==========================================
    // 2. Uruchomienie mutanta z LuminaC (AVX2 + Prefetch)
    // ==========================================
    unsigned char* s_lumina = in_lumina.data();
    unsigned char* d_lumina = out_lumina.data();
    size_t sz_lumina = Size;
    
    // Wektorowy FAST PATH (błyskawicznie "zjada" chunk'i 32-bajtowe)
    lumina_unescape_uri_avx2(&d_lumina, &s_lumina, &sz_lumina);
    
    // Jeżeli zostały ogony (sz_lumina < 33 bajtów), dokańczamy je skalarem
    if (sz_lumina > 0) {
        ngx_unescape_uri_scalar(&d_lumina, &s_lumina, sz_lumina, 0);
    }
    size_t out_len_lumina = d_lumina - out_lumina.data();

    // ==========================================
    // 3. Weryfikacja Zero Trust (Bit-Perfect Validation)
    // ==========================================
    if (out_len_scalar != out_len_lumina) {
        std::cerr << "CRASH: Oczekiwano dlugosci " << out_len_scalar << ", otrzymano " << out_len_lumina << "\n";
        abort();
    }

    if (memcmp(out_scalar.data(), out_lumina.data(), out_len_scalar) != 0) {
        std::cerr << "CRASH: Zawartosc zdekodowanego buffora NGINX i LuminaC rozni sie!\n";
        abort();
    }

    return 0;
}
