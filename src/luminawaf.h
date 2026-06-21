#ifndef LUMINAWAF_H
#define LUMINAWAF_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Struktura na wynik parsowania w reżimie C ABI.
 * Gwarantuje brak konieczności alokacji dla małych zwrotów.
 */
typedef struct {
    int error_flag;
    int threat_level;
    const char* decoded_buffer;
    size_t decoded_length;
} LuminaResult;

/*
 * Inicjalizacja stałych aren pamięci przy starcie NGINX Workera.
 * Parametr: oczekiwana ilość równoległych połączeń.
 */
int luminawaf_init_worker(size_t expected_concurrent_connections);

/*
 * Dekodowanie oraz Skanowanie WAF (Wektorowe)
 * Nie dokonuje żadnych alokacji sterty!
 * Wyniki przypisywane są do struktury out_result.
 */
int luminawaf_inspect_request(const unsigned char* uri_data, size_t uri_len, LuminaResult* out_result);

/*
 * Czyszczenie (Zwolnienie pre-alokowanych aren pamięci)
 */
void luminawaf_destroy_worker();

#ifdef __cplusplus
}
#endif

#endif // LUMINAWAF_H
