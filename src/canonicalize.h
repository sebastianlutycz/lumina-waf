#ifndef LUMINA_CANONICALIZE_H
#define LUMINA_CANONICALIZE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Zwraca zdekodowany i skanonizowany bufor.
 * Wykorzystuje Thread-Local Storage dla zapytań < 64KB, w przeciwnym razie robi malloc.
 * Użytkownik musi wywołać lumina_canonicalize_free, jeśli is_malloc == 1.
 * 
 * @param in - wejściowy bufor
 * @param len - długość wejścia
 * @param out_len - ustawiana przez funkcję długość zdekodowanego bufora
 * @param is_malloc - ustawiana na 1, jeśli bufor wymaga zwolnienia via free()
 * @return - wskaźnik do zdekodowanego bufora
 */
unsigned char* lumina_canonicalize(const unsigned char* in, size_t len, uint32_t flags, size_t* out_len, int* is_malloc);

/**
 * Czyści pamięć, jeśli była zaalokowana przez malloc.
 */
void lumina_canonicalize_free(unsigned char* buf, int is_malloc);

#ifdef __cplusplus
}
#endif

#endif // LUMINA_CANONICALIZE_H
