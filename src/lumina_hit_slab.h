#ifndef LUMINA_HIT_SLAB_H
#define LUMINA_HIT_SLAB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * K3 / VERDICT SLAB  (the "cheatcode" for chained CRS rules)
 *
 * EXACT per-request engine-rule hit map. Size SCALES WITH THE NUMBER OF
 * COMPILED AOT RULES:  LUMINA_SLAB_BITS = ceil(LUMINA_SHORT_RULE_COUNT/64)*64,
 * stored as LUMINA_SLAB_WORDS x uint64 (one word = 64 rule bits). Stack
 * allocated, zero hot-path dynamic allocation.
 *
 * This replaces the old hard-coded 190-bit slab. The 190 cap was the root
 * cause of the fork #5 "broken 196 build": with 196 rules, idx>=190 was
 * silently dropped (no dedup) and idx>=192 wrote past the 3-word array,
 * corrupting the score arena and breaking even existing rules. Now the slab
 * auto-grows with the translator's output and any overflow fails the build
 * (see #error below) instead of corrupting memory.
 *
 * Replaces the previous 384-slot hashed dedup bitmask with an exact per-rule
 * membership map. Hash collisions can no longer suppress rule scoring.
 *
 * RESPONSIBILITY:
 *   - Scanners and the AOT short-rule loop MARK their rule idx when a
 *     pattern matches (lumina_slab_mark).
 *   - The resolver decides verdict. For INDEPENDENT rules it OR-sums each
 *     rule's CRS severity into the anomaly score (parity-preserving: matches
 *     current LUMINA_ADD_SCORE_AND_CHECK behaviour).
 *   - For CHAINED CRS rules (SecRule ... "chain" ...), we fill every
 *     chain-member bit in a single scan pass, then block iff ALL member
 *     bits are set (lumina_slab_chain_hit). This collapses ModSecurity's
 *     sequential O(k) chain evaluation into one fill + a O(1) bit-AND.
 *
 * SOUNDNESS: bit-set semantics are strictly a subset of ModSecurity's; the
 * slab never causes a false POSITIVE block because block still requires the
 * same score threshold / chain-membership that CRS requires.
 * ==========================================================================*/

/* Pull in the generated AOT rule count so the slab sizes itself. Every other
 * translation unit already resolves this same header from src/generated. */
#include "generated/crs_short_rules.h"

#if LUMINA_SHORT_RULE_COUNT > 0
  #define LUMINA_SLAB_BITS  (((LUMINA_SHORT_RULE_COUNT) + 63) / 64 * 64)
#else
  #define LUMINA_SLAB_BITS  256   /* standalone / unit-test fallback ceiling */
#endif
#define LUMINA_SLAB_WORDS   (LUMINA_SLAB_BITS / 64)

#if LUMINA_SHORT_RULE_COUNT > LUMINA_SLAB_BITS
  #error "LUMINA_SHORT_RULE_COUNT exceeds LUMINA_SLAB_BITS — slab overflow would corrupt scoring"
#endif

typedef struct {
    uint64_t bits[LUMINA_SLAB_WORDS]; /* each word covers 64 engine rule indices */
} LuminaHitSlab;

static inline void lumina_slab_clear(LuminaHitSlab *s) {
    for (int i = 0; i < LUMINA_SLAB_WORDS; i++) s->bits[i] = 0;
}

static inline void lumina_slab_mark(LuminaHitSlab *s, int idx) {
    if (idx < 0 || idx >= LUMINA_SLAB_BITS) return;
    s->bits[idx >> 6] |= (1ULL << (idx & 63));
}

static inline bool lumina_slab_test(const LuminaHitSlab *s, int idx) {
    if (idx < 0 || idx >= LUMINA_SLAB_BITS) return false;
    return (s->bits[idx >> 6] >> (idx & 63)) & 1ULL;
}

/* CHAIN CHEAT: true iff every rule idx in chain[0..n) is marked.
 * n==0 returns false (an empty chain never fires). Single pass over n ints,
 * typically n<=4 for CRS chains -> 1-2 cache-line reads. */
static inline bool lumina_slab_chain_hit(const LuminaHitSlab *s, const int *chain, int n) {
    for (int i = 0; i < n; i++) {
        if (!lumina_slab_test(s, chain[i])) return false;
    }
    return n > 0;
}

/* Population count of hits (telemetry / debug only). */
static inline int lumina_slab_popcount(const LuminaHitSlab *s) {
    int c = 0;
    for (int i = 0; i < LUMINA_SLAB_WORDS; i++) c += __builtin_popcountll(s->bits[i]);
    return c;
}

#ifdef __cplusplus
}
#endif

#endif /* LUMINA_HIT_SLAB_H */
