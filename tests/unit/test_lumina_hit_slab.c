/* Unit self-test for the verdict slab (K3 / chained-rule cheat).
 * Build: gcc -O2 -Wall -I src -o /tmp/test_slab tests/unit/test_lumina_hit_slab.c
 * Expect: all assertions pass, exit 0.
 * Size-agnostic: the slab scales with LUMINA_SHORT_RULE_COUNT, so no
 * hard-coded bit counts here. */
#include "lumina_hit_slab.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
} while (0)

int main(void) {
    LuminaHitSlab s;
    lumina_slab_clear(&s);
    const int MAX = LUMINA_SLAB_BITS - 1;   /* highest valid engine idx */

    /* 1) empty slab: nothing marked, popcount 0 */
    CHECK(lumina_slab_popcount(&s) == 0, "empty popcount");
    CHECK(!lumina_slab_test(&s, 0), "empty bit 0");
    CHECK(!lumina_slab_test(&s, MAX), "empty bit MAX");

    /* 2) bounds: out-of-range mark/test are no-ops, never crash */
    lumina_slab_mark(&s, -1);
    lumina_slab_mark(&s, LUMINA_SLAB_BITS);   /* exactly one past the end */
    lumina_slab_mark(&s, 9999);
    CHECK(lumina_slab_popcount(&s) == 0, "oob mark no-op");

    /* 3) mark independent rules spanning word boundaries */
    lumina_slab_mark(&s, 0);
    lumina_slab_mark(&s, 63);
    lumina_slab_mark(&s, 64);
    lumina_slab_mark(&s, 127);
    lumina_slab_mark(&s, MAX);
    CHECK(lumina_slab_popcount(&s) == 5, "popcount after 5 marks");
    CHECK(lumina_slab_test(&s, 0)   && lumina_slab_test(&s, 63) &&
          lumina_slab_test(&s, 64)  && lumina_slab_test(&s, 127) &&
          lumina_slab_test(&s, MAX), "all marked bits read back");
    CHECK(!lumina_slab_test(&s, 1) && !lumina_slab_test(&s, 100), "unmarked bits still 0");

    /* 4) CHAIN CHEAT: 3-rule chain A(10) -> B(40) -> C(170) */
    LuminaHitSlab c;
    lumina_slab_clear(&c);
    int chain[] = {10, 40, 170};
    CHECK(!lumina_slab_chain_hit(&c, chain, 3), "empty chain does not fire");
    lumina_slab_mark(&c, 10);
    lumina_slab_mark(&c, 40);
    CHECK(!lumina_slab_chain_hit(&c, chain, 3), "partial chain (2/3) does not fire");
    lumina_slab_mark(&c, 170);
    CHECK(lumina_slab_chain_hit(&c, chain, 3), "full chain (3/3) fires");
    CHECK(!lumina_slab_chain_hit(&c, chain, 0), "empty chain array never fires");

    /* 5) chain membership is order-independent (AND is commutative) */
    LuminaHitSlab c2;
    lumina_slab_clear(&c2);
    lumina_slab_mark(&c2, 170);
    lumina_slab_mark(&c2, 10);
    lumina_slab_mark(&c2, 40);
    int chain_rev[] = {170, 40, 10};
    CHECK(lumina_slab_chain_hit(&c2, chain_rev, 3), "chain fires regardless of mark order");

    /* 6) slab size matches the derived word count */
    CHECK(sizeof(LuminaHitSlab) == (size_t)LUMINA_SLAB_WORDS * 8, "slab sized to word count");

    if (failures == 0) {
        printf("OK: verdict slab self-test passed (bits=%d words=%d popcount=%d)\n",
               LUMINA_SLAB_BITS, LUMINA_SLAB_WORDS, lumina_slab_popcount(&s));
        return 0;
    }
    printf("%d FAILURES\n", failures);
    return 1;
}
