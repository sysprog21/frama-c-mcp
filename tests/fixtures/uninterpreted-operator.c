/*
 * Align-up by the standard bit trick, which is how allocators round sizes.
 *
 * Every postcondition here is true and none is provable: WP encodes bitwise-or
 * on machine integers as an uninterpreted function rather than a bitvector, so
 * nothing connects ((x - 1) | (align - 1)) + 1 to a multiple of align. Measured
 * with Alt-Ergo 2.6.3, Z3 5.1.0, and cvc5 1.3.4: identical verdicts from all
 * three, cvc5's bitvector support making no difference because no bitvector
 * problem is ever emitted.
 *
 * The fixture exists so the server keeps calling this what it is rather than
 * advising a longer timeout or another solver.
 */
#include <stddef.h>
#include <stdint.h>

/*@
  requires align > 0;
  requires (align & (align - 1)) == 0;
  requires x <= SIZE_MAX - align + 1;
  assigns \nothing;
  ensures \result % align == 0;
  ensures \result >= x;
  ensures \result < x + align;
*/
static size_t align_up(size_t x, size_t align)
{
    return (((x - 1) | (align - 1)) + 1);
}
