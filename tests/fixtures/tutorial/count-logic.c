/*
 * From framac.md: predicates, logic functions, and axioms from ACSL by Example.
 * Exercises GLOBAL ACSL, which no MCP tool can currently inject: overloaded
 * predicates, labelled predicate {L}, recursive logic functions,
 * default-argument overloads, and lemmas.
 */

#include <stddef.h>

typedef size_t size_type;
typedef int value_type;

/*@
  predicate AllEqual(value_type *a, integer m, integer n, value_type v) =
    \forall integer i; m <= i < n ==> a[i] == v;

  predicate AllEqual(value_type *a, integer n, value_type v) =
    AllEqual(a, 0, n, v);

  predicate SomeNotEqual{L}(value_type *a, integer m, integer n, value_type v) =
    \exists integer i; m <= i < n && \at(a[i], L) != v;

  lemma NotAllEqual_SomeNotEqual:
    \forall value_type *a, v, integer m, n;
      !AllEqual(a, m, n, v) ==> SomeNotEqual(a, m, n, v);
*/

/*@
  logic integer
  Count(value_type *a, integer m, integer n, value_type v) =
    n <= m ? 0 : Count(a, m, n-1, v) + (a[n-1] == v ? 1 : 0);

  logic integer
  Count(value_type *a, integer n, value_type v) = Count(a, 0, n, v);

  lemma Count_Bounds:
    \forall value_type *a, v, integer m, n;
      0 <= m <= n ==> 0 <= Count(a, m, n, v) <= n-m;

  lemma Count_Union:
    \forall value_type *a, v, integer m, p, n;
      m <= p <= n ==>
      Count(a, m, n, v) == Count(a, m, p, v) + Count(a, p, n, v);
*/

/*@
  requires \valid_read(a + (0..n-1));
  assigns  \nothing;
  ensures  \result == Count(a, n, v);
*/
size_type count(const value_type *a, size_type n, value_type v)
{
    size_type counted = 0u;

    /*@
    loop invariant bound: 0 <= i <= n;
    loop invariant count: counted == Count(a, i, v);
    loop assigns i, counted;
    loop variant n-i;
  */
    for (size_type i = 0u; i < n; ++i) {
        if (a[i] == v) {
            counted++;
        }
    }

    return counted;
}
