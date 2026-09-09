/*
 * From framac.md: loops and loop invariants from minus-loop, find, and
 * max-element. Exercises: loop invariant / loop assigns / loop variant, named
 * invariants, \forall over an array range, `terminates`/`exits` contract
 * clauses.
 */

#include <stddef.h>

typedef size_t size_type;
typedef int value_type;

/* Smallest possible loop specification: one scalar. */
void minus_loop(void)
{
    int x = 0;
    /*@ loop invariant -10 <= x <= 0;
        loop assigns x;
        loop variant x + 10;
    */
    while (x > -10) {
        --x;
    }
}

/*@
  requires   \valid_read(a + (0..n-1));
  terminates \true;
  exits      \false;
  assigns    \nothing;
  ensures    0 <= \result <= n;

  behavior some:
    assumes  \exists integer i; 0 <= i < n && a[i] == v;
    ensures  0 <= \result < n;
    ensures  a[\result] == v;
    ensures  \forall integer i; 0 <= i < \result ==> a[i] != v;

  behavior none:
    assumes  \forall integer i; 0 <= i < n ==> a[i] != v;
    ensures  \result == n;

  complete behaviors;
  disjoint behaviors;
*/
size_type find(const value_type *a, size_type n, value_type v)
{
    /*@
    loop invariant 0 <= i <= n;
    loop invariant \forall integer k; 0 <= k < i ==> a[k] != v;
    loop assigns i;
    loop variant n-i;
   */
    for (size_type i = 0u; i < n; i++) {
        if (a[i] == v) {
            return i;
        }
    }

    return n;
}

/* Named loop invariants (bound/max/upper/first) carrying a running optimum. */
/*@
  requires \valid_read(a + (0..n-1));
  assigns  \nothing;
*/
size_type max_element(const value_type *a, size_type n)
{
    if (0u < n) {
        size_type max = 0u;

        /*@
      loop invariant bound: 0 <= i <= n;
      loop invariant max:   0 <= max <  n;
      loop invariant upper: \forall integer k; 0 <= k < i   ==> a[k] <= a[max];
      loop invariant first: \forall integer k; 0 <= k < max ==> a[k] <  a[max];
      loop assigns max, i;
      loop variant n-i;
    */
        for (size_type i = 1u; i < n; i++) {
            if (a[max] < a[i]) {
                max = i;
            }
        }

        return max;
    }

    return n;
}
