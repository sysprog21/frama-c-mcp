/*
 * From framac.md: sorting-correctness case study from tutoriel_wp. Exercises:
 * two-label predicate, inductive predicate with three cases, ghost label
 * statement (`//@ ghost begin: ;`), permutation{Pre, Here} loop invariant, and
 * swap() called with aliased arguments (imin == i).
 */

#include <stddef.h>

/*@
  predicate sorted(int *a, integer b, integer e) =
    \forall integer i, j; b <= i <= j < e ==> a[i] <= a[j];

  predicate swap_in_array{L1,L2}(int *a, integer b, integer e, integer i, integer j) =
    b <= i < e && b <= j < e &&
    \at(a[i], L1) == \at(a[j], L2) &&
    \at(a[j], L1) == \at(a[i], L2) &&
    \forall integer k; b <= k < e && k != i && k != j ==>
      \at(a[k], L1) == \at(a[k], L2);

  inductive permutation{L1,L2}(int *a, integer b, integer e) {
  case reflexive{L1}:
    \forall int *a, integer b, e; permutation{L1,L1}(a, b, e);
  case swap{L1,L2}:
    \forall int *a, integer b, e, i, j;
      swap_in_array{L1,L2}(a, b, e, i, j) ==> permutation{L1,L2}(a, b, e);
  case transitive{L1,L2,L3}:
    \forall int *a, integer b, e;
      permutation{L1,L2}(a, b, e) && permutation{L2,L3}(a, b, e) ==>
        permutation{L1,L3}(a, b, e);
  }
*/

/*@ requires \valid(a) && \valid(b);
    assigns *a, *b;
    ensures *a == \old(*b) && *b == \old(*a);
*/
void swap(int *a, int *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

/*@ requires beg < end && \valid_read(a + (beg .. end-1));
    assigns \nothing;
    ensures beg <= \result < end;
    ensures \forall integer k; beg <= k < end ==> a[\result] <= a[k];
*/
size_t min_idx_in(int *a, size_t beg, size_t end);

/*@
  requires beg < end && \valid(a + (beg .. end-1));
  assigns  a[beg .. end-1];
  ensures  sorted(a, beg, end);
  ensures  permutation{Pre, Post}(a, beg, end);
*/
void sort(int *a, size_t beg, size_t end)
{
    /*@
    loop invariant beg <= i <= end;
    loop invariant sorted(a, beg, i) && permutation{Pre, Here}(a, beg, end);
    loop invariant \forall integer j, k; beg <= j < i ==> i <= k < end ==> a[j] <= a[k];
    loop assigns i, a[beg .. end-1];
    loop variant end - i;
  */
    for (size_t i = beg; i < end; ++i) {
        //@ ghost begin: ;
        size_t imin = min_idx_in(a, i, end);
        swap(&a[i], &a[imin]);
        //@ assert swap_in_array{begin, Here}(a, beg, end, i, imin);
    }
}
