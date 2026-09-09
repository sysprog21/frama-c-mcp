/*
 * From framac.md: pointers, side effects, aliasing, and memory history.
 * Exercises: \valid, \valid_read, \old, \at + labels, assigns frame condition,
 * \separated, aliasing.
 */

#include <limits.h>

int h = 42;

/*@
    requires \valid(a) && \valid(b);
    assigns *a, *b;
    ensures *a == \old(*b);
    ensures *b == \old(*a);
*/
void swap(int *a, int *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

/* Without `assigns`, WP must assume h may change and the second assert fails.
 */
int main(void)
{
    int a = 37;
    int b = 91;

    //@ assert h == 42;
    swap(&a, &b);
    //@ assert h == 42;

    return 0;
}

/* Aliasing matters here: without \separated, *b may be written through a. */
/*@
    requires \valid(a) && \valid_read(b);
    requires \separated(a, b);
    requires INT_MIN <= *a + *b <= INT_MAX;
    assigns *a;
    ensures *a == \old(*a) + *b;
    ensures *b == \old(*b);
*/
void incr_a_by_b(int *a, int const *b)
{
    *a += *b;
}

/* \at with a C label and the ACSL builtin label Pre. */
/*@ requires \valid(x + (0..2)) && \valid(p);
    requires x + 2 != p;
    assigns *p;
*/
void at_labels(int *x, int *p)
{
    *p = 2;
    //@ assert x[2] == \at(x[2], Pre);
    /* Provable only for the first assert: \at(x[*p], Pre) evaluates *p at Pre.
     */
}

/* order_3: \separated over three pointers, behaviour under permutation. */
/*@
    requires \valid(a) && \valid(b) && \valid(c);
    requires \separated(a, b, c);
    assigns *a, *b, *c;
    ensures *a <= *b <= *c;
*/
void order_3(int *a, int *b, int *c)
{
    if (*a > *b) {
        int tmp = *b;
        *b = *a;
        *a = tmp;
    }
    if (*a > *c) {
        int tmp = *c;
        *c = *a;
        *a = tmp;
    }
    if (*b > *c) {
        int tmp = *b;
        *b = *c;
        *c = tmp;
    }
}
