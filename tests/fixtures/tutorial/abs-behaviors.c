/*
 * From framac.md: postconditions, preconditions, and behaviors. Exercises:
 * named behaviors, assumes, complete/disjoint behaviors, assigns \nothing,
 * named ensures, and the precondition-ordering trap.
 */

#include <limits.h>

/*@
    requires val > INT_MIN;
    assigns \nothing;
    ensures positive_value: \result >= 0;
    behavior pos:
        assumes 0 <= val;
        ensures \result == val;
    behavior neg:
        assumes val < 0;
        ensures \result == -val;
    complete behaviors;
    disjoint behaviors;
*/
int my_abs(int val)
{
    if (val < 0)
        return -val;
    return val;
}

/* The vacuous-truth trap: once abs(INT_MIN) violates its precondition, WP adds
 * a contradictory hypothesis, so the LINE 2 precondition is "proved" vacuously.
 * Swapping LINE 1 and LINE 2 makes both report. A green result after a violated
 * precondition is meaningless -- an agent must not treat it as progress.
 */
void foo(int a)
{
    int b = my_abs(42);
    int c = my_abs(-42);
    int e = my_abs(INT_MIN); /* LINE 1: precondition violated */
    int d = my_abs(a);       /* LINE 2: reported Valid, but vacuously */
    (void) b;
    (void) c;
    (void) d;
    (void) e;
}
