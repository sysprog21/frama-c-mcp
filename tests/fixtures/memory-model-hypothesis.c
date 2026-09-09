/*
 * WP proves every goal here and assumes a separation it never checks.
 *
 * The Typed memory model treats "p" and "&g" as distinct locations because it
 * has no reason not to. Frama-C says so, as a warning naming the hypothesis it
 * took, and proves both functions anyway. "caller" passes "&g", which violates
 * it: at run time "g" is 2 and "caller"'s own postcondition is false.
 *
 * Measured on Frama-C 32.1: 11 of 11 goals, every one by Qed.
 */

int g;

/*@ requires \valid(p);
    assigns g, *p;
    ensures g == 1 && *p == 2;
 */
void two(int *p)
{
    g = 1;
    *p = 2;
}

/*@ assigns g;
    ensures g == 1;
 */
void caller(void)
{
    two(&g);
}
