/*
 * A postcondition that fails at runtime, for E-ACSL to catch.
 *
 * `shrink(1)` returns 0, so `ensures \result > 0` is false on the one path
 * `main` takes. WP would report the goal unproved; the point here is different,
 * that a real e-acsl-gcc instruments this, the instrumented program runs, and
 * the failure comes back as a concrete violation rather than as "unproved".
 *
 * Deliberately trivial. This fixture exists to exercise the tool, not to be an
 * interesting verification problem, and anything E-ACSL might choke on for
 * unrelated reasons (allocation, pointers, the memory model) would make a
 * failure ambiguous.
 */

/*@ requires n > 0;
    assigns \nothing;
    ensures \result > 0;
 */
int shrink(int n)
{
    return n - 1;
}

int main(void)
{
    return shrink(1);
}
