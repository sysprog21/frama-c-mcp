/*
 * A postcondition EVA can disprove on its own.
 *
 * `identity` returns n, so `ensures \result == n + 1` is false, and EVA says
 * so: the property comes back `invalid_under_hyp`. WP then emits no goal for
 * it, because it generates obligations only for properties that do not already
 * carry a status. The clause therefore appeared in neither `wp_goals` nor the
 * alarm accounting, and `check` answered "proved" over it.
 *
 * `main` is here so EVA has an entry point and reaches the call. Without it EVA
 * aborts and the run reports EVA_NOT_RUN, which would hide the gap behind a
 * different one.
 */

/*@ requires n >= 0;
    assigns \nothing;
    ensures \result == n + 1;
 */
int identity(int n)
{
    return n;
}

int main(void)
{
    return identity(1);
}
