/*
 * A false postcondition that only an axiom discharges.
 *
 * `uncalled` returns n, so `ensures \result == n + 1` is false. It is not
 * reachable from `main`, which is the point: EVA leaves it alone rather than
 * disproving it, so the property carries no status and WP does emit a goal for
 * it. Without the axiom that goal does not close and `check` reports
 * GOAL_NOT_VALID. With `axiom bogus: \false;` in scope, WP discharges it and
 * every other goal, and `check` used to answer "proved" with an empty
 * `incomplete`.
 *
 * WP assumes an axiom while proving everything else and never asks whether it
 * holds, so the axiom has to be reported as the assumption it is. Delete the
 * axiom line to get the control: verdict incomplete, naming the postcondition.
 */

/*@ axiom bogus: \false; */

/*@ requires n >= 0;
    assigns \nothing;
    ensures \result == n + 1;
 */
int uncalled(int n)
{
    return n;
}

int main(void)
{
    return 0;
}
