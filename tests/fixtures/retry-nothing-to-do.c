/*
 * A function whose obligations all discharge, so a retry asked for here has
 * nothing to retry. The contract is what makes that true rather than vacuous:
 * without it WP generates no prover obligation at all, and the retry would be
 * skipped for want of goals rather than for want of a timeout.
 *
 * Its own file rather than a second function beside "slow": adding one to
 * prover-timeout.c changed what WP generated for that whole file, and the
 * timeout the other test depends on stopped happening.
 */
/*@ requires 0 <= a <= 100;
    ensures \result == a + 1;
 */
int fast(int a)
{
    return a + 1;
}
