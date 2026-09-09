/*
 * An assertion WP cannot discharge, sitting between the precondition and a
 * postcondition WP can. WP assumes the assertion for everything sequenced after
 * it, so the postcondition comes back proved while resting on it, and Frama-C
 * consolidates that property as valid_under_hyp.
 *
 * The point of the fixture is that both findings are reported against the same
 * goal identity that GOAL_NOT_VALID uses. They are produced on two different
 * paths, one digested from the raw fetchGoals array and one from goals enriched
 * against the property table, and those digests disagree.
 */

/*@ requires n >= 0;
    ensures \result >= 0;
*/
int assumption_carrier(int n)
{
    int x = n;

    /* The first conjunct is what the postcondition leans on, the second is what
     * makes the assertion unprovable. Both are needed: drop the first and the
     * postcondition follows from the precondition alone, so it no longer rests
     * on this assertion and Frama-C consolidates it plain valid.
     */
    //@ assert unprovable_bound: x >= 0 && x < 100;
    return x;
}
