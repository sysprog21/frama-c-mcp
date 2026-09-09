/*
 * A lemma WP cannot discharge, next to a postcondition that is plainly false.
 * WP assumes every lemma while proving everything else, so `\false` here makes
 * `\result == 42` provable: `frama-c -wp` reports 4 of 5 goals proved, the one
 * failure being the lemma itself. Delete the lemma and the postcondition fails
 * instead, which is the control.
 *
 * `check` reported `proved` on this file for a while. The lemma property is
 * `kind: "lemma"` with status `never_tried` whenever no goal covers it, which
 * is what a run scoped to one function leaves behind, and a function filter
 * used to drop it from the property table as well.
 */

/*@ lemma unprovable: \false; */

/* A lemma WP does discharge, so a run that reports the one above has to stay
 * quiet about this one. Reporting every lemma would be easy and useless.
 */
/*@ lemma provable: \forall integer i; i + 0 == i; */

/*@ requires \true;
    assigns  \nothing;
    ensures  \result == 42;
 */
int lemma_dependent(int x)
{
    return x;
}
