/*
 * From framac.md: Linux EAS scheduler case study from linux-eas-verif. Adapted
 * to a self-contained node type so it parses without kernel headers; the ACSL
 * shape is unchanged.
 *
 * Exercises: inductive predicate over a pointer chain, axiomatic uninterpreted
 * logic function modelling an opaque resource, GHOST FUNCTION PARAMETERS, and a
 * callee whose contract deliberately states the same fact twice (bit-level and
 * logic-level) so the solver can pick either view.
 */

#include <limits.h>
#include <stddef.h>

struct mask {
    int bits[64];
};

struct node {
    struct node *parent;
    struct mask *span;
};

/*@
  inductive linked_n{L}(
    struct node *root, struct node **array,
    integer index, integer n, struct node *bound)
  {
    case linked_n_bound{L}:
      \forall struct node **array, *bound, integer index;
        0 <= index < INT_MAX ==>
          linked_n(bound, array, index, 0, bound);

    case linked_n_cons{L}:
      \forall struct node *root, **array, *bound, integer index, n;
        0 < n ==> 0 <= index ==> 0 <= index + n < INT_MAX ==>
        \valid(root) ==> root == array[index] ==>
        linked_n(root->parent, array, index + 1, n - 1, bound) ==>
          linked_n(root, array, index, n, bound);
  }
*/

/*@ axiomatic spans {
    logic struct mask *node_span(struct node *sd);
    logic boolean mask_test(integer cpu, struct mask *m);
  }
*/

/*@ requires \valid_read(sd);
    requires \valid_read(sd->span);
    assigns \nothing;
    ensures \valid_read(\result);
    ensures \result == node_span(sd);
*/
struct mask *node_span_of(struct node *sd);

/* Dual postcondition: the bit-level view and the logic view of the same fact.
 * framac.md notes the proof only closes when both are present.
 */
/*@ requires \valid_read(m);
    requires 0 <= cpu < 64;
    requires \valid_read(m->bits + (0..63));
    assigns \nothing;
    ensures \result <==> m->bits[cpu] != 0;
    ensures (\result != 0) == mask_test(cpu, m);
*/
int mask_test_cpu(int cpu, struct mask *m);

struct node *isolated_loop_1(struct node *sd, int prev_cpu)
/*@ ghost (struct node **array, int index, int n, int loop_index) */
{
    /*@
        loop invariant loop_index_bounds: index <= loop_index <= index + n;
        loop invariant linked: linked_n(sd, array, loop_index, n - loop_index, NULL);
        loop invariant result_is_min: \forall integer j; 0 <= j < loop_index
            ==> !mask_test(prev_cpu, node_span(array[j]));
        loop assigns sd, loop_index;
        loop variant index + n - loop_index;
    */
    while (sd && !mask_test_cpu(prev_cpu, node_span_of(sd))) {
        //@ ghost loop_index++;
        sd = sd->parent;
    }
    return sd;
}
