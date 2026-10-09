/*
 * Fixture for run-recursive-logic.sh: one definition of each shape. The mutual
 * case is in the script, because the kernel rejects it at parse time and every
 * .c file here must parse for run.sh.
 */

/* Direct recursion with no decreasing argument: an inconsistent axiom. */
/*@ logic integer bad(integer n) = bad(n) + 1; */

/* Direct recursion inside an axiomatic block. It terminates, which this request
 * does not try to decide: it is reported all the same.
 */
/*@ axiomatic Fact {
      logic integer fact(integer n) = n <= 0 ? 1 : n * fact(n - 1);
    }
*/

/* Not recursive, though it calls another definition. */
/*@ logic integer twice(integer n) = n + n;
    logic integer quad(integer n) = twice(twice(n));
*/

/* Inductive: a least fixpoint, consistent by construction, even though its
 * cases mention it.
 */
/*@ inductive reach(integer a, integer b) {
      case refl: \forall integer a; reach(a, a);
      case step: \forall integer a, b; reach(a + 1, b) ==> reach(a, b);
    }
*/

/* Defined with a body that uses the inductive, so it is a node with an edge to
 * a non-node, and not recursive.
 */
/*@ predicate reach_next(integer a) = reach(a, a + 1); */

int main(void)
{
    return 0;
}
