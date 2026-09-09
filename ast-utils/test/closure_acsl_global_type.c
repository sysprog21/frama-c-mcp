/*
 * Fixture for closure ACSL dep scanning tests (acsl_globals path).
 *
 * Covers test_acsl_global_struct_dep_collected.
 *
 * Target = `target_does_not_touch_struct`. Target neither uses struct Node in
 * signature, body, nor its own contract. But acsl_globals contains a predicate
 * `node_valid` whose parameter type is `struct Node*`. Since acsl_globals is
 * wholesale-cloned into the closure, struct Node must also be pulled in to keep
 * the closure self-consistent.
 *
 * After clone_closure(["target_does_not_touch_struct"]):
 *   - struct Node in composites (via collect_logic_def_deps)
 *   - struct UnusedG must NOT appear
 */

struct Node {
    int n_data;
};
struct UnusedG {
    int u;
};

/*@ predicate node_valid(struct Node *n) = n != \null; */

void target_does_not_touch_struct(int x)
{
    int y = x + 1;
    (void) y;
}
