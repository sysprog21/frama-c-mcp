/*
 * Fixture for closure ACSL dep scanning tests (stmt annotation path).
 *
 * Covers test_stmt_annot_type_deps_collected.
 *
 * Target = `target_with_loop_annot`. Body has loop invariant referencing struct
 * Baz via cast (struct Baz not in signature, not in contract). After
 * clone_closure(["target_with_loop_annot"]):
 *   - struct Baz in composites
 *   - struct UnusedS must NOT appear
 */

struct Baz {
    int bz;
};
struct UnusedS {
    int u;
};

void target_with_loop_annot(int *p, int n)
{
    /*@ loop invariant \valid((struct Baz *)p);
      loop assigns p, n;
     */
    for (int i = 0; i < n; i++) {
        p++;
        n--;
    }
}
