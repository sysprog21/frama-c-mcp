/*
 * Fixture for closure ACSL dep scanning tests (callee contract paths).
 *
 * Covers tests in fv-core/src/vcs/closure.rs:
 *   - test_callee_contract_preserved
 *   - test_callee_contract_type_deps_collected
 *   - test_callee_contract_global_var_collected
 *
 * Target = `target_calls_callee`. Callee = `callee_with_rich_contract`. Callee
 * contract references struct Foo (not in target sig) and Gvar g_used. After
 * clone_closure(["target_calls_callee"]) the closure must contain:
 *   - callee as External { contract: Some(_), .. }
 *   - struct Foo in composites
 *   - g_used in prog_defs (as Gvar)
 *   - struct Unused / g_unused must NOT appear
 */

struct Foo {
    int fx;
};
struct Unused {
    int u;
};

int g_used;
int g_unused;

/*@ requires \valid((struct Foo *)p);
    ensures g_used == 0;
    assigns *p, g_used;
 */
void callee_with_rich_contract(int *p)
{
    /* Body is intentional: the contract attaches to Internal (cil_fn_contract).
     * clone_closure will downgrade this to External-with-contract for the
     * closure.
     */
    *p = 0;
    g_used = 0;
}

void target_calls_callee(int *q)
{
    callee_with_rich_contract(q);
}
