/*
 * Regression for extractFunctionWithDeps dropping a non-void callee's ACSL
 * contract reached via CIL's ConsInit path.
 *
 * `caller` captures the return value of `compute` into a local (`int r =
 * compute(x);`). CIL normalises this into `Local_init(r, ConsInit( compute,
 * args, _))`, where the callee varinfo is visited through `visitCilVarUse` →
 * the visitor's `vvrbl` method, NOT through `vlval`.
 *
 * Before the `vvrbl` handler (#114), `collect_visitor` only overrode `vlval`,
 * so the ConsInit callee was silently skipped and `compute`'s contract was
 * missing from the extracted sandbox → downstream WP verified `caller` against
 * a callee with default `assigns \nothing` (unsound).
 *
 * Contrast: a void / discarded-result call (`compute(x);` or `return f(p);`)
 * goes through `vlval` and was already collected — see extract_spec_deps.c.
 */

/*@ requires x >= 0;
    assigns \nothing;
    ensures \result == x + 1;
 */
int compute(int x)
{
    return x + 1;
}

int caller(int x)
{
    int r = compute(x); /* non-void call, result captured → ConsInit/vvrbl */
    return r;
}
