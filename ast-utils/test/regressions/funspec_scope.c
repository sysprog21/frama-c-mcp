/*
 * Fixture for funspec scope regression.
 *
 * Background: ACSL §2.3 restricts function-level contracts to caller-visible
 * state (formals + globals + \result + \old(formal)). Prior to the find_var
 * Kglobal scope fix, validate_acsl / add_annotation_sandbox accepted funspecs
 * referencing locals such as `assigns i, j, tmp;` because
 * logic_parse_string-style Whole_function scope exposed locals to the funspec
 * typer.
 *
 * Regression contract (see test/regressions/run_funspec_scope.sh):
 * - funspec referencing local var → rejected with "Unbound variable"
 * - funspec referencing formal / global / \result / \old(formal) → accepted
 * - stmt-level annotation referencing local → accepted (loop invariants etc.)
 */

int g;
int g_arr[10];

int helper(int x);

int foo(int *arr, int n)
{
    int i, j, tmp;
    int *p = arr;
    for (i = 0; i < n; i++) {
        for (j = i + 1; j < n; j++) {
            if (arr[i] > arr[j]) {
                tmp = arr[i];
                arr[i] = arr[j];
                arr[j] = tmp;
            }
        }
    }
    return 0;
}
