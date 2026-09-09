/*
 * Fixture for inject_all_annotations integration test. Used to exercise the
 * batch annotation injection tool with mixed valid / invalid ACSL specs (covers
 * proposed_requires / proposed_ensures / proposed_assigns /
 * proposed_loop_annots branches). See frama-c-mcp/tests/inject_all_test.rs
 */

void bubble_sort(int *a, int n)
{
    int i, j, tmp;
    for (i = 0; i < n - 1; i++) {
        for (j = 0; j < n - 1 - i; j++) {
            if (a[j] > a[j + 1]) {
                tmp = a[j];
                a[j] = a[j + 1];
                a[j + 1] = tmp;
            }
        }
    }
}
