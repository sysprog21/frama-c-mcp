/*
 * Benchmark fixture for inject_all schema v2 E2E tests. Clean version (no
 * pre-existing RTE asserts) of fv-core L3_readonly_arrays/binary_search.c.
 */

int binary_search(int *a, int x, int n)
{
    int low = -1;
    int high = n;
    while (low + 1 < high) {
        int p = (low + high) / 2;
        if (a[p] == x)
            return p;
        else if (a[p] < x)
            low = p;
        else
            high = p;
    }
    return -1;
}
