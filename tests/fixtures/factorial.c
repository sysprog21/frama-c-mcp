/*
 * Benchmark fixture for inject_all schema v2 E2E tests. Clean version (no
 * pre-existing RTE asserts) of fv-core L2_loops/factorial.c.
 */

int factorial(int n)
{
    int i = 1;
    int f = 1;
    while (i <= n) {
        f *= i;
        i++;
    }
    return f;
}
