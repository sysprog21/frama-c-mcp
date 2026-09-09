/*
 * Whole-program MCP workflow fixture extending the modular tutorial group. It
 * keeps function names unique so persisted conclusions from other tutorial
 * tests cannot affect bottom-up scheduling assertions.
 */

#include <limits.h>

int mod_e2e_global_limit = 16;

/*@ requires val > INT_MIN;
    assigns \nothing;
    ensures \result >= 0;
*/
int mod_e2e_abs(int val)
{
    if (val < 0)
        return -val;
    return val;
}

/*@ assigns \nothing;
    ensures \result >= a && \result >= b;
    ensures \result == a || \result == b;
*/
int mod_e2e_max(int a, int b)
{
    return (a > b) ? a : b;
}

int mod_e2e_loop_abs_max(int *values, int n)
{
    int i = 0;
    int best = 0;
    while (i < n) {
        best = mod_e2e_max(best, mod_e2e_abs(values[i]));
        i++;
    }
    return best;
}

int mod_e2e_even(int n);
int mod_e2e_odd(int n);

int mod_e2e_even(int n)
{
    return n <= 0 ? 1 : mod_e2e_odd(n - 1);
}

int mod_e2e_odd(int n)
{
    return n <= 0 ? 0 : mod_e2e_even(n - 1);
}

/*@ requires 0 <= x < INT_MAX;
    assigns \nothing;
    ensures \result >= 0;
*/
int mod_e2e_weak_inc(int x)
{
    return x + 1;
}

/*@ requires 0 <= x < INT_MAX;
    assigns \nothing;
    ensures \result > x;
*/
int mod_e2e_weak_caller(int x)
{
    return mod_e2e_weak_inc(x);
}

int mod_e2e_entry(int *values, int n, int x)
{
    return mod_e2e_loop_abs_max(values, n) + mod_e2e_even(n) +
           mod_e2e_weak_caller(x) + mod_e2e_global_limit;
}
