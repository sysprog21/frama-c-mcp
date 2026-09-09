/*@ predicate nonneg(integer x) = x >= 0; */

/*@ requires nonneg(n);
    assigns \nothing;
    ensures \result >= n;
 */
int inc(int n)
{
    return n + 1;
}

int sum(int *a, int n)
{
    int s = 0;
    /*@ loop invariant 0 <= i <= n;
      loop assigns i, s;
      loop variant n - i;
   */
    for (int i = 0; i < n; i++) {
        s += a[i];
    }
    return s;
}

int divide(int x, int y)
{
    return x / y;
}

/*@ requires nonneg(n);
    ensures \result >= 0;
 */
int unspecified_frame(int n)
{
    return n;
}
