/*@ requires n > 0;
    ensures \result >= 0;
 */
int helper(int n)
{
    int s = 0;
    /*@ loop invariant 0 <= i <= n;
      loop assigns i, s;
      loop variant n - i;
     */
    for (int i = 0; i < n; i++)
        s += 1;
    return s;
}

int main(void)
{
    return helper(3);
}
