/*
 * weak's contract holds for "return 0;" too, so proving it says nothing about
 * the multiplication; strong's pins the result to the input.
 */

/*@ requires 0 <= n <= 1000;
    assigns \nothing;
    ensures \result >= 0;
*/
int weak(int n)
{
    return n * n;
}

/*@ requires 0 <= n <= 1000;
    assigns \nothing;
    ensures \result == n * n;
*/
int strong(int n)
{
    return n * n;
}
