/*@ requires 0 <= a <= 1000 && 0 <= b <= 1000 && 0 <= c <= 1000;
    ensures \result >= 0;
 */
int slow(int a, int b, int c)
{
    /*@ assert (a*a*a + b*b*b != c*c*c) || (a == 0 && b == 0 && c == 0); */
    return a + b + c;
}
