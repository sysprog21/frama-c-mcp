/*@ type logic_int = integer;
    logic logic_int double_logic(logic_int x) = x + x;
    predicate nonnegative(logic_int x) = x >= 0;
*/

/*@ requires x > -2147483648;
    ensures \result >= 0;
    ensures nonnegative(\result);
    ensures \result <= double_logic(\result);
    ensures (x >= 0) ==> (\result == x);
    ensures (x < 0) ==> (\result == -x);
*/
int abs_val(int x)
{
    if (x < 0)
        return -x;
    return x;
}

/*@ requires n >= 0;
    ensures \result >= 0;
*/
int square(int n)
{
    return n * n;
}

int main(void)
{
    int a = abs_val(-5);
    int b = square(3);
    return a + b;
}
