int counter = 0;
int max_val = 100;

/*@ requires x >= 0;
    ensures \result >= 0;
    ensures \result <= max_val;
*/
int clamp(int x)
{
    if (x > max_val)
        return max_val;
    return x;
}

/*@ requires n >= 0;
    ensures counter >= \old(counter);
*/
void increment(int n)
{
    counter += n;
}

/*@ ensures \result >= 0;
*/
int process(int x)
{
    int val = clamp(x);
    increment(val);
    return val;
}

int main(void)
{
    int a = process(50);
    int b = process(200);
    return a + b;
}
