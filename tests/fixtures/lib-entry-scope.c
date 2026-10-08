/*
 * f indexes with a global that set() makes 42 before f runs. Analyzed from f
 * with the globals at their initializers, g is 0 and EVA raises nothing; from
 * an unknown global state it raises the out-of-bounds alarm.
 */
int g;
int a[10];

void set(int v)
{
    g = v;
}

void f(void)
{
    a[g] = 1;
}

int main(void)
{
    set(42);
    f();
    return 0;
}
