/*
 * An SV-COMP task as distributed: the property is that reach_error is never
 * called, and nothing in ACSL says so. The assert here is false.
 */
extern void abort(void);
void reach_error(void)
{
    abort();
}
void __VERIFIER_assert(int cond)
{
    if (!cond) {
        reach_error();
    }
}

int main(void)
{
    int x = 1;
    __VERIFIER_assert(x < 0);
    return 0;
}
