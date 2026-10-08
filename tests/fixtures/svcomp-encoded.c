/*
 * svcomp-raw.c with its property made an obligation: reach_error requires
 * false, so every call that can reach it is an obligation. The assert still
 * fails, so the property is checked and found false, which is a disproved
 * precondition rather than a gap about encoding.
 */
extern void abort(void);

/*@ requires \false;
    assigns \nothing;
*/
void reach_error(void)
{
    abort();
}

/*@ requires cond != 0;
    assigns \nothing;
*/
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
