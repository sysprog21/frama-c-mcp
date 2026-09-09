/*
 * A callee with no body and no contract.
 *
 * Frama-C generates a default `assigns` for `helper` and warns that it did so.
 * That warning is the whole reason this fixture exists: a generated assigns is
 * an assumption every proof above it rests on, and before `messages[]` it
 * reached the agent nowhere. The analysis still runs, so the warning is the
 * only sign anything is missing.
 */

int helper(int n);

/*@ requires n >= 0;
    ensures \result >= 0;
 */
int compute(int n)
{
    return helper(n);
}

int main(void)
{
    return compute(3);
}
