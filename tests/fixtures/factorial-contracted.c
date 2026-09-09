/*
 * factorial.c with its contract already in the source, which is where a
 * contract lives now: an agent proves under one and may not inject one into the
 * main project. The equivalence check needs this, because it compares the
 * sandbox's whole annotation set against main's, and a contract the agent had
 * put in the sandbox itself could never merge and so could never match.
 */

/*@ requires n >= 0;
    ensures \result >= 1;
 */
int factorial(int n)
{
    int i = 1;
    int f = 1;
    while (i <= n) {
        f *= i;
        i++;
    }
    return f;
}
