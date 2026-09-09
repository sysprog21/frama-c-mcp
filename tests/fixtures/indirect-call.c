/*
 * A call through a function pointer, with no calls clause.
 *
 * WP's answer to a call it cannot name is to assume the pointer may reach any
 * function, including "run" itself, which makes "run" recursive and pulls in a
 * decreases obligation nothing can discharge. Measured on Frama-C 32.1: 5 of 9
 * goals, four at Timeout, with the warnings "Missing 'calls' for default
 * behavior", "Unknown callee, considering non-terminating call", and "no
 * 'calls' specification for statement(s) on line(s): ... Assuming that they can
 * call 'run'".
 *
 * The paired fixture indirect-call-annotated.c is the same file with both
 * halves of the fix.
 */

int g;

/*@ assigns g;
    ensures g == 1;
 */
void seta(void)
{
    g = 1;
}

/*@ assigns g;
    ensures g == 1;
 */
void run(void (*f)(void))
{
    f();
}
