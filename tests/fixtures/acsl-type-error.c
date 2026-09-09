/*
 * An ACSL type error, which Frama-C treats as fatal at load.
 *
 * `\bogus_predicate` is not bound to anything, so Frama-C aborts before the
 * server socket exists. There is no session to ask for logs, which makes the
 * process output the only channel, and Frama-C writes it to stdout while
 * leaving stderr empty. Tailing stderr alone reported "failed to start (socket
 * missing after 10s)" with nothing after it, on a file whose problem Frama-C
 * had already named exactly.
 */

/*@ requires \bogus_predicate(n); */
int f(int n)
{
    return n;
}
