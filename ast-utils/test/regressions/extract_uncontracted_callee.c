/*
 * How extraction emits a callee decides what WP is allowed to assume about it.
 *
 * A callee whose contract states no assigns must arrive in the sandbox as an
 * empty body. A bare declaration would default to assigns \nothing, which the
 * WP manual calls best effort and unsafe, and the caller would then prove
 * against a callee that writes nothing. Its own definition would be the
 * opposite error: the sandbox would prove the caller against code it was never
 * asked to verify.
 *
 * A callee that does state assigns keeps its definition, because the contract
 * already says what it writes.
 */

int sink;
int trace;

/*@ ensures sink >= 0; */
void unconstrained_helper(int x)
{
    sink = x * 3 + 7;
}

/*@ assigns trace;
    ensures trace == x;
 */
void contracted_helper(int x)
{
    trace = x;
}

void target(int n)
{
    unconstrained_helper(n);
    contracted_helper(n);
}
