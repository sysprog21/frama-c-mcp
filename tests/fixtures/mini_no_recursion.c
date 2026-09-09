/*
 * Benchmark: mini_no_recursion
 *
 * Purpose: happy path. 3 The function has no recursive call chain c → b → a
 * (call graph: a→b→c). The main FSM should topologically sort out 3 SCCs
 * (single elements), and dispatch orders batch=[c], after completion Send [b],
 * send [a] after completion, and finally final_gate runs the entire file WP.
 *
 * Expected FSM outcome:
 *   - final_gate: PASSED
 *   - conclusions: c, b and a each stored verified
 *
 * Source design notes:
 * - no cast (Typed+nocast compatible)
 * - all operations are kept within the int range (caller a(0) → b(0)=2 →
 * c(0)=1, small value)
 * - WP can infer ensures (closed form: c(x)=x+1, b(x)=2*(x+1), a(x)=2*(x+1)+10)
 */

int c(int x);
int b(int x);
int a(int x);

int c(int x)
{
    return x + 1;
}

int b(int x)
{
    int y = c(x);
    return y + y;
}

int a(int x)
{
    int z = b(x);
    return z + 10;
}
