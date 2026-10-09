/*
 * The precondition bounds i below and not above, so the write in g can run past
 * the array for a caller that meets the contract. main's one call passes 3,
 * which EVA finds safe. With -rte-use-eva-results at its default, RTE
 * generation then skips g and WP never sees the out-of-bounds goal, so check
 * came back proved.
 */

/*@ requires \valid(a + (0 .. 9));
    requires 0 <= i;
    assigns a[i];
*/
void g(int *a, int i)
{
    a[i] = 1;
}

int main(void)
{
    int b[10];
    g(b, 3);
    return 0;
}
