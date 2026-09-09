int declared_only(int x);

int call_declared_only(int x)
{
    return declared_only(x);
}

int copy_counter(int c)
{
    int x = c;
    int y = 0;
    while (x > 0) {
        /*@ assert rte: signed_overflow: -2147483648 ≤ x - 1; */
        x--;
        /*@ assert rte: signed_overflow: y + 1 ≤ 2147483647; */
        y++;
    }
    return y;
}
