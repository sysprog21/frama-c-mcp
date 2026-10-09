/*
 * Fixture for run-ghost-integrity.sh. Every statement an insertion targets sits
 * on a line of its own, because the harness finds its sid by line.
 */

int stale(int x)
{
    //@ ghost int g = 0;
    x = x;
    //@ assert g == 1;
    return 0;
}

int scoped(int x)
{
    int r = 0;
    if (x > 0) {
        int t = x;
        r = t;
    } else {
        int t = -x;
        r = t;
    }
    return r;
}

int cond(int x)
{
    int r = 0;
    if (x > 5) {
        r = 1;
    }
    return r;
}

int looped(int n)
{
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += 1;
    }
    return s;
}
