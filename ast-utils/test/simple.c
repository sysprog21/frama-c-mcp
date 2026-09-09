int abs_val(int x)
{
    if (x < 0) {
        x = -x;
    }
    return x;
}

int sum(int n)
{
    int s = 0;
    int i = 0;
    while (i < n) {
        s = s + i;
        i = i + 1;
    }
    return s;
}
