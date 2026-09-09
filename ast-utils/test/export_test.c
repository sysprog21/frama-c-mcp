struct point {
    int x;
    int y;
};
typedef unsigned int uint;
enum color { RED, GREEN, BLUE };

int global_count;

/*@ requires x >= 0;
    ensures \result == x;
    assigns \nothing;
*/
int identity(int x)
{
    return x;
}

int abs_val(int x)
{
    if (x < 0)
        return -x;
    return x;
}

int sum(int n)
{
    int s = 0;
    /*@ loop invariant 0 <= s;
      loop assigns s;
  */
    for (int i = 0; i < n; i++) {
        s += i;
    }
    return s;
}

struct point make_point(int x, int y)
{
    struct point p;
    p.x = x;
    p.y = y;
    return p;
}

int color_value(enum color c)
{
    switch (c) {
    case RED:
        return 0;
    case GREEN:
        return 1;
    default:
        return 2;
    }
}
