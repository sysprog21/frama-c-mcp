/*
 * test_sandbox.c — copy_fundec correctness verification test set
 *
 * Each function tests a type of CIL AST construct to ensure that the refresh
 * visitor deep copies correctly.
 *
 * Coverage:
 * L1: Pure function (branch + ternary operator)
 * L2: Loop (for + while + break + continue + accumulator)
 *   L3: Goto + Label + early return
 * L4: Array reading and writing (in-place modification)
 * L5: multi-pointer swap (separated scenario)
 * L6: Nested loops (bubble sort)
 *   L7: Switch/Case/Default
 * L8: Function call (direct + through pointer)
 * L9: Structure field access
 */

/* L1: Pure function — branch + ternary operator */
int abs_val(int x)
{
    return x < 0 ? -x : x;
}

int clamp_val(int val, int lo, int hi)
{
    if (val < lo)
        return lo;
    if (val > hi)
        return hi;
    return val;
}

/* L2: Loop — for + while + break + continue */
int sum_odd(int n)
{
    int s = 0;
    for (int k = 0; k < n; k++) {
        if (k % 2 == 0)
            continue;
        s += k;
    }
    return s;
}

int count_while(int n)
{
    int c = 0;
    int i = 0;
    while (i < n) {
        if (i > 100)
            break;
        c++;
        i++;
    }
    return c;
}

/* L3: Goto + Label + __retres pattern */
int find_val(int *a, int n, int x)
{
    int __retres;
    for (int i = 0; i < n; i++) {
        if (*(a + i) == x) {
            __retres = i;
            goto return_label;
        }
    }
    __retres = -1;
return_label:
    return __retres;
}

/* L4: Array writable — in-place modification */
void double_arr(int *a, int n)
{
    for (int i = 0; i < n; i++) {
        a[i] *= 2;
    }
}

/* L5: multi-pointer swap — separated scenario */
void swap_ptr(int *a, int *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

/* L6: Nested loops — bubble sort */
void bubble_sort(int *a, int n)
{
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n - 1 - i; j++) {
            if (a[j] > a[j + 1]) {
                int t = a[j];
                a[j] = a[j + 1];
                a[j + 1] = t;
            }
        }
    }
}

/* L7: Switch / Case / Default */
int classify(int x)
{
    int r;
    switch (x % 3) {
    case 0:
        r = 10;
        break;
    case 1:
    case 2:
        r = 20;
        break;
    default:
        r = -1;
        break;
    }
    return r;
}

/* L8: function call */
int helper_add(int a, int b)
{
    return a + b;
}

int call_test(int x, int y)
{
    int s = helper_add(x, y);
    int d = helper_add(x, -y);
    return helper_add(s, d);
}

/* L9: Structure field access */
struct point2d {
    int x;
    int y;
};

int dist_sq(struct point2d *p, struct point2d *q)
{
    int dx = p->x - q->x;
    int dy = p->y - q->y;
    return dx * dx + dy * dy;
}
