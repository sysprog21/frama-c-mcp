/*
 * comprehensive.c — ast-utils full branch coverage test
 *
 * Coverage target:
 *   instr_to_json: Set, Call, Local_init(AssignInit/SingleInit),
 *                  Local_init(ConsInit), Local_init(CompoundInit),
 *                  Asm, Code_annot
 *   stmt_to_json:  Instr, Return, If, Loop, Block, Switch, Goto,
 *                  Break, Continue, UnspecifiedSequence
 * Data types: basic types, pointers, arrays, structures, nested structures,
 * Union, enumeration, function pointer, typedef
 */

#include <stddef.h>

/* Data type definition */

typedef unsigned int uint32_t_local;

enum color { RED = 0, GREEN = 1, BLUE = 2 };

struct point {
    int x;
    int y;
};

struct rect {
    struct point top_left;
    struct point bottom_right;
};

union value {
    int i;
    float f;
    char *s;
};

struct tagged_value {
    enum color tag;
    union value val;
    struct tagged_value *next; /* self-referential pointer */
};

typedef int (*binary_op)(int, int);

/* Auxiliary functions */

int add(int a, int b)
{
    return a + b;
}

int sub(int a, int b)
{
    return a - b;
}

int apply_op(binary_op op, int x, int y)
{
    return op(x, y);
}

int clamp(int val, int lo, int hi)
{
    if (val < lo)
        return lo;
    if (val > hi)
        return hi;
    return val;
}

/* Core test function */

/*@ requires n >= 0;
    ensures \result >= 0;
*/
int test_all_stmts(int n, int mode)
{
    int result = 0;
    int i;

    /* If + nested If */
    if (n > 0) {
        if (mode == 1) {
            result = 1;
        } else {
            result = 2;
        }
    } else {
        result = -1;
    }

    /* Loop + Continue + Break */
    i = 0;
    while (1) {
        if (i >= n)
            break;
        if (i % 2 == 0) {
            i++;
            continue;
        }
        result = result + i;
        i++;
    }

    /* Switch + Case + Default + Goto */
    switch (mode) {
    case 0:
        result = result * 2;
        break;
    case 1:
    case 2:
        result = result + 10;
        break;
    default:
        goto done;
    }

    /* For loop (CIL normalizes to while) */
    for (i = 0; i < 5; i++) {
        result += i;
    }

done:
    return result;
}

/* Function call + function pointer */

int test_calls(int a, int b)
{
    /* Direct call */
    int sum = add(a, b);

    /* Call via function pointer */
    binary_op op = &sub;
    int diff = op(a, b);

    /* Call through apply_op (passing function pointer) */
    int applied = apply_op(&add, a, b);

    /* Chained call */
    int clamped = clamp(add(a, b), 0, 100);

    return sum + diff + applied + clamped;
}

/* Structure + Nesting + Union + Enumeration */

struct rect make_rect(int x1, int y1, int x2, int y2)
{
    struct rect r;
    r.top_left.x = x1;
    r.top_left.y = y1;
    r.bottom_right.x = x2;
    r.bottom_right.y = y2;
    return r;
}

int rect_area(struct rect *r)
{
    int w = r->bottom_right.x - r->top_left.x;
    int h = r->bottom_right.y - r->top_left.y;
    if (w < 0)
        w = -w;
    if (h < 0)
        h = -h;
    return w * h;
}

int test_struct_union(enum color c)
{
    struct tagged_value tv;
    tv.tag = c;

    switch (c) {
    case RED:
        tv.val.i = 42;
        break;
    case GREEN:
        tv.val.f = 3.14f;
        break;
    case BLUE:
        tv.val.s = "hello";
        break;
    }

    tv.next = NULL;

    struct rect r = make_rect(0, 0, 10, 20);
    int area = rect_area(&r);

    if (tv.tag == RED)
        return tv.val.i + area;
    else
        return area;
}

/* Array + pointer arithmetic */

void test_array_ptr(int *arr, int len)
{
    int buf[10];
    int *p;

    /* Array initialization via loop */
    for (int i = 0; i < 10 && i < len; i++) {
        buf[i] = arr[i];
    }

    /* Pointer arithmetic */
    p = &buf[0];
    while (p < buf + 10) {
        *p = *p * 2;
        p++;
    }

    /* Array of structs */
    struct point pts[3];
    pts[0].x = 1;
    pts[0].y = 2;
    pts[1].x = 3;
    pts[1].y = 4;
    pts[2].x = 5;
    pts[2].y = 6;

    /* Nested array access */
    int matrix[2][3] = {{1, 2, 3}, {4, 5, 6}};
    int val = matrix[1][2];
    arr[0] = val + pts[0].x;
}

/* typedef + complex declaration */

typedef struct {
    uint32_t_local id;
    char name[32];
    binary_op handler;
} entry_t;

int test_typedef(void)
{
    entry_t e;
    e.id = 1;
    e.handler = &add;
    int res = e.handler(10, 20);
    return res;
}

/* inline asm (if supported) */

int test_asm(int x)
{
    int out;
    __asm__("movl %1, %0" : "=r"(out) : "r"(x));
    return out;
}

/* void return */

void test_void_return(int *p)
{
    if (p == NULL)
        return;
    *p = 42;
}

/* ACSL annotations in code */

int test_annotations(int *p, int n)
{
    /*@ assert p != \null; */
    /*@ assert n > 0; */

    int sum = 0;
    /*@ loop invariant 0 <= i <= n;
      loop invariant sum >= 0;
      loop assigns i, sum;
      loop variant n - i;
  */
    for (int i = 0; i < n; i++) {
        sum += p[i];
    }

    return sum;
}
