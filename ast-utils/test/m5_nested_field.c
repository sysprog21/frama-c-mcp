/*
 * Fixture for M-5 ATfield/ATsubscript ty correctness test. Constructs nested
 * struct + array + ptr access in ACSL contract; verifies that each
 * ATfield/ATsubscript node carries the correct field/element type, not the
 * parent term type.
 */

struct Inner {
    int h;
    int hh[4];
};

struct Outer {
    int x;
    struct Inner g;
    struct Inner *pg;
};

/*@ requires s.g.h == 0;
    requires s.g.hh[2] == 0;
    requires s.pg->h == 0;
    ensures \result == s.g.h;
 */
int test_nested(struct Outer s)
{
    return s.g.h;
}
