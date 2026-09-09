/*
 * From framac.md: struct contracts and named behavior groups from
 * frama-c-practice. Exercises: struct/enum in contracts, two orthogonal named
 * behavior groups, `disjoint behaviors <list>`, and the b*b + c*c overflow
 * guard the naive per-term precondition set misses.
 */

#include <limits.h>

enum Sides { EQUILATERAL, ISOSCELE, SCALENE };
enum Angles { OBTUSE, RIGHT, ACUTE };

struct TriangleInfo {
    enum Sides sides;
    enum Angles angles;
};

/*@
  requires \valid(info);
  requires a <= b+c && a >= b && a >= c;
  requires 0 <= a && a*a <= INT_MAX;
  requires 0 <= b && b*b <= INT_MAX;
  requires 0 <= c && c*c <= INT_MAX;
  requires b*b + c*c <= INT_MAX;
  assigns *info;

  behavior equilateral:
    assumes a <= b+c && a == b && b == c;
    ensures info->sides == EQUILATERAL;
  behavior isocele:
    assumes a <= b+c;
    assumes a == b || a == c || b == c;
    assumes a != b || a != c || b != c;
    ensures info->sides == ISOSCELE;
  behavior scalene:
    assumes a <= b+c && a != b && a != c && b != c;
    ensures info->sides == SCALENE;

  behavior obtuse:
    assumes a <= b+c && a*a > b*b + c*c;
    ensures info->angles == OBTUSE;
  behavior right:
    assumes a <= b+c && a*a == b*b + c*c;
    ensures info->angles == RIGHT;
  behavior acute:
    assumes a <= b+c && a*a < b*b + c*c;
    ensures info->angles == ACUTE;

  disjoint behaviors equilateral, isocele, scalene;
  disjoint behaviors obtuse, right, acute;
*/
int classify(int a, int b, int c, struct TriangleInfo *info)
{
    if (a == b && b == c)
        info->sides = EQUILATERAL;
    else if (a == b || a == c || b == c)
        info->sides = ISOSCELE;
    else
        info->sides = SCALENE;

    if (a * a > b * b + c * c)
        info->angles = OBTUSE;
    else if (a * a == b * b + c * c)
        info->angles = RIGHT;
    else
        info->angles = ACUTE;

    return 0;
}
