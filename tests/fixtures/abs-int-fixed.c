#include <limits.h>

/*@
  requires x > INT_MIN;
  assigns \nothing;
  ensures \result >= 0;
  ensures (x >= 0 ==> \result == x);
  ensures (x < 0 ==> \result == -x);
*/
int abs_int(int x)
{
    if (x < 0)
        return -x;
    return x;
}

/*@ assigns \nothing; */
int main(void)
{
    int r = abs_int(-5);
    return r;
}
