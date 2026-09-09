#include <limits.h>

/*@
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

int main(void)
{
    int r = abs_int(INT_MIN);
    return r;
}
