#include "mod-abs.h"
int mod_abs(int val)
{
    if (val < 0)
        return -val;
    return val;
}
