/*
 * From framac.md: modular WP verification. Contracts live on the prototypes in
 * the headers, not on the definitions. Sandbox extraction of mod_max_abs must
 * carry the callee contracts from the headers; taking them from the .c
 * definitions would find nothing.
 */

#include <limits.h>
#include "mod-abs.h"
#include "mod-max.h"

/*@ requires a > INT_MIN && b > INT_MIN;
    assigns \nothing;
    ensures \result >= 0;
*/
int mod_max_abs(int a, int b)
{
    int abs_a = mod_abs(a);
    int abs_b = mod_abs(b);
    return mod_max(abs_a, abs_b);
}
