/*
 * From framac.md: EVA value-analysis harness shape from Crouse-Frama-C.
 * Exercises the EVA path rather than WP: a non-main entry point, the
 * Frama_C_*_interval builtins that inject non-deterministic input ranges, and
 * the -eva-slevel / -eva-ilevel precision knobs.
 *
 * Note: __fc_builtin.h ships with Frama-C; the declaration below is kept local
 * so the file parses without extra include paths.
 */

typedef unsigned int u32;

unsigned long Frama_C_unsigned_long_interval(unsigned long min,
                                             unsigned long max);

u32 rotateLeft(u32 num, u32 rotation)
{
    rotation &= 31u;
    if (rotation == 0u)
        return num;
    return (u32) ((num << rotation) | (num >> (32u - rotation)));
}

/* Entry point for EVA: run with main_function = "eva_main". */
int eva_main(void)
{
    u32 num = (u32) Frama_C_unsigned_long_interval(0UL, 0xFFFFFFFFUL);
    u32 rotation = (u32) Frama_C_unsigned_long_interval(0UL, 0xFFFFFFFFUL);
    u32 result = rotateLeft(num, rotation);
    (void) result;
    return 0;
}
