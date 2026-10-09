/*
 * Each postcondition rests on a builtin Frama-C models too weakly: proved only
 * with builtin_models: true.
 */

/*@ assigns \nothing; ensures \result >= 0; */
int f(int x)
{
    if (x < 0)
        __builtin_unreachable();
    return x;
}
/*@ assigns \nothing; ensures \result >= 0; */
int g(int x)
{
    if (x < 0)
        __builtin_trap();
    return x;
}
/*@ requires v != 0; assigns \nothing; ensures \result < 32; */
int h(unsigned v)
{
    return __builtin_clz(v) + 0 * __builtin_ctz(v) + 0 * __builtin_popcount(v);
}
