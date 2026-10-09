/*
 * bad never terminates, so its definition is inconsistent, and WP assumes it
 * anyway. The postcondition is false for every input.
 */

/*@ logic integer bad(integer n) = bad(n) + 1; */

/*@ assigns \nothing;
    ensures bad(x) >= 0 ==> \result == 998;
*/
int f(int x)
{
    return 0;
}
