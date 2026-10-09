/*
 * One of each smoke failure: vac can never be called, and the branch in dead
 * can never run while dead itself is fine.
 */

/*@ requires x > 0 && x < 0; assigns \nothing; ensures \result == 0; */
int vac(int x)
{
    return 0;
}

/*@ requires x >= 0; assigns \nothing; */
int dead(int x)
{
    if (x < 0) {
        x = 5;
    }
    return x;
}
