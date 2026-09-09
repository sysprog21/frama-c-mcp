// Iterative verification workflow test, RAW version (no ACSL)
//
// Source: adapted from RTE-Guided-Specification-Generation benchmark
// (pointers/dir8_div_rem.c)
//
// EVA expected alarms:
//   safe_div:     division_by_zero (b could be 0)
//   array_read:   mem_access / index_bound (idx could be out of bounds)
//
// Uses volatile nondet to force EVA to consider full value ranges.

#define SIZE 10
int arr[SIZE];
volatile int nondet;

int safe_div(int a, int b)
{
    return a / b;
}

int array_read(int idx)
{
    return arr[idx];
}

int main(void)
{
    arr[0] = 100;
    arr[5] = 200;
    int x = safe_div(nondet, nondet);
    int y = array_read(nondet);
    return x + y;
}
