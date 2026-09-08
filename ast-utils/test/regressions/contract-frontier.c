/* Fixture for the getContractFrontier regression.
   "entry" and "helper" carry contracts; "deep_a" and "deep_b" are reachable
   from them and carry none, so they are the frontier. "orphan" is defined,
   unspecified and unreachable from any contract, so it is not. */

int deep_a(int x) { return x + 1; }

int deep_b(int x) { return x * 2; }

/*@ assigns \nothing; ensures \result >= 0; */
int helper(int x)
{
  if (x < 0) return 0;
  return deep_a(x) + deep_b(x);
}

/*@ assigns \nothing; ensures \result >= 0; */
int entry(int x) { return helper(x); }

int orphan(int x) { return x - 1; }
