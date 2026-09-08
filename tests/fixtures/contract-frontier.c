/* The specification frontier of a partly contracted program.
 *
 * "entry" carries a contract and calls "helper", which carries one too and
 * calls "deep_a" and "deep_b", which carry none. Those two are the frontier:
 * defined, reachable from a contract, and unspecified.
 *
 * "orphan" is defined and unspecified and nothing contracted reaches it, so it
 * is not on the frontier. That is the discriminator: seeding from every
 * defined function instead of from the contracted ones would report it.
 */

int deep_a(int x)
{
  return x + 1;
}

int deep_b(int x)
{
  return x * 2;
}

/*@ assigns \nothing;
    ensures \result >= 0; */
int helper(int x)
{
  if (x < 0)
    return 0;
  return deep_a(x) + deep_b(x);
}

/*@ assigns \nothing;
    ensures \result >= 0; */
int entry(int x)
{
  return helper(x);
}

int orphan(int x)
{
  return x - 1;
}
