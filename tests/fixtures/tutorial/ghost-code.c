/*
 * From framac.md: Ghost Code + Lemma function (ISPRAS 2018). Exercises every
 * ghost form the tutorial uses: ghost global, ghost local, ghost else-block,
 * ghost loop with nested /@ @/ ACSL, and a recursive ghost lemma function whose
 * contract carries `decreases`.
 */

//@ ghost int ghost_glob_var = 0;

void ghost_local(int a)
{
    //@ ghost int ghost_loc_var = a;
}

void ghost_else(int a)
{
    //@ ghost int a_was_ok = 0;
    if (a < 5) {
        a = 5;
    } /*@ ghost else {
        a_was_ok = 1;
    } */
}

void ghost_loop(unsigned n)
{
    /*@ ghost
        unsigned i;

        /@
            loop invariant 0 <= i <= n;
            loop assigns i;
            loop variant n-i;
        @/
        for (i = 0; i < n; ++i) {

        }

        /@ assert i == n; @/
    */
}

/* Lemma function: the ghost body is the induction, the contract is the lemma.
 * `decreases` must precede assigns/ensures or Frama-C reports a clause order
 * error.
 *
 * The closed form is `2 * sum(n) == n*(n+1)` rather than the textbook `sum(n)
 * == n*(n+1)/2`. Both state the same fact, since n*(n+1) is always even and the
 * ACSL integer division is therefore exact, yet Alt-Ergo 2.6.3 times out on the
 * division form and discharges the multiplied one in milliseconds (Z3 proves
 * either). Multiplying out is the habit to take from this fixture.
 */
/*@ logic integer sum(integer n) = n <= 0 ? 0 : n + sum(n-1); */
/*@ ghost
  /@ requires n >= 0;
     decreases n;
     assigns \nothing;
     ensures 2 * sum(n) == n*(n+1);
  @/
  void lemma_sum(int n){
    if (n > 0) lemma_sum(n-1);
  }
*/
