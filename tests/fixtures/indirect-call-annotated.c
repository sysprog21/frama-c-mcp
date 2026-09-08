/* indirect-call.c with both halves of the fix.
 *
 * The calls clause names the callee set, which stops WP assuming the pointer
 * may reach anything; the precondition says which function it actually holds,
 * without which the call-point goal stays open. Measured on Frama-C 32.1:
 * 9 of 10 with the calls clause alone, 10 of 10 with both.
 *
 * The call is still indirect, so this server still reports it: the AST is what
 * the plug-in walks and a statement's annotations are not part of that.
 */

int g;

/*@ assigns g;
    ensures g == 1; */
void seta(void)
{
  g = 1;
}

/*@ requires f == &seta;
    assigns g;
    ensures g == 1; */
void run(void (*f)(void))
{
  /*@ calls seta; */
  f();
}
