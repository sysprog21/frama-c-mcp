/* The negative control for memory-model-hypothesis.c.
 *
 * One pointer formal and no global in the same frame, so the Typed model needs
 * no separation and Frama-C prints none. Measured on Frama-C 32.1: 4 of 4
 * goals and no hypothesis warning.
 */

/*@ requires \valid(p);
    assigns *p;
    ensures *p == 1; */
void one(int *p)
{
  *p = 1;
}
