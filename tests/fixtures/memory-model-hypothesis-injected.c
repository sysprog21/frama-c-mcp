/* A separation that exists only once a contract has been injected.
 *
 * "bump" writes the global and never touches "p", so the file as written gives
 * the Typed model no reason to relate the two and Frama-C prints no memory
 * model hypothesis. A contract that names "*p" puts the pointer in the frame,
 * and the same model then needs "\separated(p, &g)" and says so.
 *
 * That gap is the point. Annotations reach Frama-C through the server protocol
 * and are never written back to this file, so a probe that re-parses the file
 * describes the program above rather than the one that was proved, and reports
 * no hypotheses for a proof that rested on one.
 *
 * Measured on Frama-C 33.0: no hypothesis warning for the file as it stands,
 * "requires \separated(p, &g);" once the contract below is in the AST.
 */

int g;

void bump(int *p)
{
  g = 1;
}
