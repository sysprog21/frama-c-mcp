/*
 * A successor pointer computed by byte arithmetic, which is how an intrusive
 * allocator reaches the next block header.
 *
 * Under Typed+nocast the cast does not fail safely: Why3 aborts with
 * Invalid_argument("unbound variable in of_term") and WP stamps the goals
 * FAILED without any prover having answered. The same contract proves under
 * Typed+cast. The fixture exists so the server keeps telling those two apart.
 */
#include <stddef.h>

typedef struct blk {
    struct blk *prev;
    size_t header;
} blk_t;

/*@
  predicate span{L}(blk_t *b) =
    \valid_read(b) &&
    \valid((char *)b + (0 .. sizeof(blk_t) + b->header - 1));
*/

/*@
  requires span(b);
  assigns \result \from b, b->header;
  ensures \valid(&\result->prev);
*/
static blk_t *nextblk(blk_t *b)
{
    return (blk_t *) ((char *) b + b->header);
}
