/*
 * A source Frama-C cannot parse unless the caller supplies a define.
 *
 * _Atomic is the real case this fixture stands for: Frama-C 33's front end
 * stops at it with a syntax error, and a codebase that uses it for one struct
 * field is unreachable to WP until "-D_Atomic=" erases the keyword. The
 * qualifier below is deliberately on a field the proved function never reads,
 * which is what makes erasing it sound for a single-threaded WP run.
 */

typedef struct {
    _Atomic int state;
    int limit;
} slot_t;

/*@
  requires 0 <= n;
  requires \valid_read(s);
  requires 0 <= s->limit;
  assigns \nothing;
  ensures 0 <= \result <= n;
 */
int slot_clamp(const slot_t *s, int n)
{
    return n < s->limit ? n : s->limit;
}
