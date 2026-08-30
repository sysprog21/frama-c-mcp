/* One unknown attribute name, used twice. Frama-C reports an unknown
   attribute once per distinct name per process, not once per site, so the
   count for this file is 1 and not 2. */
int repeat_one(void) __attribute__((__unknown_frama_repeat__));
int repeat_two(void) __attribute__((__unknown_frama_repeat__));
