/* Two points where the analyzed program stops being the compiled program: an
   inline-assembly memory clobber whose real effects Frama-C cannot see, and
   two dropped declarations. Counted as 2 clobber sites and 2 distinct
   attribute names. */
int clobber_one(int x) { __asm__ volatile("" ::: "memory"); return x; }
int clobber_two(int x) { __asm__ volatile("" ::: "memory"); return x; }
int attribute_one(void) __attribute__((__unknown_frama_first__));
int attribute_two(void) __attribute__((__unknown_frama_attribute__));
