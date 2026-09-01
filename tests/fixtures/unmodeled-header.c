/* A source that cannot be parsed, for the reason that actually stops most of a
   real tree: it includes a header the host has and Frama-C's modeled libc does
   not. Nothing here is wrong with the C. The point of the fixture is that no
   declaration written locally makes this file parse, because the gap is the
   model rather than a missing name. */
#include <sys/mount.h>

int mounted_block_size(const struct statfs *fs) { return (int) fs->f_bsize; }
