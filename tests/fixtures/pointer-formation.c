/*
 * p is formed before the bound is tested. The precondition says nothing about
 * where the object ends, so for a large enough off, past one-past-the-end of a
 * ten-element array for instance, p points outside it even though it is never
 * read. Proves 5/5 by default; with -warn-invalid-pointer the pointer_value
 * goal stays open.
 */

/*@ requires \valid_read(base + (0 .. 9));
    requires 0 <= off;
    assigns \nothing;
*/
int f(int *base, int off)
{
    int *p = base + off;
    if (off < 10)
        return *p;
    return 0;
}
