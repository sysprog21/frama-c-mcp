/*
 * From framac.md: Linux kernel string-function case study from verker.
 * Exercises: axiomatic block wrapping a predicate + recursive logic function, a
 * logic function sharing a C function's name, ghost variable pinning a
 * loop-destroyed length, and pointer arithmetic on void * (GNU extension).
 *
 * framac.md records that memset here does NOT fully prove under today's WP
 * (17/24 on v33.0, identical across Typed / Typed+cast / Bytes). Keep it as a
 * negative fixture: the server must report the shortfall honestly, and must be
 * able to select all three models to reproduce the comparison.
 */

#include <stddef.h>

/*@ axiomatic Strlen {
    predicate valid_str(char *s) =
       \exists size_t n; s[n] == '\0' && \valid(s+(0..n));

    logic size_t logic_strlen(char *s) =
       s[0] == '\0' ? (size_t) 0 : (size_t) ((size_t)1 + logic_strlen(s + 1));
    }
 */

/*@ requires valid_str((char *)s);
    assigns \nothing;
    ensures \result == logic_strlen((char *)s);
    ensures s[\result] == '\0';
    ensures \forall integer i; 0 <= i < \result ==> s[i] != '\0';
 */
size_t kstrlen(const char *s)
{
    const char *sc;
    /*@ loop invariant s <= sc <= s + logic_strlen((char *)s);
        loop invariant valid_str((char *)sc);
        loop invariant logic_strlen((char *)s) == logic_strlen((char *)sc) + (sc - s);
        loop assigns sc;
        loop variant logic_strlen((char *)s) - (sc - s);
     */
    for (sc = s; *sc != '\0'; ++sc)
        /* nothing */;
    return sc - s;
}

/*@ requires \valid((char *)s+(0..count-1));
    assigns ((char *)s)[0..count-1];
    ensures \forall char *p; (char *)s <= p < (char *)s + count ==> *p == (char)c;
    ensures \result == s;
 */
void *kmemset(void *s, int c, size_t count)
{
    char *xs = s;
    //@ ghost size_t ocount = count;

    /*@ loop invariant 0 <= count <= ocount;
        loop invariant (char *)s <= xs <= (char *)s + ocount;
        loop invariant xs - (char *)s == ocount - count;
        loop invariant \forall char *p; (char *)s <= p < xs ==> *p == (char)c;
        loop assigns count, xs, ((char *)s)[0..ocount-1];
        loop variant count;
     */
    while (count--)
        *xs++ = (char) c;

    /* Not redundant: `while (count--)` tests the pre-decrement value, so count
     * wraps to SIZE_MAX on exit.
     */
    //@ assert count == (size_t)(-1);
    return s;
}
