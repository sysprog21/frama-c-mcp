/*
 * EVA cannot compute this initializer, aborts before analyzing main, and the
 * compute request still answers successfully.
 */
int x = 1 / 0;

int main(void)
{
    return x;
}
