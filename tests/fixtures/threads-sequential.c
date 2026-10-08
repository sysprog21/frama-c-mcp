/*
 * The thread body is never analyzed by EVA from main: Frama-C's pthread_create
 * stub assigns the handle and does not call w.
 */
#include <pthread.h>

int counter;

void *w(void *arg)
{
    (void) arg;
    counter++;
    return 0;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, 0, w, 0);
    counter++;
    pthread_join(t, 0);
    return 0;
}
