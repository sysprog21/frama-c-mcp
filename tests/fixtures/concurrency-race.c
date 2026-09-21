/* Level-0 concurrency screening fixture.

   Every shape here was reported clean by the first version of the screen: a
   definition whose brace opens the next line, a pool spawned from one textual
   pthread_create inside a loop, a global reached only through a helper, a
   compound assignment, a multi declarator global, and an access sharing its
   line with a pthread call. The screen is syntactic, so this file is never
   analysed for its proofs; it is read as text. */

#include <pthread.h>

static int shared_counter;
static int flag, spare;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void bump(void)
{
    shared_counter += 1;
}

void *worker(void *arg)
{
    bump();
    return 0;
}

void *guarded(void *arg)
{
    pthread_mutex_lock(&lock);
    flag = 1;
    pthread_mutex_unlock(&lock);
    return 0;
}

int main(void)
{
    pthread_t pool[4];
    pthread_t one;
    int i;

    for (i = 0; i < 4; i++)
        pthread_create(&pool[i], 0, worker, 0);
    pthread_create(&one, 0, guarded, 0);
    for (i = 0; i < 4; i++)
        pthread_join(pool[i], 0);
    pthread_join(one, 0);
    return 0;
}
