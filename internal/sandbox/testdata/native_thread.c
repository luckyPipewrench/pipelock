// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

#include <pthread.h>
#include <stdio.h>

static void *thread_entry(void *arg) {
    *(int *)arg = 42;
    return NULL;
}

int main(void) {
    pthread_t thread;
    int marker = 0;
    int err = pthread_create(&thread, NULL, thread_entry, &marker);
    if (err != 0) {
        fprintf(stderr, "pthread_create: %d\n", err);
        return 1;
    }
    err = pthread_join(thread, NULL);
    if (err != 0 || marker != 42) {
        fprintf(stderr, "pthread_join: %d marker: %d\n", err, marker);
        return 1;
    }
    puts("thread-ok");
    return 0;
}
