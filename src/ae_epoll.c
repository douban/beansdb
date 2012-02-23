/* Linux epoll(2) based ae.c module
 * Copyright (C) 2009-2010 Salvatore Sanfilippo - antirez@gmail.com
 * Released under the BSD license. See the COPYING file for more info. */

#include <sys/epoll.h>
#include <errno.h>

typedef struct aeApiState {
    int epfd;
    struct epoll_event events[AE_SETSIZE];
} aeApiState;

static int aeApiCreate(EventLoop *eventLoop) {
    aeApiState *state = malloc(sizeof(aeApiState));

    if (!state) return -1;
    state->epfd = epoll_create(1024); /* 1024 is just an hint for the kernel */
    if (state->epfd == -1) return -1;
    eventLoop->apidata = state;
    return 0;
}

static void aeApiFree(EventLoop *eventLoop) {
    aeApiState *state = eventLoop->apidata;

    close(state->epfd);
    free(state);
}

static int aeApiAddEvent(EventLoop *eventLoop, int fd, int mask) {
    aeApiState *state = eventLoop->apidata;
    struct epoll_event ee;
    ee.events = EPOLLONESHOT;
    if (mask & AE_READABLE) ee.events |= EPOLLIN;
    if (mask & AE_WRITABLE) ee.events |= EPOLLOUT;
    ee.data.u64 = 0; /* avoid valgrind warning */
    ee.data.fd = fd;
    if (epoll_ctl(state->epfd, EPOLL_CTL_ADD,fd,&ee) == -1 && errno != EEXIST) {
        fprintf(stderr, "epoll_ctl(%d,%d) failed: %d\n", EPOLL_CTL_ADD,fd,errno);
        return -1;
    }
    return 0;
}

static int aeApiUpdateEvent(EventLoop *eventLoop, int fd, int mask) {
    aeApiState *state = eventLoop->apidata;
    struct epoll_event ee;
    ee.events = EPOLLONESHOT;
    if (mask & AE_READABLE) ee.events |= EPOLLIN;
    if (mask & AE_WRITABLE) ee.events |= EPOLLOUT;
    ee.data.u64 = 0; /* avoid valgrind warning */
    ee.data.fd = fd;
    if (epoll_ctl(state->epfd, EPOLL_CTL_MOD,fd,&ee) == -1) {
        fprintf(stderr, "epoll_ctl(%d,%d) failed: %d\n", EPOLL_CTL_ADD,fd,errno);
        return -1;
    }
    return 0;
}

static int aeApiDelEvent(EventLoop *eventLoop, int fd) {
    aeApiState *state = eventLoop->apidata;
    struct epoll_event ee;

    ee.events = 0;
    ee.data.u64 = 0; /* avoid valgrind warning */
    ee.data.fd = fd;
    /* Note, Kernel < 2.6.9 requires a non null event pointer even for
     * EPOLL_CTL_DEL. */
    if ( epoll_ctl(state->epfd,EPOLL_CTL_DEL,fd,&ee) == -1 
            && errno != ENOENT && errno != EBADF) {
        fprintf(stderr, "epoll_ctl(%d,%d) failed: %d\n", EPOLL_CTL_DEL,fd,errno);
        return -1;
    }
    return 0;
}

int aeApiPoll(EventLoop *eventLoop, struct timeval *tvp) {
    aeApiState *state = eventLoop->apidata;
    int retval, numevents = 0;

    retval = epoll_wait(state->epfd,state->events,AE_SETSIZE,
            tvp ? (tvp->tv_sec*1000 + tvp->tv_usec/1000) : -1);
    if (retval > 0) {
        int j;

        numevents = retval;
        for (j = 0; j < numevents; j++) {
            int mask = 0;
            struct epoll_event *e = state->events+j;

            if (e->events & EPOLLIN) mask |= AE_READABLE;
            if (e->events & EPOLLOUT) mask |= AE_WRITABLE;
            eventLoop->fired[j] = e->data.fd;
        }
    }
    return numevents;
}

static char *aeApiName(void) {
    return "epoll";
}
