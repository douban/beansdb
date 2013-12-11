/* Select()-based ae.c module
 * Copyright (C) 2009-2010 Salvatore Sanfilippo - antirez@gmail.com
 * Released under the BSD license. See the COPYING file for more info. */

#include <string.h>

typedef struct aeApiState
{
    int maxfd;
    fd_set rfds, wfds;
    /* We need to have a copy of the fd sets as it's not safe to reuse
     * FD sets after select(). */
    fd_set _rfds, _wfds;
} aeApiState;

static int aeApiCreate(EventLoop *eventLoop)
{
    aeApiState *state = malloc(sizeof(aeApiState));

    if (!state) return -1;
    FD_ZERO(&state->rfds);
    FD_ZERO(&state->wfds);
    eventLoop->apidata = state;
    return 0;
}

static void aeApiFree(EventLoop *eventLoop)
{
    free(eventLoop->apidata);
}

static int aeApiAddEvent(EventLoop *eventLoop, int fd, int mask)
{
    aeApiState *state = eventLoop->apidata;

    if (mask & AE_READABLE) FD_SET(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_SET(fd,&state->wfds);

    if (fd > state->maxfd)
    {
        state->maxfd = fd;
    }
    return 0;
}

static int aeApiUpdateEvent(EventLoop *eventLoop, int fd, int mask)
{
    return aeApiAddEvent(eventLoop, fd, mask);
}

static int aeApiDelEvent(EventLoop *eventLoop, int fd)
{
    aeApiState *state = eventLoop->apidata;

    FD_CLR(fd,&state->rfds);
    FD_CLR(fd,&state->wfds);
    return 0;
}

static int aeApiPoll(EventLoop *eventLoop, struct timeval *tvp)
{
    aeApiState *state = eventLoop->apidata;
    int retval, j, numevents = 0;

    memcpy(&state->_rfds,&state->rfds,sizeof(fd_set));
    memcpy(&state->_wfds,&state->wfds,sizeof(fd_set));

    retval = select(state->maxfd+1,
                    &state->_rfds,&state->_wfds,NULL,tvp);
    if (retval > 0)
    {
        for (j = 0; j <= state->maxfd; j++)
        {
            if (FD_ISSET(j,&state->_rfds) || FD_ISSET(j,&state->_wfds))
            {
                eventLoop->fired[numevents] = j;
                numevents++;
            }
        }
    }
    return numevents;
}

static char *aeApiName(void)
{
    return "select";
}
