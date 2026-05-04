/*
**  igmpv3proxy - IGMPv3 Proxy based multicast router
**  Copyright (C) 2022-2024 Sietse van Zanen <uglymotha@wizdom.nu>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**----------------------------------------------------------------------------
**
**  This software is derived work from the following software. The original
**  source code has been modified from it's original state by the author
**  of igmpv3proxy.
**
**  smcroute 0.92 - Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
**  - Licensed under the GNU General Public License, either version 2 or
**    any later version.
**
**  mrouted 3.9-beta3 - Copyright (C) 2002 by The Board of Trustees of
**  Leland Stanford Junior University.
**  - Licensed under the 3-clause BSD license, see Stanford.txt file.
**
**  igmpproxy     - Copyright (C) 2005 by Johny Egeland et al.
*/

/**
*   timers.c - Functions for IGMP and other timers.
*/

#include "igmpv3proxy.h"

// Queue definition.
static struct timeOutQueue {
    struct timeOutQueue  *prev;            // Previous event in queue
    struct timeOutQueue  *next;            // Next event in queue
    void                (*func)(void *);   // function to call
    void                 *data;            // Argument for function.
    struct timespec       time;            // Time for event
    char                  name[];          // name of the timer
}     *queue = NULL;

#define TMSZ(n)  (sizeof(struct timeOutQueue)+strlen(n)+1)
#define TMLST     0, 0, 0, 0, tmr, 0
#define TMLSTn(n) 0, 0, 0, 0, tmr, TMSZ(n)

static struct timeOutQueue *last  = NULL;

/**
*   Execute at most CONF->tmQsz expired timers, return time difference to next scheduled timer.
*   Returns -1,-1 if no timer is scheduled, 0, -1 if next timer has already expired.
*/
struct timespec timerAgeQueue(void) {
    struct timeOutQueue *node;
    struct timespec      time;
    uint64_t             i = 0;

    clock_gettime(CLOCK_REALTIME, &curtime);
    for (node = queue; i <= CONF->tmQsz && node && timeDiff(curtime, node->time).tv_nsec == -1; node = queue, i++) {
        LOG(LOG_INFO, 0, "About to call timeout (#%d) - %s - Missed by %dus", i + 1, node->name,
            timeDiff(node->time, curtime).tv_nsec / 1000);
        clock_gettime(CLOCK_REALTIME, &time);
        node->func(node->data);
        clock_gettime(CLOCK_REALTIME, &curtime);
        LOG(LOG_DEBUG, 0, "Timeout #%d took %dus", i + 1, timeDiff(time, curtime).tv_nsec / 1000);
    }
    if (i > 0)
        DEBUGQUEUE("-Age Queue-", 1, -1);
    return queue ? timeDiff(curtime, queue->time) : (struct timespec){-1, -1};
}

/**
*   Inserts a timer in queue. Queue is maintained in order of execution.
*/
void timerSet(void **tid, struct timespec delay, const char *name, void *func, void *data)
{
    struct timeOutQueue        *pnode = NULL, *node = (struct timeOutQueue *)*tid;
    struct timespec             time;
    uint64_t                    rep = 1, dir, i;
    clock_gettime(CLOCK_REALTIME, &time);
    time.tv_sec  += delay.tv_sec  + ((time.tv_nsec + delay.tv_nsec) >= 1000000000);
    time.tv_nsec += delay.tv_nsec - ((time.tv_nsec + delay.tv_nsec) >= 1000000000) * 1000000000;

    // Create and set a new timer, walk the queue to find the right place.
    if (node) {
        dir = (timeDiff(time, node->time).tv_nsec == -1);
        if (   ( dir && (! node->next || timeDiff(node->next->time, time).tv_nsec == -1))
            || (!dir && (! node->prev || timeDiff(time, node->prev->time).tv_nsec == -1)))
            rep = 0;
        else if (last && (   ( dir && timeDiff(time, last->time).tv_nsec == -1 && timeDiff(last->time, node->time).tv_nsec == -1)
                          || (!dir && timeDiff(last->time, time).tv_nsec == -1)))
            pnode = last;
        else
            pnode = node->prev;
        if (rep)
            LST_RM(node, queue, TMLST);
    } else if (last && timeDiff(time, last->time).tv_nsec == -1)
        pnode = last;
    if (! pnode && queue && timeDiff(time, queue->time).tv_nsec == -1)
        pnode = queue;
    for (i = 1; pnode && pnode->next && timeDiff(time, pnode->next->time).tv_nsec == -1; pnode = pnode->next, i++);
    if (! node) {
        LST_IN(node, queue, pnode, TMLSTn(name));  // Freed by timerClear()
        node->func = func;
        node->data = data;
        memcpy(&node->name, name, strlen(name) + 1);
        *tid = node;
    } else if (rep)
        LST_IN(node, queue, pnode, TMLST);
    node->time = time;
    last = node;

    LOG(LOG_INFO, 0, "Created timeout (#%d): %s - delay %d.%d secs", i, node->name, delay.tv_sec, delay.tv_nsec/ 100000000);
    DEBUGQUEUE("-Set Timer-", 1, -1);
}

/**
*   Removes a timer from the queue.
*/
void timerClear(void **tid) {
    uint64_t             i = 1;
    struct timeOutQueue *node = (struct timeOutQueue *)*tid;

    if (last == node)
        last = NULL;
    IF_FOR(loglevel >= LOG_INFO, (struct timeOutQueue *n = node; n->prev; n = n->prev, i++));
    LOG(LOG_INFO, 0, "Removed timeout (#%d): %s", i, node->name);
    LST_RM(node, queue, TMLSTn(node->name));  // Alloced by timerSet()
    *tid = NULL;
    DEBUGQUEUE("Clear Timer", 1, -1);
}

/**
*   Debugging utility
*/
void timerDebugQueue(const char *header, int h, int fd) {
    char                *buf;
    struct timeOutQueue *node = queue;
    uint64_t             i;

    clock_gettime(CLOCK_REALTIME, &curtime);
    if (fd < 0)
        LOG(LOG_DEBUG, 0, "----------------------%s----------------------", header);
    else if (h) {
        buf = strFmt(h, "Active Timers:\n_Nr_|____In____|________________Name_______________\n", "");
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
    for (i = 1; node; node = node->next, i++) {
        struct timespec delay = timeDiff(curtime, node->time);
        if (fd < 0)
            LOG(LOG_DEBUG, 0, "| %3d %5d.%1ds | %s", i, delay.tv_sec, delay.tv_nsec / 100000000, node->name);
        else {
            buf = strFmt(h, "%3d | %5d.%1ds | %s\n", "%d %d.%d %s\n", i, delay.tv_sec, delay.tv_nsec / 100000000, node->name);
            send(fd, buf, strlen(buf), MSG_DONTWAIT);
        }
    }
    if (fd < 0) {
        LOG(LOG_DEBUG, 0, "---------------------------------------------------");
        LOG(LOG_DEBUG, 0, "Memory Stats: %lldb in use, %lld allocs, %lld frees.", memuse.tmr, memalloc.tmr, memfree.tmr);
    } else if (h) {
        buf = strFmt(1, "---------------------------------------------------\n", "");
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
}
