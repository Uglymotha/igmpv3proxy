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
    char                 *name;            // name of the timer
}     *queue = NULL;
#define TMSZ(n)  (sizeof(struct timeOutQueue)+strlen(n)+1)
#define TMLST(n) 0, 0, 0, 0, tmr, TMSZ(n)

/**
*   Execute at most CONF->tmQsz expired timers, return time difference to next scheduled timer.
*   Returns -1,-1 if no timer is scheduled, 0, -1 if next timer has already expired.
*/
struct timespec timerAgeQueue(void) {
    struct timeOutQueue *node;
    uint64_t             i = 1;

    clock_gettime(CLOCK_REALTIME, &curtime);
    for (node = queue; i <= CONF->tmQsz && node && timeDiff(curtime, node->time).tv_nsec == -1; node = queue, i++) {
        LOG(LOG_INFO, 0, "About to call timeout (#%d) - %s - Missed by %dus", i, node->name,
            timeDiff(node->time, curtime).tv_nsec / 1000);
        clock_gettime(CLOCK_REALTIME, &node->time);
        node->func(node->data);
        clock_gettime(CLOCK_REALTIME, &curtime);
        LOG(LOG_DEBUG, 0, "%s took %dus", node->name, timeDiff(node->time, curtime).tv_nsec / 1000);
        LST_RM(node, queue, TMLST(node->name));   // Alloced by timer_setTimer()
    }
    if (i > 1)
        DEBUGQUEUE("-Age Queue-", 1, -1);
    return queue ? timeDiff(curtime, queue->time) : (struct timespec){-1, -1};
}

/**
*   Inserts a timer in queue. Queue is maintained in order of execution.
*   FIFO if timers are scheduled at exactly the same time. Delay in multiples of .1s
*/
intptr_t timerSet(int delay, const char *name, void (*func)(), void *data) {
    struct timeOutQueue  *pnode = NULL, *node;
    uint64_t              i = 1;
    struct timespec       tdiff = timeDelay(delay);

    // Create and set a new timer, walk the queu to find the right place..
    IF_FOR(queue && timeDiff(queue->time, tdiff).tv_nsec != -1,
           (pnode = queue, i++; pnode->next && timeDiff(pnode->next->time, tdiff).tv_nsec != -1; pnode = pnode->next, i++));
    LST_IN(node, queue, pnode, TMLST(name));  // Freed by timer_ageQueue() or timer_clearTimer()
    *node = (struct timeOutQueue){ node->prev, node->next, func, data, tdiff, memcpy(&node->name + 1, name, strlen(name) + 1) };

    LOG(LOG_INFO, 0, "Created timeout (#%d): %s - delay %d.%1d secs", i, node->name, delay / 10, delay % 10);
    DEBUGQUEUE("-Set Timer-", 1, -1);
    return (intptr_t)node;
}

/**
*   Removes a timer from the queue.
*/
intptr_t timerClear(intptr_t node) {
    uint64_t i = 1;

    IF_FOR(loglevel >= LOG_INFO, (struct timeOutQueue *n = (struct timeOutQueue *)node; n->prev; n = n->prev, i++));
    LOG(LOG_INFO, 0, "Removed timeout (#%d): %s", i, ((struct timeOutQueue *)node)->name);
    LST_RM(node, queue, TMLST(((struct timeOutQueue *)node)->name));  // Alloced by timer_setTimer()
    DEBUGQUEUE("Clear Timer", 1, -1);
    return (intptr_t)NULL;
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
