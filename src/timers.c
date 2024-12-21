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

extern volatile sig_atomic_t sighandled;  // From igmpv3proxy.c signal handler.

// Queue definition.
static struct timeOutQueue {
    uint64_t                id;
    void                (*func)(void *, uint64_t);  // function to call
    void                 *data;                     // Argument for function.
    struct timespec       time;                     // Time for event
    struct timeOutQueue  *next;                     // Next event in queue
    char                 *name;                     // name of the timer
}     *queue = NULL;
#define TMSZ(n) (sizeof(struct timeOutQueue) + strlen(n) + 1)
static uint64_t id = 1;

/**
*   Execute at most CONF->tmQsz expired timers, return time difference to next scheduled timer.
*   Returns -1,-1 if no timer is scheduled, 0, -1 if next timer has already expired.
*/
struct timespec timer_ageQueue(void) {
    struct timeOutQueue *node = queue;
    uint64_t                i = 1;

    clock_gettime(CLOCK_REALTIME, &curtime);
    for (; !sighandled && !STARTUP && i <= CONF->tmQsz && node && timeDiff(curtime, node->time).tv_nsec == -1; node = queue, i++) {
        LOG(LOG_INFO, 0, "About to call timeout %d (#%d) - %s - Missed by %dus", node->id, i, node->name,
                          timeDiff(node->time, curtime).tv_nsec / 1000);
        node->func(node->data, node->id);
        // The function may have removed the timeout itself, check before freeing.
        if (queue == node) {
            queue = node->next;
            _free(node, tmr, TMSZ(node->name));
        }
        clock_gettime(CLOCK_REALTIME, &curtime);
    }
    if (i > 1)
        DEBUGQUEUE("Age Queue", 1, -1);

    return queue ? timeDiff(curtime, queue->time) : (struct timespec){-1, -1};
}

/**
*   Inserts a timer in queue. Queue is maintained in order of execution.
*   FIFO if timers are scheduled at exactly the same time. Delay in multiples of .1s
*/
uint64_t timer_setTimer(int delay, const char *name, void (*func)(), void *data) {
    struct timeOutQueue  *ptr = NULL, *node = NULL;
    uint64_t                i = 1;

    // Create and set a new timer.
    _malloc(node, tmr, TMSZ(name));  // Freed by timer_ageQueue() or timer_clearTimer()
    *node = (struct timeOutQueue){ id++, func, data, timeDelay(delay), NULL, memcpy(&node->name + 1, name, strlen(name) + 1) };
    if (!queue || timeDiff(queue->time, node->time).tv_nsec == -1) {
        // Start of queue, insert.
        node->next = queue;
        queue = node;
    } else {
        // chase the queue looking for the right place.
        for (ptr = queue, i++; ptr->next && timeDiff(ptr->next->time, node->time).tv_nsec != -1; ptr = ptr->next, i++);
        node->next = ptr->next;
        ptr->next = node;
    }

    LOG(LOG_INFO, 0, "Created timeout %d (#%d): %s - delay %d.%1d secs", node->id, i, node->name, delay / 10, delay % 10);
    DEBUGQUEUE("Set Timer", 1, -1);
    return node->id;
}

/**
*   Removes a timer from the queue.
*/
void *timer_clearTimer(uint64_t tid) {
    struct timeOutQueue *node, *pnode;
    uint64_t i;

    // Find the timer and remove it if found.
    for (pnode = NULL, i = 1, node = queue; node && node->id != tid; pnode = node, node = node->next, i++);
    if (node) {
        if (pnode)
            pnode->next = node->next;
        else
            queue = node->next;
        DEBUGQUEUE("Clear Timer", 1, -1);
        pnode = (void *)node->data;
        LOG(LOG_DEBUG, 0, "Removed timeout %d (#%d): %s", node->id, i, node->name);
        _free(node, tmr, TMSZ(node->name));        // Alloced by timer_setTimer()
    }

    // If timer was removed, return its data, the caller may need it.
    return node ? (void *)pnode : NULL;
}

/**
*   Debugging utility
*/
void debugQueue(const char *header, int h, int fd) {
    char                  msg[CLI_CMD_BUF] = "", buf[CLI_CMD_BUF] = "";
    struct timeOutQueue  *node = queue;
    uint64_t              i;

    if (fd < 0 && CONF->logLevel < LOG_DEBUG)
        return;
    clock_gettime(CLOCK_REALTIME, &curtime);
    if (fd < 0)
        LOG(LOG_DEBUG, 0, "----------------------%s-----------------------", header);
    else if (h) {
        sprintf(buf, "Active Timers:\n_Nr_|____In____|___ID___|________________Name_______________\n");
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
    for (i = 1; node; node = node->next, i++) {
        struct timespec delay = timeDiff(curtime, node->time);
        if (fd < 0)
            LOG(LOG_DEBUG, 0, "| %3d %5d.%1ds | - Id:%6d - %s", i, delay.tv_sec, delay.tv_nsec / 100000000, node->id, node->name);
        else {
            strcpy(msg, h ? "%3d | %5d.%1ds | %6d | %s" : "%d %d.%d %d %s");
            sprintf(buf, strcat(msg, "\n"), i, delay.tv_sec, delay.tv_nsec / 100000000, node->id, node->name);
            send(fd, buf, strlen(buf), MSG_DONTWAIT);
        }
    }
    if (fd < 0) {
        LOG(LOG_DEBUG, 0, "------------------------------------------------------");
        LOG(LOG_DEBUG, 0, "Memory Stats: %lldb in use, %lld allocs, %lld frees.", memuse.tmr, memalloc.tmr, memfree.tmr);
    } else if (h) {
        sprintf(buf, "------------------------------------------------------------\n");
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
}
