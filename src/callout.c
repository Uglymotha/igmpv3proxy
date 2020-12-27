/*
**  igmpproxy - IGMP proxy based multicast router
**  Copyright (C) 2005 Johnny Egeland <johnny@rlo.org>
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
**  of igmpproxy.
**
**  smcroute 0.92 - Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
**  - Licensed under the GNU General Public License, either version 2 or
**    any later version.
**
**  mrouted 3.9-beta3 - Copyright (C) 2002 by The Board of Trustees of
**  Leland Stanford Junior University.
**  - Licensed under the 3-clause BSD license, see Stanford.txt file.
**
*/

#include "igmpproxy.h"

// Queue definition.
static struct timeOutQueue {
    uint64_t                id;
    char                    name[40];   // name of the timer
    timer_f                 func;       // function to call
    void                   *data;       // Argument for function.
    struct timespec         time;       // Time for event
    struct timeOutQueue    *next;       // Next event in queue
}     *queue = NULL;
static uint64_t id = 1;

/**
*   Clears all scheduled timeouts...
*/
void timer_freeQueue(void) {
    struct timeOutQueue *p;

    for (p = queue; queue; queue = p) {
        p = p->next;
        free(queue);        // Alloced by timer_setTimer()
    }
    myLog(LOG_DEBUG, 0, "timer_freeQueue: All Timeouts removed, Queue is empty.");
}

/**
*   Execute all expired timers, return time difference to next scheduled timer.
*/
struct timespec timer_ageQueue() {
    struct timeOutQueue *ptr;
    uint64_t i = 1;

    for (ptr = queue; ptr && ((curtime.tv_sec > ptr->time.tv_sec) || (curtime.tv_sec == ptr->time.tv_sec && curtime.tv_nsec > ptr->time.tv_nsec)); ptr = queue) {
        myLog(LOG_DEBUG, 0, "About to call timeout %d (#%d) - %s - Missed by %dus", ptr->id, i++, ptr->name, (ptr->time.tv_nsec > curtime.tv_nsec ? 1000000000 - ptr->time.tv_nsec + curtime.tv_nsec: curtime.tv_nsec - ptr->time.tv_nsec) / 1000);
        queue = ptr->next;
        ptr->func(ptr->data);
        free(ptr);     // Alloced by timer_setTimer()
    }
    if (i > 1) debugQueue("Age Queue", 1, NULL, 0);

    return queue ? (struct timespec){ curtime.tv_nsec > queue->time.tv_nsec ? queue->time.tv_sec - curtime.tv_sec - 1 : queue->time.tv_sec - curtime.tv_sec,
                                      curtime.tv_nsec > queue->time.tv_nsec ? 1000000000 - curtime.tv_nsec + queue->time.tv_nsec: queue->time.tv_nsec - curtime.tv_nsec }
                 : (struct timespec){ -1, -1 };
}

/**
*   Inserts a timer in queue.
*   @param timer_id - Timer to modify. 0 to create new timer.
*   @param delay    - Timer delay in .1s.
*   @param name     - Name for the timer.
*   @param action   - The function to call on timeout.
*   @param data     - Pointer to the function data to supply.
*/
uint64_t timer_setTimer(uint64_t timer_id, unsigned int delay, const char name[40], timer_f action, void *data) {
    struct timeOutQueue  *ptr, *node;
    uint64_t              i = 1;

    if (timer_id) {
        // If a timer is to be modified look it up in the queue.
        for (ptr = NULL, node = queue; node && node->id != timer_id; ptr = node, node = node->next);
        if (! node) return 0;
        node->func = action ? action : node->func;
        node->data = data ? data : node->data;
    } else if (! (node = (struct timeOutQueue *)malloc(sizeof(struct timeOutQueue)))) {  // Freed by timer_freeQueue(), timer_ageQueue() or timer_clearTimer()
        myLog(LOG_ERR, 0, "timer_setTimer: Out of memory.");
    } else *node = (struct timeOutQueue){ id++, "", action, data, (struct timespec){0, 0}, NULL };
    strcpy(node->name, ! timer_id || (timer_id && strlen(name) > 0) ? name : node->name);
    if (! timer_id || (timer_id && delay)) {
        // If the a timer's scheduled time is modified remove it from the list before reinserting.
        if (timer_id && ptr) ptr->next = node->next;
        else if (timer_id && ! ptr) queue = node->next;
        clock_gettime(CLOCK_MONOTONIC, &curtime);
        node->time.tv_sec  = curtime.tv_nsec + (delay % 10) * 100000000 > 1000000000 ? curtime.tv_sec + delay / 10 + 1 : curtime.tv_sec + delay / 10;
        node->time.tv_nsec = curtime.tv_nsec + (delay % 10) * 100000000 > 1000000000 ? curtime.tv_nsec + (delay % 10) * 100000000 - 1000000000 : curtime.tv_nsec + (delay % 10) * 100000000;
    }

    // if the queue is empty, insert the node and return.
    if (! queue) queue = node;
    else if (! timer_id || (timer_id && delay)) {
        // chase the queue looking for the right place.
        for (ptr = queue, i++; ptr->next && (node->time.tv_sec > ptr->next->time.tv_sec ||
                               (node->time.tv_sec == ptr->next->time.tv_sec && node->time.tv_nsec >= ptr->next->time.tv_nsec)); ptr = ptr->next, i++);
        if (ptr == queue && (node->time.tv_sec < ptr->time.tv_sec || (node->time.tv_sec == ptr->time.tv_sec && node->time.tv_nsec < ptr->time.tv_nsec))) {
           // Start of queue, insert.
           i--;
           queue = node;
           node->next = ptr;
        } else {
           node->next = ptr->next;
           ptr->next = node;
        }
    }

    myLog(LOG_DEBUG, 0, "%s timeout %d (#%d): %s - delay %d.%1d secs", timer_id ? "Modified" : "Created", node->id, i, node->name, delay / 10, delay % 10);
    debugQueue("Set Timer", 1, NULL, 0);
    return node->id;
}

/**
*   Removes a timer from the queue.
*/
void *timer_clearTimer(uint64_t timer_id) {
    struct timeOutQueue *ptr = NULL, *fptr = NULL;
    void *data = NULL;
    uint64_t i = 1;

    // If no queue or timer_id is zero return.
    if (! queue || timer_id == 0) return NULL;

    // Search queue for timer and remove.
    if (queue->id == timer_id) {
        fptr = queue;
        queue = queue->next;
    } else {
        for (i++, ptr = queue; ptr->next && ptr->next->id != timer_id; ptr = ptr->next, i++);
        fptr = ptr->next;
        ptr->next = ptr->next ? ptr->next->next : NULL;
    }
    if (fptr) {
        clock_gettime(CLOCK_MONOTONIC, &curtime);
        debugQueue("Clear Timer", 1, NULL, 0);
        myLog(LOG_DEBUG, 0, "Removed timeout %d (#%d): %s", i, fptr->id, fptr->name);
        data = fptr->data;
        free(fptr);        // Alloced by timer_setTimer()
    }

    // Return pointer to the cleared timer's data, the caller may need it.
    return data;
}

/**
*   Debugging utility
*/
void debugQueue(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd) {
    char                  msg[CLI_CMD_BUF] = "", buf[CLI_CMD_BUF] = "";
    struct timeOutQueue  *ptr;
    uint64_t              i;

    if (! cliSockAddr) myLog(LOG_DEBUG, 0, "----------------------%s-----------------------", header);
    else if (h) {
        sprintf(buf, "Active Timers:\n_Nr_|____In____|___ID___|________________Name_______________\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
    for (i = 1, ptr = queue; ptr; ptr = ptr->next, i++) {
        if (! cliSockAddr) {
            myLog(LOG_DEBUG, 0, "%3d [%5d.%1ds] - Id:%6d - %s", i, ptr->time.tv_nsec < curtime.tv_nsec ? ptr->time.tv_sec - curtime.tv_sec - 1 : ptr->time.tv_sec - curtime.tv_sec, ptr->time.tv_nsec < curtime.tv_nsec ? (1000000000 - curtime.tv_nsec + ptr->time.tv_nsec) / 100000000 : (ptr->time.tv_nsec - curtime.tv_nsec) / 100000000, ptr->id, ptr->name);
            continue;
        }
        else if (h) strcpy(msg, "%3d | %5d.%1ds | %6d | %s");
        else strcpy(msg, "%d %d.%d %d %s");
        sprintf(buf, strcat(msg, "\n"), i, ptr->time.tv_nsec < curtime.tv_nsec ? ptr->time.tv_sec - curtime.tv_sec - 1 : ptr->time.tv_sec - curtime.tv_sec, ptr->time.tv_nsec < curtime.tv_nsec ? (1000000000 - curtime.tv_nsec + ptr->time.tv_nsec) / 100000000 : (ptr->time.tv_nsec - curtime.tv_nsec) / 100000000, ptr->id, ptr->name);
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
    if (h) {
        sprintf(buf, "------------------------------------------------------------\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
