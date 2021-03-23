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
    uint64_t              id;
    char                  name[TMNAMESZ];  // name of the timer
    timer_f               func;            // function to call
    void                 *data;            // Argument for function.
    struct timespec       time;            // Time for event
    struct timeOutQueue  *next;            // Next event in queue
}     *queue = NULL;
static uint64_t id = 1;

/**
*   Clears all scheduled timeouts...
*/
void timer_freeQueue(void) {
    struct timeOutQueue *p;

    for (p = queue; queue; p = p->next, free(queue), queue = p);  // Alloced by timer_setTimer()
    myLog(LOG_DEBUG, 0, "timer_freeQueue: All Timeouts removed, Queue is empty.");
}

/**
*   Execute all expired timers, return time difference to next scheduled timer.
*/
struct timespec timer_ageQueue() {
    struct timeOutQueue *ptr;
    uint64_t i = 1;

    clock_gettime(CLOCK_MONOTONIC, &curtime);
    for (ptr = queue; ptr && ((curtime.tv_sec > ptr->time.tv_sec) || (curtime.tv_sec == ptr->time.tv_sec && curtime.tv_nsec > ptr->time.tv_nsec)); ptr = queue) {
        myLog(LOG_DEBUG, 0, "About to call timeout %d (#%d) - %s - Missed by %dus", ptr->id, i++, ptr->name, (ptr->time.tv_nsec > curtime.tv_nsec ? 1000000000 - ptr->time.tv_nsec + curtime.tv_nsec: curtime.tv_nsec - ptr->time.tv_nsec) / 1000);
        queue = ptr->next;
        ptr->func(ptr->data, ptr->id);
        free(ptr);     // Alloced by timer_setTimer()
    }
    if (i > 1 && CONFIG->logLevel == LOG_DEBUG) debugQueue("Age Queue", 1, NULL, 0);

    return queue ? (curtime.tv_nsec > queue->time.tv_nsec ? (struct timespec){ queue->time.tv_sec - curtime.tv_sec - 1, 1000000000 - curtime.tv_nsec + queue->time.tv_nsec }
                                                          : (struct timespec){ queue->time.tv_sec - curtime.tv_sec    , queue->time.tv_nsec - curtime.tv_nsec })
                 : (struct timespec){ -1, -1 };
}

/**
*   Inserts a timer in queue.
*   @param timer_id - Timer to modify. 0 to create new timer.
*   @param delay    - When tv_sec < 0, tv_nsec is delay in .1s, otherwise it's the exact time of schedule.
*   @param name     - Name for the timer.
*   @param action   - The function to call on timeout.
*   @param data     - Pointer to the function data to supply.
*/
uint64_t timer_setTimer(uint64_t timer_id, struct timespec delay, const char name[TMNAMESZ], timer_f action, void *data) {
    struct timeOutQueue  *ptr = NULL, *node = NULL;
    uint64_t              i = 1;

    if (timer_id) {
        // If a timer is to be modified remove it up in the queue first.
        for (node = queue; node && node->id != timer_id; ptr = node, node = node->next);
        if (! node)   return 0;
        else if (ptr) ptr->next = node->next;
        else          queue = node->next;
    } else if (! (node = (struct timeOutQueue *)malloc(sizeof(struct timeOutQueue))))  // Freed by timer_freeQueue(), timer_ageQueue() or timer_clearTimer()
        myLog(LOG_ERR, 0, "timer_setTimer: Out of memory.");

    *node = (struct timeOutQueue){ id++, "", action, data, (struct timespec){0, 0}, NULL };
    strcpy(node->name, name);
    if (delay.tv_sec < 0) {
        clock_gettime(CLOCK_MONOTONIC, &curtime);
        if (curtime.tv_nsec + (delay.tv_nsec % 10) * 100000000 > 1000000000)
            node->time = (struct timespec){ curtime.tv_sec + delay.tv_nsec / 10 + 1, curtime.tv_nsec + (delay.tv_nsec % 10) * 100000000 - 1000000000 };
        else
            node->time = (struct timespec){ curtime.tv_sec + delay.tv_nsec / 10, curtime.tv_nsec + (delay.tv_nsec % 10) * 100000000 };
    } else
        node->time = delay;

    // if the queue is empty, insert the node and return.
    if (! queue) queue = node;
    else {
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

    delay = curtime.tv_nsec > node->time.tv_nsec ? (struct timespec){ node->time.tv_sec - curtime.tv_sec - 1, 999999999 - curtime.tv_nsec + node->time.tv_nsec}
                                                 : (struct timespec){ node->time.tv_sec - curtime.tv_sec    , node->time.tv_nsec - curtime.tv_nsec }; 
    myLog(LOG_DEBUG, 0, "%s timeout %d (#%d): %s - delay %d.%1d secs", timer_id ? "Modified" : "Created", node->id, i, node->name, delay.tv_sec, delay.tv_nsec / 100000000);
    if (CONFIG->logLevel == LOG_DEBUG) debugQueue("Set Timer", 1, NULL, 0);
    return node->id;
}

/**
*   Removes a timer from the queue.
*/
void *timer_clearTimer(uint64_t timer_id) {
    struct timeOutQueue *ptr = NULL, *fptr = NULL;
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
        if (ptr->next) ptr->next = ptr->next->next;
    }
    if (fptr) {
        if (CONFIG->logLevel == LOG_DEBUG) debugQueue("Clear Timer", 1, NULL, 0);
        ptr = (void *)fptr->data;
        myLog(LOG_DEBUG, 0, "Removed timeout %d (#%d): %s", fptr->id, i, fptr->name);
        free(fptr);        // Alloced by timer_setTimer()
    }

    // Return pointer to the cleared timer's data, the caller may need it.
    return (void *)ptr;
}

/**
*  Returns the scheduled time for given timer.
*/
inline struct timespec timer_getTime(uint64_t timer_id) {
    struct timeOutQueue *node = NULL;
    for (node = queue; node && node->id != timer_id; node = node->next);
    return node ? node->time : (struct timespec){ -1, -1 };
}

/**
*   Debugging utility
*/
void debugQueue(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd) {
    char                  msg[CLI_CMD_BUF] = "", buf[CLI_CMD_BUF] = "";
    struct timeOutQueue  *ptr;
    uint64_t              i;

    clock_gettime(CLOCK_MONOTONIC, &curtime);
    if (! cliSockAddr) myLog(LOG_DEBUG, 0, "----------------------%s-----------------------", header);
    else if (h) {
        sprintf(buf, "Active Timers:\n_Nr_|____In____|___ID___|________________Name_______________\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
    for (i = 1, ptr = queue; ptr; ptr = ptr->next, i++) {
        struct timespec delay = curtime.tv_sec > ptr->time.tv_sec || (curtime.tv_sec == ptr->time.tv_sec && curtime.tv_nsec > ptr->time.tv_nsec) ? (struct timespec){ 0, 0 } :
                                ptr->time.tv_nsec < curtime.tv_nsec ? (struct timespec){ ptr->time.tv_sec - curtime.tv_sec - 1, 1000000000 - (curtime.tv_nsec + ptr->time.tv_nsec) / 100000000 }
                                                                    : (struct timespec){ ptr->time.tv_sec - curtime.tv_sec    , ptr->time.tv_nsec - curtime.tv_nsec / 100000000 };
        if (! cliSockAddr)
            myLog(LOG_DEBUG, 0, "%3d [%5d.%1ds] - Id:%6d - %s", i, delay.tv_sec, delay.tv_nsec / 100000000, ptr->id, ptr->name);
        else {
            if (h) strcpy(msg, "%3d | %5d.%1ds | %6d | %s");
            else   strcpy(msg, "%d %d.%d %d %s");
            sprintf(buf, strcat(msg, "\n"), i, delay.tv_sec, delay.tv_nsec / 100000000, ptr->id, ptr->name);
            sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
        }
    }
    if (h) {
        sprintf(buf, "------------------------------------------------------------\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
