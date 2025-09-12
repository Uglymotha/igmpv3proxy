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
*   mctable.h
*   Common multicast group structures and functions.
*/

#ifndef MCTABLE_H
#define MCTABLE_H

struct vifFlags {
    // Generic per vif flags, applies to both groups and sources
    uint32_t            sd;                       // Filters set flag for downstream
    uint32_t            d;                        // Active downstream vifs
    uint32_t            dd;                       // Denied dowstream vifs
    uint32_t            su;                       // Filters set flag for upstream
    uint32_t            u;                        // Active upstream vifs for mct, or downstream vifs for src/mfc
    uint32_t            ud;                       // Denied upstream vifs
    uint32_t            uj;                       // Upstream membership state (joined in exclude mode)
    uint32_t            lm;                       // Last member vifs
    uint32_t            qry;                      // Active query vifs
    uint8_t             age[MAXVIFS];             // Age value
};

struct src {
    // Keeps information on sources
    struct src         *prev;
    struct src         *next;
    struct mcTable     *mct;                      // Pointer to group
    struct mfc         *mfc;                      // Pointer to active MFC
    uint32_t            ip;                       // Source IP adress
    struct vifFlags     vifB;
    uint64_t            dHostsHT[];               // Host tracking table
};

struct mfc {
    // Keeps information on upstream sources, the actual routes in the kernel.
    struct mfc         *prev;
    struct mfc         *next;
    struct timespec     stamp;                    // Time Route was installed or last traffic seen
    struct src         *src;                      // Pointer to source struct
    struct IfDesc      *IfDp;                     // Incoming interface
    uint8_t             ttlVc[MAXVIFS];           // Outgoing interface tlls
    uint64_t            bytes;
    uint64_t            rate;                     // Bwcontrol counters
};

struct mcTable {
    // Keeps multicast group and source membership information.
    struct mcTable     *prev;                     // Pointer to the previous group in table.
    struct mcTable     *next;                     // Pointer to the next group in table.
    uint32_t            group;                    // The group to route
    uint32_t            nsrcs[2];                 // Nr of sources, 0 = include mode sources, 1 = origins.
    struct src         *sources;                  // Downstream source list for group
    struct mfc         *mfc;                      // Active upstream sources for group

    // Keeps the group states. Per vif flags.
    struct timespec     stamp;                    // Time group was installed
    uint32_t            mode;                     // Mode (include/exclude) for group
    struct vifFlags     vifB;
    uint32_t            v1Bits;                   // v1 compatibility flags
    uint8_t             v1Age[MAXVIFS];           // v1 compatibility timer
    uint32_t            v2Bits;                   // v2 compatibility flags
    uint8_t             v2Age[MAXVIFS];           // v2 compitibility timer

    // Keeps downstream hosts information
    uint64_t            dHostsHT[];
};

struct ifMct {
    struct ifMct       *prev;
    struct IfDesc      *IfDp;                     // Pointer back to interface.
    struct mcTable     *mct;                      // Pointer to group in multicast table
    struct ifMct       *next;
};

struct qlst {
    struct qlst       *prev;
    struct qlst       *next;
    struct mcTable    *mct;                       // Pointer to group being queried
    struct ifMct      *imc;                       // Interface for query
    intptr_t           tid;                       // Timer ID
    uint8_t            type;                      // Query type (GSQ/GSSQ)
    uint8_t            code;                      // Query max response code
    uint8_t            misc;                      // Query misc (RA/QRV)
    uint8_t            cnt;                       // Nr of queries sent
    uint32_t           group;                     // Group for query
    uint32_t           nsrcs[2];                  // Nr of sources in query, 0 = original, 1 = current
    struct src        *src[];                     // Array of pointers to sources
};
#define MCTSZ            (CONF->mcTables * sizeof(void *))
#define MCESZ            (sizeof(struct mcTable) + CONF->dHostsHTSize)
#define OMCESZ           (sizeof(struct mcTable) + OLDCONF->dHostsHTSize)
#define SRCSZ            (sizeof(struct src) + CONF->dHostsHTSize)
#define OSRCSZ           (sizeof(struct src) + OLDCONF->dHostsHTSize)
#define IFMSZ            (sizeof(struct ifMct))
#define MFCSZ            (sizeof(struct mfc))
#define QLSZ             (sizeof(struct qlst))
#define QRYSZ(n)         (QLSZ + ((((n) / 32) + 1) * 32 * sizeof(void *)))
#define INCL              0
#define EXCL              1
#define IS_EX(x, y)       BIT_TST(x->mode, y->index)
#define IS_IN(x, y)      !BIT_TST(x->mode, y->index)
#define IS_SET(x, y, z)   BIT_TST(x->vifB.y, z->index)
#define NOT_SET(x, y, z) !BIT_TST(x->vifB.y, z->index)
#define SET_HASH(x,y)     if (IfDp->conf->quickLeave) setHash(x,y)
#define CLR_HASH(x,y)     if (IfDp->conf->quickLeave) clearHash(x,y)
#define NO_HASH(x)        ({register uint64_t i = 0, n = CONF->dHostsHTSize >> 3; \
                            while(i < n && x[i] == 0) i++; i >= n; })
#define GETMRT(x)         if (MCT)                                                   \
                              for (uint16_t iz = 0; iz < CONF->mcTables; iz++)       \
                                   for (x = MCT[iz]; x; x = ! x ? MCT[iz] : x->next)
// Vif counter from ifvc.c.
extern int      vifcount, upvifcount, downvifcount;

// Prototypes
struct mcTable *findGroup(register uint32_t group, bool create);
struct ifMct   *delGroup(struct mcTable *mct, struct IfDesc *IfDp, struct ifMct *imc, int dir);
struct src     *delSrc(struct src *src, struct IfDesc *IfDp, int mode, bool leave, uint32_t srcHash);
void            joinBlockSrc(struct src *src, struct IfDesc *IfDp, bool join);
bool            checkFilters(struct IfDesc *IfDp, int dir, struct src *src, struct mcTable *mct);
struct qlst    *addSrcToQlst(struct src *src, struct IfDesc *IfDp, struct qlst *qlst, uint32_t srcHash);
void            toInclude(struct ifMct *imc);
void            startQuery(struct IfDesc *IfDp, struct qlst *qlst);
void            groupSpecificQuery(struct qlst *qlst);
void            delQuery(struct IfDesc *IfDP, struct qlst *qry, struct mcTable *mct, struct src *src);

#endif // MCTABLE_H_INCLUDED
