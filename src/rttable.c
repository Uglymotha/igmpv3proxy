/*
**  igmpv3proxy - IGMP proxy based multicast router
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
*/
/**
*   rttable.c
*   Maintains IGMP group membership and routes.
*/

#include "igmpv3proxy.h"

/**
*   Routing table structure definitions.
*/
struct perms {
    uint32_t            e;                        // Flag if permissions are evaluated
    uint32_t            p;                        // Permission, 0 = block, 1 = allow
};

struct sources {
    // Keeps information on sources
    struct sources     *prev;
    struct sources     *next;
    struct mcTable     *mct;                      // Pointer to group
    struct mfc         *mfc;                      // Pointer to active MFC
    uint32_t            ip;                       // Source IP adress
    uint32_t            vifBits;                  // Active vifs for source
    struct perms        uPBits;                   // Disallowed upstream vifs for source
    struct perms        dPBits;                   // Disallowed downstream vifs for source
    uint32_t            lmBits;                   // Per vif last member state
    uint32_t            qryBits;                  // Active query interfaces flag
    uint8_t             age[MAXVIFS];             // Age value for source
    uint64_t            dHostsHT[];               // Host tracking table
};

struct mfc {
    // Keeps information on upstream sources, the actual routes in the kernel.
    struct mfc         *prev;
    struct mfc         *next;
    struct timespec     stamp;                    // Time Route was installed or last traffic seen
    struct sources     *src;                      // Pointer to source struct
    struct IfDesc      *IfDp;                     // Incoming interface
    uint64_t            bytes, rate;              // Bwcontrol counters
};

struct mcTable {
    // Keeps multicast group and source membership information.
    struct mcTable     *prev;                     // Pointer to the previous group in table.
    struct mcTable     *next;                     // Pointer to the next group in table.
    uint32_t            group;                    // The group to route
    uint32_t            nsrcs;                    // Number of sources for group
    struct sources     *sources;                  // Downstream source list for group
    struct mfc         *mfc;                      // Active upstream sources for group

    // Keeps the group states. Per vif flags.
    struct timespec     stamp;                    // Time group was installed
    uint32_t            mode;                     // Mode (include/exclude) for group
    uint32_t            vifBits;                  // Bits representing recieving VIFs
    struct perms        uPBits;                   // Disallowed upstream vifs for group
    struct perms        dPBits;                   // Disallowed downstream vifs for group
    uint32_t            upstrState;               // Upstream membership state
    uint32_t            gcBits;                   // Garbage Collection flags
    uint32_t            qryBits;                  // Active query interfaces flag
    uint32_t            lmBits;                   // Last member flag
    uint32_t            v1Bits;                   // v1 compatibility flags
    uint8_t             v1Age[MAXVIFS];           // v1 compatibility timer
    uint32_t            v2Bits;                   // v2 compatibility flags
    uint8_t             v2Age[MAXVIFS];           // v2 compitibility timer
    uint8_t             age[MAXVIFS];             // Downcounter for death.

    // Keeps downstream hosts information
    uint64_t            dHostsHT[];
};

struct ifMct {
    struct ifMct       *prev;
    struct mcTable     *mct;                      // Pointer to group in multicast table
    struct ifMct       *next;
};

struct qlst {
    struct qlst       *prev;
    struct qlst       *next;
    struct mcTable    *mct;                       // Pointer to group being queried
    struct IfDesc     *IfDp;                      // Interface for query
    uint64_t           tid;                       // Timer ID
    uint8_t            type;                      // Query type (GSQ/GSSQ)
    uint8_t            code;                      // Query max response code
    uint8_t            misc;                      // Query misc (RA/QRV)
    uint8_t            cnt;                       // Nr of queries sent
    uint16_t           nsrcs;                     // Nr of sources in query
    struct sources    *src[];                     // Array of pointers to sources
};

// Routing table static vars.
static struct mcTable  **MCT           = NULL;   // Multicast group membership tables
static struct qlst      *qL            = NULL;   // List of running GSQ
static uint32_t          qC            = 0;      // Querier count.
static char              msg[TMNAMESZ] = "";     // Timer name buffer

// Prototypes
static struct mcTable         *findGroup(register uint32_t group, bool create);
static inline bool             addGroup(struct mcTable* mct, struct IfDesc *IfDp, int dir);
static struct ifMct           *delGroup(struct mcTable *mct, struct IfDesc *IfDp, struct ifMct *imc, int dir);
static bool                    checkFilters(struct IfDesc *IfDp, int old, int dir, struct sources *dsrc, struct mcTable *mct);
static struct ifMct           *updateSourceFilter(struct mcTable *mct, struct IfDesc *IfDp, struct ifMct *imc);
static void                    sendJoinLeaveUpstream(struct mcTable* mct, int join);
static inline struct sources  *addSrc(struct IfDesc *IfDp, struct mcTable *mct, uint32_t ip, bool check, struct sources *dsrc);
static struct sources         *delSrc(struct sources *dsrc, struct IfDesc *IfDp, uint32_t srcHash);
static inline struct qlst     *addSrcToQlst(struct sources *dsrc, struct IfDesc *IfDp, struct qlst *qlst, uint32_t srcHash);
static inline void             toInclude(struct mcTable *mct, struct IfDesc *IfDp);
static inline void             startQuery(struct IfDesc *IfDp, struct qlst *qlst);
static void                    groupSpecificQuery(struct qlst *qlst);

/**
*   Private access function to find a given group in MCT, creates new if required.
*/
static struct mcTable *findGroup(register uint32_t group, bool create) {
    struct mcTable *mct, *Nmct;
    uint32_t        mctHash = murmurhash3(group) % CONFIG->mcTables;

    // Initialize the routing tables if necessary.
    if (! MCT && ! (MCT = calloc(CONFIG->mcTables, sizeof(void *))))   // Freed by delGroup())
        LOG(LOG_ERR, errno, "findGroup: Out of memory.");
    // Find the group (or place for new) in the table.
    for (mct = MCT[mctHash];; mct = mct->next) {
        if (mct && mct->group == group)
            return mct;
        if (! mct || ! mct->next || mct->next->group > group) {
            if (!create)
                return NULL;
            else
                break;
        }
    }

    // Create and initialize the new MCT entry. Freed by delGroup()
    LOG(LOG_INFO, 0, "findGroup: Create new group %s in table %d.", inetFmt(group, 1), mctHash);
    if (! (Nmct = calloc(1, sizeof(struct mcTable) + CONFIG->dHostsHTSize)))
        LOG(LOG_ERR, errno, "findGroup: Out of memory.");
    Nmct->group = group;
    clock_gettime(CLOCK_REALTIME, &(Nmct->stamp));
    if (! MCT[mctHash] || MCT[mctHash]->group > group) {
        MCT[mctHash] = Nmct;
        if (mct) {
            mct->prev = Nmct;
            Nmct->next = mct;
        }
    } else {
        Nmct->prev = mct;
        Nmct->next = mct->next;
        if (Nmct->next)
            Nmct->next->prev = Nmct;
        mct->next = Nmct;
    }

    return Nmct;
}

/**
*  Adds a group to an interface.
*/
static inline bool addGroup(struct mcTable* mct, struct IfDesc *IfDp, int dir) {
    struct ifMct *imc, **list = (struct ifMct **)(dir ? &IfDp->dMct : mct->vifBits ? &IfDp->uMct : &IfDp->gMct);
    if (   (                 dir && !checkFilters(IfDp, 0, 1, NULL, mct))
        || (mct->vifBits && !dir && !checkFilters(IfDp, 0, 0, NULL, mct))) {
        LOG(LOG_NOTICE, 0, "The group %s may not be requested %s on %s.", inetFmt(mct->group , 1),
                            dir ? "downstream" : "upstream", IfDp->Name);
        return false;
    }

    if (!dir || NOT_SET(mct, IfDp)) {
        // Create a new group on interfaces, there should not be any queries running, but clean up just in case.
        delQuery(IfDp, NULL, mct, NULL, 0);
        if (! (imc = malloc(sizeof(struct ifMct))))   // Freed by delGroup or freeIfDescL()
            LOG(LOG_ERR, errno, "addGroup: Out of Memory.");
        *imc = (struct ifMct){ NULL, mct, *list };
        if (*list)
            (*list)->prev = imc;
        *list = imc;
    }

    if (dir && !mct->vifBits && mct->gcBits)
        for (int i = 0; i < MAXVIFS; ((mct->gcBits >> i) & 0x1) ? delGroup(mct, getIf(i, 0), NULL, 0) : (void)0, i++);
    if (dir)
           BIT_SET(mct->vifBits, IfDp->index);
    else if (mct->vifBits)
        BIT_SET(mct->upstrState, IfDp->index);

    return true;
}

/**
*   Remove a specified MCT from interface.
*/
static struct ifMct *delGroup(struct mcTable* mct, struct IfDesc *IfDp, struct ifMct *imc, int dir) {
    struct ifMct *pimc = NULL;
    // Log the cleanup in debugmode...
    LOG(LOG_DEBUG, 0, "delGroup: Removing group entry for %s from %s.",
                       inetFmt(mct->group, 1), IfDp ? IfDp->Name : "all interfaces");

    // Clear group membership from interface (or all on shutdown) and ckeck if it can be removed completely.
    if (dir) {
        delQuery(IfDp, NULL, mct, NULL, 0);
        BIT_CLR(mct->vifBits, IfDp->index);
        if (mct->vifBits) {
            // Clear interface and sources flags and Update kernel route if group still active on other interface.
            BIT_CLR(mct->qryBits, IfDp->index),
            BIT_CLR(mct->lmBits, IfDp->index);
            BIT_CLR(mct->mode, IfDp->index);
            BIT_CLR(mct->v1Bits, IfDp->index);
            BIT_CLR(mct->v2Bits, IfDp->index);
            BIT_CLR(mct->dPBits.e, IfDp->index);
            BIT_CLR(mct->uPBits.e, IfDp->index);
            mct->age[IfDp->index] = mct->v1Age[IfDp->index] = mct->v2Age[IfDp->index] = 0;
            for (struct mfc *mfc = mct->mfc; mfc; activateRoute(NULL, mfc->src, 0, 0, true), mfc = mfc->next);
            for (struct sources *dsrc = mct->sources; dsrc; dsrc = delSrc(dsrc, IfDp, (uint32_t)-1));
        }
    }

    // Update the interface group list.
    if (!(dir && mct->vifBits)) {
        if (! imc)
            for (imc = dir ? IfDp->dMct : BIT_TST(mct->gcBits, IfDp->index) ? IfDp->gMct : IfDp->uMct;
                 imc && imc->mct != mct; imc = imc->next);
        pimc = imc->prev;
        if (imc->next)
            imc->next->prev = imc->prev;
        if (imc->prev)
            imc->prev->next = imc->next;
        else if (dir)
            IfDp->dMct = imc->next;
        else if (BIT_TST(mct->gcBits, IfDp->index))
            IfDp->gMct = imc->next;
        else
            IfDp->uMct = imc->next;
        free(imc);  // Alloced by addGroup()
    }

    if (!dir && BIT_TST(mct->gcBits, IfDp->index))
        BIT_CLR(mct->gcBits, IfDp->index);

    // Check if group should be removed from table.
    if (!mct->vifBits && !mct->gcBits && !(!dir && mct->upstrState)) {
        uint32_t mctHash = murmurhash3(mct->group) % CONFIG->mcTables;

        LOG(LOG_DEBUG, 0, "delGroup: Deleting group %s from table %d.",inetFmt(mct->group, 1), mctHash);
        // Send Leave request upstream.
        sendJoinLeaveUpstream(mct, 0);
        for (struct mfc *mfc = mct->mfc; mfc; activateRoute(NULL, mfc->src, 0, 0, false), mfc = mct->mfc);

        // Update MCT and check if all tables are empty.
        if (mct->next)
            mct->next->prev = mct->prev;
        if (mct != MCT[mctHash])
            mct->prev->next = mct->next;
        else if (! (MCT[mctHash] = mct->next)) {
            uint16_t iz;
            for (iz = 0; MCT && iz < CONFIG->mcTables && ! MCT[iz]; iz++);
            if (iz == CONFIG->mcTables) {
                free(MCT);  // Alloced by findGroup()
                MCT = NULL;
            }
        }

        // Remove all sources from group.
        for (struct sources *src = mct->sources; src; src = delSrc(src, NULL, (uint32_t)-1));
        free(mct);  // Alloced by findGroup()
    } else if (!dir)
        // Clear upstream flag if group removed from upstream interface.
        BIT_CLR(mct->upstrState, IfDp->index);

    if (MCT)
        logRouteTable("Remove Group", 1, NULL, 0);
    else
        LOG(LOG_DEBUG, 0, "delGroup: Multicast table is empty.");
    return pimc;
}

/**
*   Creates a new source for group and adds it to list of sources. Doubly linked list
*   with prev of fist pointing to last item in queue. We will be called from updateGroup()
*   which as it evaluates the list in linear order knows exactly where source should be
*   created in list, no dsrc if it should go to end of list.
*/
static inline struct sources *addSrc(struct IfDesc *IfDp, struct mcTable *mct, uint32_t ip, bool check, struct sources *dsrc) {
    if (! dsrc || dsrc->ip != ip) {
        // New source should be created.
        struct sources *nsrc;
        LOG(LOG_DEBUG, 0, "addSrc: New source %s for group %s.", inetFmt(ip, 1), inetFmt(mct->group, 2));
        if (! (nsrc = calloc(1, sizeof(struct sources) + CONFIG->dHostsHTSize)))
            LOG(LOG_ERR, errno, "addSrc: Out of memory.");   // Freed by delSrc()
        nsrc->ip = ip;
        nsrc->mct = mct;
        if (! mct->sources) {
            mct->sources = nsrc;
            nsrc->prev = nsrc;
        } else if (! dsrc) {
            nsrc->prev = mct->sources->prev;
            nsrc->prev->next = mct->sources->prev = nsrc;
        } else {
            nsrc->prev = dsrc->prev;
            if (mct->sources == dsrc)
                mct->sources = nsrc;
            else
                nsrc->prev->next = nsrc;
            nsrc->next = dsrc;
            dsrc->prev = nsrc;
        }
        dsrc = nsrc;
        mct->nsrcs++;
    } else if (!dsrc->vifBits)
        // Unrequested sending source or source in garbage route was requested, increase nrsrcs.
        mct->nsrcs++;

    // Check if maxorigins is exceeded. Remove source if so.
    if (CONFIG->maxOrigins && mct->nsrcs > CONFIG->maxOrigins) {
        mct->nsrcs |= 0x80000000;
        LOG(LOG_WARNING, 0, "Max origins (%d) exceeded for %s.",
                             CONFIG->maxOrigins, inetFmt(mct->group, 1), inetFmt(ip, 2));
        delSrc(dsrc, IfDp, (uint32_t)-1);
        return NULL;
    }

    // Check if the source is allowed on interface. Remove it it isn't.
    if (check && !checkFilters(IfDp, 0, 1, dsrc, mct)) {
        LOG(LOG_NOTICE, 0, "Group %s from source %s not allowed on %s.", inetFmt(mct->group, 1), inetFmt(ip, 2), IfDp->Name);
        delSrc(dsrc, IfDp, (uint32_t)-1);
        return NULL;
    }

    return dsrc;
}

/**
*   Removes a source from the list of group sources.
*/
static struct sources *delSrc(struct sources *dsrc, struct IfDesc *IfDp, uint32_t srcHash) {
    struct sources *nsrc = dsrc->next;

    LOG(LOG_DEBUG, 0, "delSrc: Remove source %s from %s on %s.", inetFmt(dsrc->ip, 1), inetFmt(dsrc->mct->group, 2),
                       IfDp ? IfDp->Name : "all interfaces");
    // Remove source from hosts hash table, and clear vifbits.
    if (srcHash != (uint32_t)-1)
        clearHash(dsrc->dHostsHT, srcHash);
    if (IfDp)
        BIT_CLR(dsrc->vifBits, IfDp->index);

    if (! IfDp || !BIT_TST(dsrc->qryBits, IfDp->index)) {
        // Remove the source if it is not actively being queried and not active on other vifs.
        if (IfDp) {
            BIT_CLR(dsrc->dPBits.e, IfDp->index);
            BIT_CLR(dsrc->uPBits.e, IfDp->index);
            BIT_CLR(dsrc->lmBits, IfDp->index);
            dsrc->age[IfDp->index] = 0;
        }
        if (! IfDp || !dsrc->vifBits) {
            if (CONFIG->maxOrigins && --dsrc->mct->nsrcs < CONFIG->maxOrigins)
                // Reset maxorigins exceeded flag.
                dsrc->mct->nsrcs &= ~0x80000000;
            if (! dsrc->mfc) {
                // Remove the source if there are no senders.
                if (dsrc->next)
                    dsrc->next->prev = dsrc->prev;
                if (dsrc == dsrc->mct->sources->prev)
                    dsrc->mct->sources->prev = dsrc->prev;
                if (dsrc != dsrc->mct->sources)
                    dsrc->prev->next = dsrc->next;
                else
                    dsrc->mct->sources = dsrc->next;
                free(dsrc);  // Alloced by addSrc()
            }
        }
    }
    return nsrc;
}

/**
*   Calculates bandwidth fo group/subnet filter.
*/
uint64_t getGroupBw(struct subnet group, struct IfDesc *IfDp) {
    struct mcTable    *mct;
    struct mfc        *mfc;
    register uint64_t  bw = 0;

    // Go over all groups and calculate combined bandwith for subnet/mask.
    GETMRT(mct) {
        if (IS_UPSTREAM(IfDp->state) && (mct->group & group.mask) == group.ip) {
            for (mfc = mct->mfc; mfc; mfc = mfc->next)
                bw = mfc->IfDp == IfDp ? bw + mfc->rate : bw;
        } else if (IS_DOWNSTREAM(IfDp->state) && (mct->group & group.mask) == group.ip && IS_SET(mct, IfDp)) {
            for (mfc = mct->mfc; mfc; mfc = mfc->next)
                bw += mfc->rate;
        }
    }

    return bw;
}

#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
/**
*   Bandwith control processing for BSD systems.
*/
void processBwUpcall(struct bw_upcall *bwUpc, int nr) {
    struct IfDesc  *IfDp;
    struct mfc     *mfc;

    // Process all pending BW_UPCALLS.
    for (int i = 0; i < nr; i++, bwUpc++) {
        struct mcTable *mct = findGroup(bwUpc->bu_dst.s_addr, false);
        if (! mct)
            LOG(LOG_WARNING, 0, "BW_UPCALL: Src %s, Dst %s, but no group found.",
                                 inetFmt(bwUpc->bu_dst.s_addr, 1), inetFmt(bwUpc->bu_dst.s_addr, 2));

        // Find the source for the upcall and add to counter.
        for (mfc = mct->mfc; mfc && mfc->src->ip != bwUpc->bu_src.s_addr; mfc = mfc->next);
        if (mfc) {
            mfc->bytes += bwUpc->bu_measured.b_bytes;
            mfc->rate = bwUpc->bu_measured.b_bytes / CONFIG->bwControlInterval;
            LOG(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to Src %s Dst %s, total %lldB (%lld B/s)",
                               bwUpc->bu_measured.b_bytes, inetFmt(mfc->src->ip, 1), inetFmt(mct->group, 2), mfc->bytes, mfc->rate);
            for (GETIFL(IfDp)) {
                // Find the incoming and outgoing interfaces and add to counter.
                if (IfDp == mfc->IfDp || IS_SET(mct, IfDp)) {
                    IfDp->bytes += bwUpc->bu_measured.b_bytes;
                    LOG(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to interface %s (%lld B/s), total %lld.",
                                       bwUpc->bu_measured.b_bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
                }
            }
        }
    }
}
#endif

/**
*   Process all S,G counters and calculate interface rates.
*/
void bwControl(uint64_t *tid) {
    struct IfDesc   *IfDp = NULL;
    struct mcTable  *mct;
    struct mfc      *mfc;

    // Reset all interface rate counters.
    for (GETIFL(IfDp))
        IfDp->rate = 0;

    // Go over all MCT.
    GETMRT(mct) {
        // Go over all sources.
        for (mfc = mct->mfc; mfc; mfc = mfc->next) {
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
            // On Linux get the S,G statistics via ioct. On BSD they are processed by processBwUpcall().
            struct sioc_sg_req siocReq = { {mfc->src->ip}, {mct->group}, 0, 0, 0 };
            if (ioctl(MROUTERFD, SIOCGETSGCNT, (void *)&siocReq, sizeof(siocReq))) {
                LOG(LOG_WARNING, errno, "BW_CONTROL: ioctl failed.");
                continue;
            }
            uint64_t bytes = siocReq.bytecnt - mfc->bytes;
            mfc->bytes += bytes;
            mfc->rate = bytes / CONFIG->bwControlInterval;
            LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to Src %s Dst %s (%lld B/s), total %lld.",
                               bytes, inetFmt(mfc->src->ip, 1), inetFmt(mct->group, 2), mfc->rate, mfc->bytes);
#else
            // On BSD systems go over all interfaces.
            for (GETIFL(IfDp)) {
                if (IfDp == mfc->IfDp || IS_SET(mct, IfDp)) {
                    IfDp->rate += mfc->rate;
                    LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld B/s to interface %s (%lld B/s), total %lld.",
                                       mfc->rate, IfDp->Name, IfDp->rate, IfDp->bytes);
                }
            }
#endif
        }
    }

    // On Linux get the interface stats via ioctl.
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
    for (GETIFL(IfDp)) {
        if (IfDp->index != (uint8_t)-1) {
            struct sioc_vif_req siocVReq = { IfDp->index, 0, 0, 0, 0 };
            if (ioctl(MROUTERFD, SIOCGETVIFCNT, (void *)&siocVReq, sizeof(siocVReq))) {
                LOG(LOG_WARNING, errno, "BW_CONTROL: ioctl failed.");
                continue;
            }
            uint64_t bytes = (IS_UPSTREAM(IfDp->state) ? siocVReq.ibytes : siocVReq.obytes) - IfDp->bytes;
            IfDp->bytes += bytes;
            IfDp->rate = bytes / CONFIG->bwControlInterval;
            LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to interface %s (%lld B/s), total %lld.",
                               bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
        }
    }
#endif

    // Set next timer;
    *tid = timer_setTimer(TDELAY(CONFIG->bwControlInterval * 10), "Bandwidth Control", (timer_f)bwControl, tid);
}

/**
*  ACL evaluation. Returns whether group/src is allowed on interface.
*  dir: 0 = upstream, 1 = downstream
*/
static bool checkFilters(struct IfDesc *IfDp, int old, int dir, struct sources *dsrc, struct mcTable *mct) {
    // Check if permissions are known, or need to be evaluated against filters for interface.
    if (BIT_TST(dsrc ? (dir ? dsrc->dPBits.e : dsrc->uPBits.e) : (dir ? mct->dPBits.p : mct->uPBits.p), IfDp->index)) {
        if (old) {
            if (IfDp->filCh)
                // When reloading configuration and filters changed, reset eval flag and reevaluate permission.
                dsrc ? (dir ? BIT_CLR(dsrc->dPBits.e, IfDp->index) : BIT_CLR(dsrc->uPBits.e, IfDp->index))
                     : (dir ? BIT_CLR(mct->dPBits.e, IfDp->index)  : BIT_CLR(mct->uPBits.e, IfDp->index));
        } else if (!CONFRELOAD && !SSIGHUP)
            // Reset interface filter change flag is not reloading configuration.
            IfDp->filCh = false;
        // Return whether group is allowed on interface, based on permissions flags.
        return BIT_TST(dsrc ? (dir ? dsrc->dPBits.p : dsrc->uPBits.p) : (dir ? mct->dPBits.p : mct->uPBits.p), IfDp->index);
    }

    LOG(LOG_DEBUG, 0, "checkFilters: Checking Access for %s:%s on %s interface %s.",
                       dsrc ? inetFmt(dsrc->ip, 1) : inetFmt(INADDR_ANY, 1),
                       inetFmt(mct->group, 2), dir ? "downstream" : "upstream", IfDp->Name);
    // Filters are processed top down until a definitive action (BLOCK or ALLOW) is found.
    // The default action when no filter applies is block.
    struct filters *filter;
    for (filter = old ? IfDp->oldconf->filters : IfDp->conf->filters; filter; filter = filter->next) {
        if (filter->action > ALLOW || ( dir && !IS_DOWNSTREAM(filter->dir))
                                   || (!dir && !IS_UPSTREAM(filter->dir)))
             continue;
        if ((! dsrc || dsrc->ip == INADDR_ANY) && (mct->group & filter->dst.mask) == filter->dst.ip) {
            if (!old) {
                dir ? BIT_SET(mct->dPBits.e, IfDp->index) : BIT_SET(mct->uPBits.e, IfDp->index);
                filter->action ? (dir ? BIT_SET(mct->dPBits.p, IfDp->index) : BIT_SET(mct->uPBits.p, IfDp->index))
                               : (dir ? BIT_CLR(mct->dPBits.p, IfDp->index) : BIT_CLR(mct->uPBits.p, IfDp->index));
            }
            return filter->action;
        } else if ((dsrc->ip & filter->src.mask) == filter->src.ip && (mct->group & filter->dst.mask) == filter->dst.ip) {
            if (!old) {
                dir ? BIT_SET(dsrc->dPBits.e, IfDp->index) : BIT_SET(dsrc->uPBits.e, IfDp->index);
                filter->action ? (dir ? BIT_SET(dsrc->dPBits.p, IfDp->index) : BIT_SET(dsrc->uPBits.p, IfDp->index))
                               : (dir ? BIT_CLR(dsrc->dPBits.p, IfDp->index) : BIT_CLR(dsrc->uPBits.p, IfDp->index));
            }
            return filter->action;
        }
    }

    return BLOCK;
}

/**
*   Updates source filter for a group on an upstream interface.
*/
static struct ifMct *updateSourceFilter(struct mcTable *mct, struct IfDesc *IfDp, struct ifMct *imc) {
    uint32_t        nsrcs = 0, *slist = NULL, i;
    struct sources *dsrc;
    if (!BIT_TST(mct->upstrState, IfDp->index)) {
        // Group is not joined on upstream interface, join.
        if (!addGroup(mct, IfDp, 0))
            return imc;
        LOG(LOG_INFO, 0, "updateSourceFilter: Joining group %s upstream on interface %s.", inetFmt(mct->group, 1), IfDp->Name);
        if (!k_joinMcGroup(IfDp, mct->group)) {
            return (delGroup(mct, IfDp, imc, 0));
    } else if (imc)
        // Called from clearGroups when group is no longer allowed on upstream interface, set to IS_IN { }.
        LOG(LOG_INFO, 0, "updateSourceFilter: Leaving group %s upstream on interface %s.", inetFmt(mct->group, 1), IfDp->Name);
        k_setSourceFilter(IfDp, mct->group, MCAST_INCLUDE, 0, NULL);
        return (delGroup(mct, IfDp, imc, 0));
    } else {
        // Build source list for upstream interface.
        // For IN: All active downstream and allowed sources are to be included in the list.
        // For EX: All sources, with timer = 0 on all active interfaces are to be included.
        if (! (slist = malloc((mct->nsrcs & ~0x80000000) * sizeof(uint32_t))))  // Freed by self
            LOG(LOG_ERR, errno, "updateSourceFilter: Out of Memory.");
        for (nsrcs = 0, dsrc = mct->sources; dsrc; dsrc = dsrc->next) {
            if (!mct->mode) {
                if (!dsrc->vifBits || noHash(dsrc->dHostsHT)) {
                        LOG(LOG_INFO, 0, "updateSourceFilter: No downstream hosts %s:%s on %s, not adding to source list.",
                                          inetFmt(dsrc->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
                    continue;
                }
                if (!checkFilters(IfDp, 0, 0, dsrc, mct)) {
                    // Check if source is allowed for group on upstream interface.
                    LOG(LOG_INFO, 0, "updateSourceFilter: Source %s not allowed for group %s on interface %s.",
                                     inetFmt(dsrc->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
                    continue;
                }
            } else {
                if (dsrc->vifBits != mct->vifBits)
                    continue;
                else for (i = 0; i < MAXVIFS && ( !((mct->vifBits >> i) & 0x1) || !mct->age[i] ); i++ );
                if (i >= MAXVIFS)
                    continue;
            }

            LOG(LOG_DEBUG, 0, "updateSourceFilter: Adding %s to source list for %s on %s.",
                               inetFmt(dsrc->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
            slist[nsrcs++] = dsrc->ip;
        }
    }

    // If the group is joined on interface update the source filter. If IN no sources, group is unjoined effectively.
    if (BIT_TST(mct->upstrState, IfDp->index)) {
        if (!mct->mode && !nsrcs) {
            LOG(LOG_INFO, 0, "updateSourceFilter: Leaving group %s upstream on interface %s.", inetFmt(mct->group, 1), IfDp->Name);
            imc = delGroup(mct, IfDp, imc, 0);
        }
        k_setSourceFilter(IfDp, mct->group, mct->mode ? MCAST_EXCLUDE : MCAST_INCLUDE, nsrcs, slist);
    }

    free(slist);  // Alloced by self
    return imc;
}

/**
*   Internal function to send join or leave requests for a specified group upstream...
*   When rebuilding interfaces use old IfDesc Table for leaving groups.
*/
static void sendJoinLeaveUpstream(struct mcTable* mct, int join) {
    struct IfDesc *IfDp = NULL;

    // Only join a group if there are listeners downstream. Only leave a group if joined.
    if (join && mct->vifBits == 0) {
        LOG(LOG_INFO, 0, "No downstream listeners for group %s, not joining.", inetFmt(mct->group, 1));
        return;
    }

    for (GETIFL(IfDp)) {
        // Check if this Request is legit to be forwarded to upstream
        if ((join && !IS_UPSTREAM(IfDp->state)) || (!join && !BIT_TST(mct->upstrState, IfDp->index))) {
            continue;
        } else if (!join && BIT_TST(mct->upstrState, IfDp->index)) {
            LOG(LOG_INFO, 0, "Leaving group %s upstream on interface %s", inetFmt(mct->group, 1), IfDp->Name);
            k_leaveMcGroup(IfDp, mct->group);
            delGroup(mct, IfDp, NULL, 0);
        } else if (CONFIG->bwControlInterval && IfDp->conf->ratelimit > 0 && IfDp->rate > IfDp->conf->ratelimit) {
            LOG(LOG_NOTICE, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.",
                              IfDp->Name, IfDp->rate, IfDp->conf->ratelimit, inetFmt(mct->group, 1));
        } else if (join)
            updateSourceFilter(mct, IfDp, NULL);
    }
}

/**
*   Clears / Updates all groups and routing table, and sends Joins / Leaves upstream.
*   If called with NULL pointer all groups and routes are removed.
*/
void clearGroups(void *Dp) {
    struct ifMct      *imc;
    struct mcTable    *mct;
    struct IfDesc     *IfDp     = Dp != CONFIG && Dp != getConfig ? Dp : NULL;
    register uint8_t   oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);

    if (Dp == CONFIG || Dp == getConfig || (!IS_UPSTREAM(oldstate) && IS_UPSTREAM(newstate))) {
        GETMRT(mct) {
            if (Dp == CONFIG) {
                struct sources **src;
                // Quickleave was enabled or disabled, or hastable size was changed.
                // Reallocate appriopriate amount of memory and reinitialize downstreahosts tracking.
                for (src = &(mct->sources); *src; src = &(*src)->next) {
                    if (! (*src = realloc(*src, sizeof(struct sources) + CONFIG->dHostsHTSize)))
                        LOG(LOG_ERR, errno, "clearGroups: Out of memory.");
                    if (CONFIG->fastUpstreamLeave)
                        memset((*src)->dHostsHT, 0, CONFIG->dHostsHTSize);
                }
                if (! (mct = realloc(mct, sizeof(struct mcTable) + CONFIG->dHostsHTSize)))
                    LOG(LOG_ERR, errno, "clearGroups: Out of memory.");
                if (CONFIG->fastUpstreamLeave)
                    memset(mct->dHostsHT, 0, CONFIG->dHostsHTSize);
                if (! mct->prev)
                    MCT[iz] = mct;
                else
                    mct->prev->next = mct;
                if (mct->next)
                    mct->next->prev = mct;
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
            } else if (Dp == getConfig) {
                // BW control interval was changed. Reinitialize all bw_upcalls.
                struct mfc *mfc;
                for (mfc = mct->mfc; mfc; mfc = mfc->next) {
                    k_deleteUpcalls(mfc->src->ip, mct->group);
                    activateRoute(NULL, mfc->dsrc, 0, 0, true);
                }
#endif
            } else
                // New upstream interface join all relevant groups and sources.
                updateSourceFilter(mct, IfDp, NULL);
        }
        return;
    }

    // Upstream interface transition.
    if (IS_UPSTREAM(newstate) || IS_UPSTREAM(oldstate)) {
        for (imc = IfDp->uMct; imc; imc = imc ? imc->next : IfDp->uMct) {
            if ((CONFRELOAD || SSIGHUP) && IS_UPSTREAM(newstate) && IS_UPSTREAM(oldstate)) {
                // Clear uptsream perm bits for all sources, they will be reevaluated next source filter update.
                for (struct sources *dsrc = imc->mct->sources; dsrc; BIT_CLR(dsrc->uPBits.e, IfDp->index), dsrc = dsrc->next);
                if (checkFilters(IfDp, 1, 0, NULL, imc->mct)) {
                    if (!checkFilters(IfDp, 0, 0, NULL, imc->mct) && imc->mct->vifBits) {
                        // Group is no longer allowed. Leave.
                        LOG(LOG_NOTICE, 0, "clearGroups: Leaving group %s on %s, no longer allowed.",
                                            inetFmt(imc->mct->group, 1), IfDp->Name);
                        imc = updateSourceFilter(imc->mct, IfDp, imc);
                    }
                }
            } else if (!IS_UPSTREAM(newstate) && BIT_TST(imc->mct->upstrState, IfDp->index)) {
                // Transition from upstream to downstream or disabled. Leave group.
                LOG(LOG_INFO, 0, "clearGroups: Leaving group %s on %s, no longer upstream.",
                                  inetFmt(imc->mct->group, 1), IfDp->Name);
                k_leaveMcGroup(IfDp, imc->mct->group);
                imc = delGroup(imc->mct, IfDp, imc, 0);
            }
        }
        for (imc = IfDp->gMct; imc; imc = imc ? imc->next : IfDp->gMct)
            if (!IS_UPSTREAM(newstate) && BIT_TST(imc->mct->gcBits, IfDp->index))
                imc = delGroup(imc->mct, IfDp, imc, 0);
    }

    // Downstream interface transition.
    for (imc = IfDp->dMct; imc; imc = imc ? imc->next : IfDp->dMct) {
        // Clear upstream permissions, access will be reevaluated next time group is requested downstream.
        if (!IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate)) {
            // Transition to disabled / upstream, remove from group.
            LOG(LOG_INFO, 0, "clearGroups: Vif %d - %s no longer downstream, removing group %s.",
                              IfDp->index, IfDp->Name, inetFmt(imc->mct->group, 1));
            imc = delGroup(imc->mct, IfDp, imc, 1);
        } else if (IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate) && (CONFRELOAD || SSIGHUP)) {
            if (checkFilters(IfDp, 1, 1, NULL, imc->mct)) {
                // Check against bl / wl changes on config reload / sighup.
                if (!checkFilters(IfDp, 0, 1, NULL, imc->mct)) {
                    LOG(LOG_NOTICE, 0, "clearGroups: Group %s no longer allowed on Vif %d - %s.",
                                        inetFmt(imc->mct->group, 1), IfDp->index, IfDp->Name);
                    imc = delGroup(imc->mct, IfDp, imc, 1);
                }
            }
        }
    }

    if (! MCT)
        LOG(LOG_INFO, 0, "clearGroups: Multicast table is empty.");
    else
        logRouteTable("Clear Groups", 1, NULL, 0);
}

/**
*   Adds a specified group to the MCT or updates if it exists already.
*   Function will implement group table and proces group reports per RFC.
*   See paragraph 6.4 of RFC3376 for more information.
*   Not 100% RFC compliant, RFC specifies to set sources to group timer in certain cases.
*   We do not do this, as it would require keeping absolute timers for aging.
*   We keep relative timers, based on the time queries were sent.
*   There is a corner case where upon receiving respectiver report the absolute timer for the source
*   is lower than last member query time. In that case the source will be aged slightly slower than it should.
*   Unless of course large last member intervals are configured, but that remains user discretion.
*
*   The incoming array of sources is sorted, so that we can easily keep the sources list
*   in the same order. It allows for fast linear evaluation of both lists.
*   The logic may be complex sometimes, but it is just doing list management based upon the rules
*   in RFC3376 p6.4.
*/
void updateGroup(struct IfDesc *IfDp, uint32_t src, struct igmpv3_grec *grec) {
    uint16_t  i = 0, type    = grecType(grec), nsrcs = grecNscrs(grec);
    uint32_t         group   = grec->grec_mca.s_addr,
                     srcHash = murmurhash3(src) % (CONFIG->dHostsHTSize);
    struct sources  *dsrc    = NULL, *tsrc = NULL;
    struct qlst     *qlst, *qlst1;
    struct mcTable  *mct;

    // Return if request is bogus (BLOCK / ALLOW / IS_IN with no sources, or no group when BLOCK or TO_IN with no sources).
    if ((nsrcs == 0 && (type == IGMPV3_ALLOW_NEW_SOURCES || type == IGMPV3_MODE_IS_INCLUDE || type == IGMPV3_BLOCK_OLD_SOURCES))
       || ! (mct = findGroup(group, !((type == IGMPV3_CHANGE_TO_INCLUDE && nsrcs == 0) || type == IGMPV3_BLOCK_OLD_SOURCES))))
        return;

    // Initialze the query list and sort array of sources in group report..
    if (! (qlst = malloc(sizeof(struct qlst))))  // Freed by startQuery() or delQuery().
        LOG(LOG_ERR, errno, "updateGroup: Out of Memory.");
    *qlst = (struct qlst){ NULL, NULL, mct, IfDp, 0, 0, IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount, 0, 0 };
    nsrcs = sortArr((uint32_t *)grec->grec_src, nsrcs);
    LOG(LOG_DEBUG, 0, "updateGroup: Processing %s with %d sources for %s on %s.",
                       grecKind(type), nsrcs, inetFmt(group, 1), IfDp->Name);

    // Toggle compatibility modes if older version reports are received.
    if (grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT) {
        LOG(LOG_INFO, 0, "Detected v1 host on %s. Setting compatibility mode for %s.", IfDp->Name, inetFmt(group, 1));
        BIT_SET(mct->v1Bits, IfDp->index);
        mct->v1Age[IfDp->index] = IfDp->querier.qrv;
    } else if (grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT || grec->grec_type == IGMP_V2_LEAVE_GROUP) {
        LOG(LOG_INFO, 0, "Detected v2 host on %s. Setting compatibility mode for %s.", IfDp->Name, inetFmt(group, 1));
        BIT_SET(mct->v2Bits, IfDp->index);
        mct->v2Age[IfDp->index] = IfDp->querier.qrv;
    }

    bool join = true;
    switch (type) {
    case IGMPV3_CHANGE_TO_EXCLUDE:
        if ((BIT_TST(mct->v1Bits, IfDp->index) || BIT_TST(mct->v2Bits, IfDp->index || IfDp->querier.ver < 3)) && nsrcs > 0) {
            LOG(LOG_INFO, 0, "updateGroup: Ignoring %d sources for %s on %s, v1 or v2 host/querier present.",
                              nsrcs, inetFmt(group, 1), IfDp->Name);
            nsrcs = 0;
        } /* FALLTHRU */
    case IGMPV3_MODE_IS_EXCLUDE:
        if (!addGroup(mct, IfDp, 1))
            break;
        mct->age[IfDp->index] = IfDp->querier.qrv;  // Group timer = GMI
        BIT_CLR(mct->lmBits, IfDp->index);
        setHash(mct->dHostsHT, srcHash);

        qlst->type = 4;
        for (i = 0, dsrc = mct->sources; dsrc || i < nsrcs; i++) {
            if (dsrc && (i >= nsrcs || dsrc->ip < grec->grec_src[i].s_addr)) do {
                // IN: Delete (A-B) / EX: Delete (X - A), Delete (Y - A)
                if (IS_SET(dsrc, IfDp))
                    dsrc = delSrc(dsrc, IfDp, srcHash);
                else
                    dsrc = dsrc->next;
                } while (dsrc && (i >= nsrcs || dsrc->ip < grec->grec_src[i].s_addr));
            if (i < nsrcs && (! (tsrc = dsrc) || tsrc->ip >= grec->grec_src[i].s_addr)) {
                if ((dsrc = addSrc(IfDp, mct, grec->grec_src[i].s_addr, false, tsrc))) {
                    // IN: (B-A) = 0 / EX: (A - X - Y) = Group Timer?
                    BIT_SET(dsrc->vifBits, IfDp->index);
                }
                if (type == IGMPV3_CHANGE_TO_EXCLUDE &&
                         (   (    dsrc && (! tsrc || tsrc->ip > grec->grec_src[i].s_addr) && IS_EX(mct, IfDp))
                          || (   (tsrc && tsrc->ip == grec->grec_src[i].s_addr) && ((IS_IN(mct, IfDp) && IS_SET(dsrc, IfDp))
                              || (IS_EX(mct, IfDp) && (NOT_SET(dsrc, IfDp) || dsrc->age[IfDp->index] > 0)))))) {
                    // IN: Send Q(G, A*B) / EX: Send Q(G, A-Y)
                    qlst = addSrcToQlst(dsrc, IfDp, qlst, srcHash);
                }
                dsrc = dsrc ? dsrc->next : tsrc;
            }
        }
        BIT_SET(mct->mode, IfDp->index);
        break;

    case IGMPV3_CHANGE_TO_INCLUDE:
        if (BIT_TST(mct->v1Bits, IfDp->index) || IfDp->querier.ver == 1) {
            LOG(LOG_INFO, 0, "updateGroup: Ignoring TO_IN for %s on %s, v1 host/querier present.", inetFmt(group, 1), IfDp->Name);
            break;
        }
        if (nsrcs == 0) {
            clearHash(mct->dHostsHT, srcHash);
            if (!(join = !noHash(mct->dHostsHT)))
                LOG(LOG_INFO, 0, "updateGroup: Quickleave enabled, %s was the last downstream host, leaving group %s now",
                                  inetFmt(src, 1), inetFmt(group, 2));
        }
        if (IS_EX(mct, IfDp) && !BIT_TST(mct->lmBits, IfDp->index) && checkFilters(IfDp, 0, 1, NULL, mct)) {
            if (! (qlst1 = malloc(sizeof(struct qlst))))  // // Freed by startQuery() or delQuery().
                LOG(LOG_ERR, errno, "updateGroup: Out of Memory.");
            *qlst1 = (struct qlst){ NULL, NULL, mct, IfDp, 0, 0x2, IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount, 0, 0 };
            startQuery(IfDp, qlst1);
        }  /* FALLTHRU */
    case IGMPV3_ALLOW_NEW_SOURCES:
    case IGMPV3_MODE_IS_INCLUDE:
        if (nsrcs > 0 && !addGroup(mct, IfDp, 1))
            break;

        qlst->type = 0x4;
        for (i = 0, dsrc = mct->sources; dsrc || i < nsrcs; dsrc = dsrc ? dsrc->next : dsrc) {
            if (dsrc && (i >= nsrcs || dsrc->ip < grec->grec_src[i].s_addr)) {
                if (type == IGMPV3_CHANGE_TO_INCLUDE && IS_SET(dsrc, IfDp) && (IS_IN(mct, IfDp) || dsrc->age[IfDp->index] > 0))
                    // EX: Send Q(G, X-A) IN: Send Q(G, A-B)
                    qlst = addSrcToQlst(dsrc, IfDp, qlst, (uint32_t)-1);
            } else if (i < nsrcs && (! (tsrc = dsrc) || dsrc->ip >= grec->grec_src[i].s_addr)) do {
                if ((dsrc = addSrc(IfDp, mct, grec->grec_src[i].s_addr, true, tsrc))) {
                    // IN (B) = GMI, (A + B) / EX: (A) = GMI, (X + A) (Y - A)
                    BIT_SET(dsrc->vifBits, IfDp->index);
                    BIT_CLR(dsrc->lmBits, IfDp->index);
                    dsrc->age[IfDp->index] = IfDp->querier.qrv;
                    setHash(dsrc->dHostsHT, srcHash);
                } else
                    dsrc = tsrc;
                dsrc = ! tsrc && dsrc ? dsrc->next : dsrc;
            } while (++i < nsrcs && (! tsrc || tsrc->ip >= grec->grec_src[i].s_addr));
        }
        break;

    case IGMPV3_BLOCK_OLD_SOURCES:
        if (!IS_SET(mct, IfDp) || BIT_TST(mct->v1Bits, IfDp->index) ||
             BIT_TST(mct->v2Bits, IfDp->index) || IfDp->querier.ver < 3) {
            LOG(LOG_INFO, 0, "updateGroup: Ignoring BLOCK for %s on %s, %s.", inetFmt(group, 1), IfDp->Name,
                              !IS_SET(mct, IfDp) ? "not active" : "v1 or v2 host/querier present");
            break;
        }

        qlst->type = 4, i = 0;
        dsrc = mct->sources;
        while (i < nsrcs && (IS_EX(mct, IfDp) || dsrc)) {
            // IN: Send Q(G,A*B) / EX: Send Q(G,A-Y), (A-X-Y) = Group Timer?
            if ((dsrc && dsrc->ip == grec->grec_src[i].s_addr && IS_SET(dsrc, IfDp) &&
                         (IS_IN(mct, IfDp) || dsrc->age[IfDp->index] > 0 || NOT_SET(dsrc, IfDp)))
                      || (IS_EX(mct, IfDp) && (! (tsrc = dsrc) || dsrc->ip > grec->grec_src[i].s_addr))) {
                if ((dsrc = addSrc(IfDp, mct, grec->grec_src[i].s_addr, false, dsrc)))
                    qlst = addSrcToQlst(dsrc, IfDp, qlst, srcHash);
                else
                    dsrc = tsrc;
                i++;
            }
            for (; dsrc && i < nsrcs && (dsrc->ip < grec->grec_src[i].s_addr || NOT_SET(dsrc, IfDp)); dsrc = dsrc->next);
            if (dsrc && i < nsrcs && (    NOT_SET(dsrc, IfDp) || dsrc->ip > grec->grec_src[i].s_addr
                                      || (IS_EX(mct, IfDp) && dsrc->ip == grec->grec_src[i].s_addr)))
                i++;
        }
    }

    startQuery(IfDp, qlst);
    if (!mct->mode && !mct->nsrcs)
        // Delete group if it is INCLUDE no sources.
        delGroup(mct, IfDp, NULL, 1);
    else {
        // Update upstream and kernel.
        sendJoinLeaveUpstream(mct, join);
        for (struct mfc *mfc = mct->mfc; mfc; activateRoute(NULL, mfc->src, 0, 0, true), mfc = mfc->next);
    }

    LOG(LOG_DEBUG, 0, "Updated group entry for %s on VIF #%d", inetFmt(group, 1), IfDp->index);
    logRouteTable("Update Group", 1, NULL, 0);
}

/**
*   Switches a group from exclude to include mode.
*   Returns false if group IS_IN no sources (can be deleted by caller).
*/
static void toInclude(struct mcTable *mct, struct IfDesc *IfDp) {
    struct sources *dsrc = mct->sources;

    LOG(LOG_INFO, 0, "TO_IN: Switching mode for %s to include on %s.", inetFmt(mct->group, 1), IfDp->Name);
    BIT_CLR(mct->mode, IfDp->index);
    BIT_CLR(mct->v2Bits, IfDp->index);
    mct->age[IfDp->index] = mct->v2Age[IfDp->index] = 0;
    while (dsrc) {
         if (IS_SET(dsrc, IfDp) && dsrc->age[IfDp->index] == 0) {
             LOG(LOG_DEBUG, 0, "TO_IN: Removed inactive source %s from group %s.", inetFmt(dsrc->ip, 1), inetFmt(mct->group, 2));
             BIT_CLR(dsrc->lmBits, IfDp->index);
             BIT_CLR(dsrc->qryBits, IfDp->index);
             dsrc = delSrc(dsrc, IfDp, (uint32_t)-1);
         } else
             dsrc = dsrc->next;
    }
}

/**
*   Adds a source to list of sources to query. Toggles appropriate flags and adds to qlst array.
*/
static inline struct qlst *addSrcToQlst(struct sources *dsrc, struct IfDesc *IfDp, struct qlst *qlst, uint32_t srcHash) {
    uint16_t nsrcs = qlst->nsrcs;

    // Add source to query list if required, prevent duplicates.
    if ((BIT_TST(qlst->type, 5) || IQUERY) && !BIT_TST(dsrc->lmBits, IfDp->index)
                                           && (!nsrcs || qlst->src[qlst->nsrcs - 1]->ip != dsrc->ip)) {
        // In case source is in running query, remove it there and add to current list.
        if (BIT_TST(dsrc->qryBits, IfDp->index))
            delQuery(IfDp, NULL, NULL, dsrc, 0);

        // Add to source to the query list. Allocate memory per 32 sources.
        LOG(LOG_DEBUG, 0, "addSrcToQlst: Adding source %s to query list for %s (%d).",
                          inetFmt(dsrc->ip, 1), inetFmt(dsrc->mct->group, 2), nsrcs + 1);
        if ((nsrcs & 0x1F) == 0 && ! (qlst = realloc(qlst, sizeof(struct qlst) + ((nsrcs >> 5) + 1) * 0x20 * sizeof(void *))))
            LOG(LOG_ERR, errno, "addSrcToQlst; Out of Memory.");  // Freed by startQuery() or delQuery().
        if (srcHash != (uint32_t)-1)
            clearHash(dsrc->dHostsHT, srcHash);
        BIT_SET(dsrc->vifBits, IfDp->index);
        BIT_SET(dsrc->qryBits, IfDp->index);
        BIT_SET(dsrc->lmBits, IfDp->index);
        dsrc->age[IfDp->index] = qlst->misc;
        qlst->src[qlst->nsrcs++] = dsrc;
    }
    return qlst;
}

/**
*   Process a group specific query received from other querier.
*/
void processGroupQuery(struct IfDesc *IfDp, struct igmpv3_query *query, uint8_t ver) {
    struct mcTable  *mct = findGroup(query->igmp_group.s_addr, false);
    uint16_t         nsrcs = ver == 2 ? 0 : ntohs(query->igmp_nsrcs);
    struct qlst     *qlst;
    struct sources  *dsrc;

    // If no group found for query, or not active on interface return.
    if (! mct || !IS_SET(mct, IfDp))
        return;

    // Initialize query list and sort array of sources in query.
    if (! (qlst = malloc(sizeof(struct qlst) + nsrcs * sizeof(void *))))  // Freed by startQuery() or delQuery().
        LOG(LOG_ERR, errno, "processGroupQuery: Out of Memory.");
    *qlst = (struct qlst){ NULL, NULL, mct, IfDp, 0, 0,
                           query->igmp_code, ver == 3 ? query->igmp_misc & ~0x8 : IfDp->conf->qry.lmCount, 0, 0 };
    nsrcs = sortArr((uint32_t *)query->igmp_src, nsrcs);

    if (nsrcs == 0) {
        LOG(LOG_DEBUG, 0, "processGroupQuery: Group specific query for %s on %s.", inetFmt(mct->group, 1), IfDp->Name);
        qlst->type = 0x10;
    } else {
        LOG(LOG_DEBUG, 0, "processGroupQuery: Group group and source specific query for %s with %d sources on %s.",
                           inetFmt(mct->group, 1), nsrcs, IfDp->Name);
        qlst->type = 0x20;
        uint16_t i;
        for (dsrc = mct->sources, i = 0; dsrc && i < nsrcs; i++, dsrc = dsrc ? dsrc->next : dsrc) {
            if (dsrc->ip > query->igmp_src[i].s_addr)
                for (; i < nsrcs && dsrc->ip > query->igmp_src[i].s_addr; i++);
            if (dsrc->ip == query->igmp_src[i].s_addr)
                addSrcToQlst(dsrc, IfDp, qlst, (uint32_t)-1);
            for(; dsrc && dsrc->next && dsrc->next->ip < query->igmp_src[i].s_addr; dsrc = dsrc->next);
        }
    }
    startQuery(IfDp, qlst);
}

/**
*   Builds a group (and source) specific query and start last member process.
*   Will use an igmpv3_query struct as it suits well for this purpose.
*   Hacky Tacky Piggy Backy interface name after sources list.
*   Set appropriate flags for query, depending on type, copy sources from qlst to array.
*/
static inline void startQuery(struct IfDesc *IfDp, struct qlst *qlst) {
    // Check sanity of query list. Remove list if not ok (no sources for gssq, not querier on interface).
    if (!qlst->type || ((BIT_TST(qlst->type, 2) || BIT_TST(qlst->type, 3) || BIT_TST(qlst->type, 5)) && qlst->nsrcs == 0)
                    || ( !BIT_TST(qlst->type, 4) && !BIT_TST(qlst->type, 5) && !IQUERY)) {
        free(qlst);  // Alloced by updateGroup(), addSrcToQlst() or processGroupQuery().
        return;
    }

    // Check if we should take over for a running GSQ.
    if ((BIT_TST(qlst->type, 1) || BIT_TST(qlst->type, 4)) && BIT_TST(qlst->mct->qryBits, IfDp->index))
        delQuery(IfDp, NULL, qlst->mct, NULL, qlst->type);

    // Allocate and assign new querier.
    if (qL) {
        qlst->next = qL;
        qL->prev = qlst;
    }
    qL = qlst;
    qC++;

    if (qlst->nsrcs == 0) {
        LOG(LOG_INFO, 0, "startQuery #%d: Querying group %s on %s.", qC, inetFmt(qlst->mct->group, 1), IfDp->Name);
        BIT_SET(qlst->mct->qryBits, IfDp->index);
        BIT_SET(qlst->mct->lmBits, IfDp->index);
        qlst->mct->age[IfDp->index] = qlst->misc;
    } else
        LOG(LOG_INFO, 0, "startQuery #%d: Querying %d sources for %s on %s.",
                         qC, qlst->nsrcs, inetFmt(qlst->mct->group, 1), IfDp->Name);
    groupSpecificQuery(qlst);
}

/**
*   Sends a group specific member report query until the group times out.
*   bit 0 - Router Supress flag
*   bit 1 - Group Specific Query
*   bit 2 - Group and Source Specific query
*   bit 3 - Garbage Collection
*   bit 4 - Group Specific Query (Other querier)
*   bit 5 - Group and Source Specific query (Other querier)
*/
static void groupSpecificQuery(struct qlst *qlst) {
    struct igmpv3_query *query = NULL, *query1 = NULL, *query2 = NULL;
    uint32_t            i = 0, nsrcs = qlst->nsrcs, size = sizeof(struct igmpv3_query) + nsrcs * sizeof(struct in_addr);

    // Do aging upon reentry.
    if (qlst->cnt > 0) {
        if (BIT_TST(qlst->type, 1) || BIT_TST(qlst->type, 4)) {
            // Age group in case of GSQ.
            if (!BIT_TST(qlst->mct->lmBits, qlst->IfDp->index)) {
                LOG(LOG_INFO, 0, "GSQ: %s no longer in last member state on %s.", inetFmt(qlst->mct->group, 1), qlst->IfDp->Name);
                BIT_SET(qlst->type, 0);  // Suppress router processing flag for next query.
                if (BIT_TST(qlst->type, 4))
                    // If aging for other querier, we're done.
                    qlst->cnt = qlst->misc;
            } else if (--qlst->mct->age[qlst->IfDp->index] == 0) {
                // Group in exclude mode has aged, switch to include.
                LOG(LOG_DEBUG, 0, "GSQ: Switch group %s to inlcude on %s after querying.",
                                  inetFmt(qlst->mct->group, 1), qlst->IfDp->Name);
                qlst->cnt = qlst->misc;  // Make sure we're done.
                if (!BIT_TST(qlst->mct->v1Bits, qlst->IfDp->index))
                    // RFC says v2 groups should not switch and age normally, but v2 hosts must respond to query, so should be safe.
                    toInclude(qlst->mct, qlst->IfDp);
            }

        } else if (BIT_TST(qlst->type, 2) || BIT_TST(qlst->type, 5)) {
            // Age sources in case of GSSQ. Create two queries (1 - sources still last member 2 - active source).
            if (! (query1 = malloc(size)) || ! (query2 = malloc(size)))  // Freed by self.
                LOG(LOG_ERR, errno, "GSQ: Out of Memory.");
            *query1 = (struct igmpv3_query){ qlst->type      , qlst->code, 0, {qlst->mct->group}, qlst->misc, 0, 0 };
            *query2 = (struct igmpv3_query){ qlst->type | 0x1, qlst->code, 0, {qlst->mct->group}, qlst->misc, 0, 0 };
            while (i < qlst->nsrcs) {
                if (!BIT_SET(qlst->src[i]->lmBits, qlst->IfDp->index) || NOT_SET(qlst->src[i], qlst->IfDp)) {
                    // Source no longer in last member state.
                    LOG(LOG_INFO, 0, "GSQ: Source %s for group %s no longer in last member state on %s.",
                                      inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->mct->group, 2), qlst->IfDp->Name);
                    query2->igmp_src[query2->igmp_nsrcs++].s_addr = qlst->src[i++]->ip;
                } else if (--qlst->src[i]->age[qlst->IfDp->index] == 0) {
                    // Source expired. Remove from query list.
                    BIT_CLR(qlst->src[i]->qryBits, qlst->IfDp->index);
                    BIT_CLR(qlst->src[i]->lmBits, qlst->IfDp->index);
                    if (IS_IN(qlst->mct, qlst->IfDp)) {
                        // Aged source in include mode should be removed.
                        LOG(LOG_INFO, 0, "GSQ: Removed inactive source %s from group %s on %s.",
                                          inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->mct->group, 2), qlst->IfDp->Name);
                        delSrc(qlst->src[i], qlst->IfDp, (uint32_t)-1);
                    } else
                        // In exclude mode sources should be kept.
                        LOG(LOG_INFO, 0, "GSQ: Source %s from group %s on %s expired.",
                                          inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->mct->group, 2), qlst->IfDp->Name);
                    qlst->src[i] = qlst->src[--qlst->nsrcs];
                } else
                    // Source still in last member state, add to  query.
                    query1->igmp_src[query1->igmp_nsrcs++].s_addr = qlst->src[i++]->ip;
            }
            if (BIT_TST(qlst->type, 5) && !qlst->nsrcs)
                // If aging for other querier and no sources left to age, we're done.
                qlst->cnt = qlst->misc;
        }
    }

    if (qlst->cnt++ < qlst->misc) {
        // Send a query if not aging for other querier.
        if (!BIT_TST(qlst->type, 4) && !BIT_TST(qlst->type, 5)) {
            if (qlst->cnt == 1 || BIT_TST(qlst->type, 1)) {
                // Use qlst in case of group query, or first group and source query.
                if (! (query = malloc(sizeof(struct igmpv3_query) + qlst->nsrcs * sizeof(struct in_addr))))
                    LOG(LOG_ERR, errno, "GSQ: Out of Memory.");
                *query = (struct igmpv3_query){ qlst->type, qlst->code, 0, {qlst->mct->group}, qlst->misc, 0, qlst->nsrcs };
                if (BIT_TST(qlst->type, 2) || BIT_TST(qlst->type, 3))
                    for (uint16_t i = 0; i < qlst->nsrcs; query->igmp_src[i].s_addr = qlst->src[i]->ip, i++);
                sendIgmp(qlst->IfDp, query);
                free(query);
            } else {
                // Send two queries, with active and last member sources.
                if (query1 && query1->igmp_nsrcs)
                    sendIgmp(qlst->IfDp, query1);
                if (query2 && query2->igmp_nsrcs)
                    sendIgmp(qlst->IfDp, query2);
            }
        }
        // Set timer for next round if there is still aging to do.
        if (qlst->misc == qlst->cnt && (  (BIT_TST(qlst->type, 1) && !BIT_TST(qlst->mct->lmBits, qlst->IfDp->index))
                                       || (BIT_TST(qlst->type, 4) && !qlst->nsrcs)))
            LOG(LOG_INFO, 0, "GSQ: done querying %s/%d on %s.", inetFmt(qlst->mct->group, 1), nsrcs, qlst->IfDp->Name);
        else {
            sprintf(msg, "GSQ (%s): %15s/%u", qlst->IfDp->Name, inetFmt(qlst->mct->group, 1), qlst->nsrcs);
            uint32_t timeout = BIT_TST(qlst->type, 4) || BIT_TST(qlst->type, 5) ? qlst->code
                             : qlst->IfDp->querier.ver == 3 ? getIgmpExp(qlst->IfDp->conf->qry.lmInterval, 0)
                             : qlst->IfDp->conf->qry.lmInterval;
            qlst->tid = timer_setTimer(TDELAY(timeout), msg, (timer_f)groupSpecificQuery, qlst);
        }
    } else if (qlst->cnt >= qlst->misc) {
        // Done querying. Remove current querier from list.
        LOG(LOG_INFO, 0, "GSQ: done querying %s/%d on %s.", inetFmt(qlst->mct->group, 1), nsrcs, qlst->IfDp->Name);
        if (!qlst->mct->mode && !qlst->mct->nsrcs)
            // Delete the group if IS_IN no sources, or update upstream status.
            delGroup(qlst->mct, qlst->IfDp, NULL, 1);
        else {
            sendJoinLeaveUpstream(qlst->mct, 1);
            for (struct mfc *mfc = qlst->mct->mfc; mfc; activateRoute(NULL, mfc->src, 0, 0, true), mfc = mfc->next);
            delQuery(qlst->IfDp, qlst, NULL, NULL, 0);
        }
    }

    free(query1);  // Alloced by self.
    free(query2);  // Alloced by self.
}

/**
*   Removes all active queriers specified by parameters.
*/
void delQuery(struct IfDesc *IfDp, void *qry, void *mct, void *src, uint8_t type) {
    struct qlst     *ql   = qry ? qry : qL;
    struct mcTable  *_mct = qry ? ql->mct : mct;
    struct sources  *dsrc = src;
    LOG(LOG_INFO, 0, "delQry: Removing quer%s%s%s%s on %s.", qry || dsrc ? "y" : "ies",
                      _mct || dsrc ? " for " : "", dsrc ? inetFmt(dsrc->ip, 1) : "",
                      _mct ? inetFmt(_mct->group, 2) : "", IfDp->Name);
    while (ql) {
        struct qlst *nql = qry ? NULL : ql->next;
        // Find all queriers for interface, group and type.
        if (ql->IfDp == IfDp && ((! _mct || ql->mct == _mct) && (!type || type == (ql->type & ~0x1)))) {
            if (dsrc) {
                // Find and remove source from all queries.
                uint16_t i;
                for (i = 0; ql && i < ql->nsrcs && ql->src[i] != dsrc; i++);
                if (ql && i < ql->nsrcs) {
                    LOG(LOG_NOTICE, 0, "Existing query for source %s in group %s on %s.",
                                        inetFmt(ql->src[i]->ip, 1), inetFmt(ql->mct->group, 2), ql->IfDp->Name);
                    ql->src[i] = ql->src[--ql->nsrcs];
                }
            } else if (BIT_TST(ql->type, 1) || BIT_TST(ql->type, 4)) {
                // Clear last member and query bits for group.
                BIT_CLR(_mct->lmBits, IfDp->index);
                BIT_CLR(_mct->qryBits, IfDp->index);
            } else
                // Clear last member and query bits for sources.
                for (uint16_t i = 0; i < ql->nsrcs; BIT_CLR(ql->src[i]->lmBits, IfDp->index),
                                                    BIT_CLR(ql->src[i]->qryBits, IfDp->index), i++);
            // Unlink from query list and free qlst.
            if (! dsrc || (!ql->nsrcs && (BIT_TST(ql->type, 2) || BIT_TST(ql->type,5)))) {
                if (! qry)
                    timer_clearTimer(ql->tid);
                if (ql->next)
                    ql->next->prev = ql->prev;
                if (ql->prev)
                    ql->prev->next = ql->next;
                if (qL == ql)
                    qL = ql->next;
                qC--;
                free(ql);  // Alloced by updateGroup(), addSrcToQlst() or processGroupQuery()
            }
        }
        ql = nql;
    }
}

/**
*   Activates, updates or removes a route in the kernel MFC.
*   If called from acceptRouteActivation a new MFC route will be created.
*   If called with pointer to source and activate the route will be updated.
*   If called with pointer to source and !activate the route will be removed.
*/
inline void activateRoute(struct IfDesc *IfDp, void *src, register uint32_t ip, register uint32_t group, bool activate) {
    struct sources  *dsrc = src;
    struct mcTable  *mct  = dsrc ? dsrc->mct : findGroup(group, true);

    if (activate) {
        // Garbage route. Sender for group which was never requested downstream.
        if (!mct->vifBits && !BIT_TST(mct->gcBits, IfDp->index)) {
            addGroup(mct, IfDp, 0);
            BIT_SET(mct->gcBits, IfDp->index);
        }

        // Find source or create source in group when new should be created.
        if (! dsrc) {
            for (dsrc = mct->sources; dsrc && !(dsrc->ip >= ip); dsrc = dsrc->next);
            if (! dsrc || dsrc->ip > ip) {
                if (! (dsrc = addSrc(IfDp, mct, ip, false, dsrc))) {
                    LOG(LOG_WARNING, 0, "Unable to activate route: %s to %s on %s. Cannot create source.",
                                        inetFmt(ip, 1), inetFmt(group, 2), IfDp->Name);
                    return;
                } else
                    mct->nsrcs--;  // Source created here does not count as requested source.
            }
        }

        // Create and initialize an upstream source for new sender.
        if (! dsrc->mfc) {
            struct mfc *nmfc;
            if (! (dsrc->mfc = nmfc = malloc(sizeof(struct mfc))))
                LOG(LOG_ERR, errno, "activateRoute: Out of Memory!");  // Freed by Self.
            *nmfc = (struct mfc){ NULL, NULL, {0, 0}, dsrc, IfDp, 0, 0 };
            clock_gettime(CLOCK_REALTIME, &nmfc->stamp);
            dsrc->mfc = nmfc;
            if (mct->mfc) {
                nmfc->next = mct->mfc;
                mct->mfc->prev = nmfc;
            }
            mct->mfc = nmfc;
        }
    }

    LOG(LOG_INFO, 0, "activateRoute: %s for src: %s to group: %s on VIF %s (%d)", activate ? "Activation" : "Deactivation", 
                      inetFmt(dsrc->mct->group, 1), inetFmt(dsrc->ip, 2), dsrc->mfc->IfDp->Name, dsrc->mfc->IfDp->index);
    LOG(LOG_DEBUG, 0, "Vif bits: 0x%08x", dsrc->mct->vifBits);

    if (activate) {
        // Install or update kernel MFC. See RFC 3376: 6.3 IGMPv3 Source-Specific Forwarding Rules.
        uint8_t ttlVc[MAXVIFS] = {0};
        for (GETIFL(IfDp)) {
            if (IS_DOWNSTREAM(IfDp->state) && IS_SET(mct, IfDp) &&
               (  (IS_IN(mct, IfDp) && !noHash(dsrc->dHostsHT) && IS_SET(dsrc, IfDp)
                                       && dsrc->age[IfDp->index] > 0)
               || (IS_EX(mct, IfDp) && !noHash(mct->dHostsHT)
                                       && (!IS_SET(dsrc, IfDp) || dsrc->age[IfDp->index] > 0)))) {
                LOG(LOG_DEBUG, 0, "Setting TTL for Vif %d to %d", IfDp->index, IfDp->conf->threshold);
                ttlVc[IfDp->index] = IfDp->conf->threshold;
            }
        }
        k_addMRoute(ip, mct->group, dsrc->mfc->IfDp->index, ttlVc);
    } else {
        // Remove kernel MFC and delete the upstream source.
        k_delMRoute(dsrc->ip, mct->group, dsrc->mfc->IfDp->index);
        if (dsrc->mfc->next)
            dsrc->mfc->next->prev = dsrc->mfc->prev;
        if (dsrc->mfc->prev)
            dsrc->mfc->prev->next = dsrc->mfc->next;
        if (mct->mfc == dsrc->mfc)
            mct->mfc = dsrc->mfc->next;
        free(dsrc->mfc);   // Alloced by Self
        dsrc->mfc = NULL;
    }

    logRouteTable("Activate Route", 1, NULL, 0);
}

/**
*   Ages active groups in tables.
*/
void ageGroups(struct IfDesc *IfDp) {
    struct ifMct *imc;
    LOG(LOG_INFO, 0, "ageGroups: Aging active groups on %s.", IfDp->Name);

    for (imc = IfDp->dMct; imc; imc = imc ? imc->next : IfDp->dMct) {
        if (BIT_TST(imc->mct->lmBits, IfDp->index))
            continue;

        // Age v1 and v2 compatibility mode.
        if (imc->mct->v1Age[IfDp->index] == 0)
            BIT_CLR(imc->mct->v1Bits, IfDp->index);
        else if (imc->mct->v1Age[IfDp->index] > 0)
            imc->mct->v1Age[IfDp->index]--;
        if (imc->mct->v2Age[IfDp->index] == 0)
            BIT_CLR(imc->mct->v2Bits, IfDp->index);
        else if (imc->mct->v2Age[IfDp->index] > 0)
            imc->mct->v2Age[IfDp->index]--;

        // Age sources in group.
        bool             keep = false;
        struct sources *dsrc = imc->mct->sources;
        while (dsrc) {
            if (NOT_SET(dsrc, IfDp) || (IS_EX(imc->mct, IfDp) && dsrc->age[IfDp->index] == 0)) {
                dsrc = dsrc->next;
            } else if (!BIT_TST(dsrc->lmBits, IfDp->index) && IS_IN(imc->mct, IfDp) && dsrc->age[IfDp->index] == 0) {
                LOG(LOG_INFO, 0, "ageGroups: Removed source %s from %s on %s after aging.",
                                  inetFmt(dsrc->ip, 1), inetFmt(imc->mct->group, 2), IfDp->Name);
                dsrc = delSrc(dsrc, IfDp, (uint32_t)-1);
            } else if (BIT_TST(dsrc->lmBits, IfDp->index) || dsrc->age[IfDp->index]-- > 0) {
                dsrc = dsrc->next;
                keep = true;
            }
        }

        // Next age group.
        if (IS_EX(imc->mct, IfDp) && imc->mct->age[IfDp->index] == 0 && !BIT_TST(imc->mct->v1Bits, IfDp->index))
            toInclude(imc->mct, IfDp);
        if (IS_IN(imc->mct, IfDp) && (!keep || !imc->mct->nsrcs)) {
            LOG(LOG_INFO, 0, "ageGroups: Removed group %s from %s after aging.", inetFmt(imc->mct->group, 2), IfDp->Name);
            imc = delGroup(imc->mct, IfDp, imc, 1);
            continue;
        } else if (IS_IN(imc->mct, IfDp)) {
            sendJoinLeaveUpstream(imc->mct, 1);
        } else if (imc->mct->age[IfDp->index] > 0)
            imc->mct->age[IfDp->index]--;

        for (struct mfc *mfc = imc->mct->mfc; mfc; activateRoute(NULL, mfc->src, 0, 0, true), mfc = mfc->next);
    }

    if (MCT)
        logRouteTable("Age Groups", 1, NULL, 0);
    else
        LOG(LOG_DEBUG, 0, "ageGroups: Multicast table is empty.");
}

/**
*   Debug function that writes the routing table entries to the log or sends them to the cli socket specified in arguments.
*/
void logRouteTable(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd) {
    struct mcTable  *mct;
    struct mfc      *mfc;
    struct IfDesc   *IfDp = NULL;
    char             msg[CLI_CMD_BUF] = "", buf[CLI_CMD_BUF] = "";
    unsigned int     rcount = 1;
    uint64_t         totalb = 0, totalr = 0;

    if (! cliSockAddr) {
        LOG(LOG_DEBUG, 0, "Current multicast table (%s):", header);
        LOG(LOG_DEBUG, 0, "_____|______SRC______|______DST______|_______In_______|_____Out____|____dHost____|_______Data_______|______Rate_____");
    } else if (h) {
        sprintf(buf, "Current Multicast Table:\n_____|______SRC______|______DST______|_______In_______|_____Out____|____dHost____|_______Data_______|______Rate_____\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
    GETMRT(mct) {
        mfc = mct->mfc;
        do {
            if (mfc) {
                IfDp = mfc->IfDp;
                totalb += mfc->bytes;
                totalr += mfc->rate;
            }
            if (h) {
                strcpy(msg, "%4d |%15s|%15s|%16s| 0x%08x | %11s | %14lld B | %10lld B/s");
            } else {
                strcpy(msg, "%d %s %s %s %08x %s %ld %ld");
            }
            if (! cliSockAddr) {
                LOG(LOG_DEBUG, 0, msg, rcount, mfc ? inetFmt(mfc->src->ip, 1) : "-", inetFmt(mct->group, 2), mfc ? IfDp->Name : "", mct->vifBits, ! CONFIG->fastUpstreamLeave || !mct->mode ? "not tracked" : noHash(mct->dHostsHT) ? "no" : "yes", mfc ? mfc->bytes : 0, mfc ? mfc->rate : 0);
            } else {
                sprintf(buf, strcat(msg, "\n"), rcount, mfc ? inetFmt(mfc->src->ip, 1) : "-", inetFmt(mct->group, 2), mfc ? IfDp->Name : "", mct->vifBits, ! CONFIG->fastUpstreamLeave || !mct->mode ? "not tracked" : noHash(mct->dHostsHT) ? "no" : "yes", mfc ? mfc->bytes : 0, mfc ? mfc->rate : 0);
                sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
            }
            mfc = mfc ? mfc->next : NULL;
            rcount++;
        } while (mfc);
    }

    if (! cliSockAddr) {
        LOG(LOG_DEBUG, 0, "Total|---------------|---------------|----------------|------------|-------------| %14lld B | %10lld B/s", totalb, totalr);
    } else if (h) {
        strcpy(msg, "Total|---------------|---------------|----------------|------------|-------------| %14lld B | %10lld B/s\n");
        sprintf(buf, msg, totalb, totalr);
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
