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

struct vifFlags {
    // Generic per vif flags, applies to both groups and sources
    uint32_t            sd;                       // Filters set flag for downstream
    uint32_t            d;                        // Active downstream vifs
    uint32_t            dd;                       // Denied dowstream vifs
    uint32_t            su;                       // Filters set flag for upstream
    uint32_t            u;                        // Active upstream vifs
    uint32_t            ud;                       // Denied upstream vifs
    uint32_t            us;                       // Upstream membership state
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
    uint64_t            bytes, rate;              // Bwcontrol counters
};

struct mcTable {
    // Keeps multicast group and source membership information.
    struct mcTable     *prev;                     // Pointer to the previous group in table.
    struct mcTable     *next;                     // Pointer to the next group in table.
    uint32_t            group;                    // The group to route
    uint32_t            nsrcs;                    // Number of sources for group
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
    struct src        *src[];                     // Array of pointers to sources
};

// Routing table static vars.
static struct mcTable  **MCT           = NULL;    // Multicast group membership tables
static struct qlst      *qL            = NULL;    // List of running GSQ
static uint32_t          qC            = 0;       // Querier count.
static char              msg[TMNAMESZ] = "";      // Timer name buffer

// Prototypes
static struct mcTable     *findGroup(register uint32_t group, bool create);
static bool                addGroup(struct mcTable* mct, struct IfDesc *IfDp, int dir, int mode, uint32_t srcHash);
static struct ifMct       *delGroup(struct mcTable *mct, struct IfDesc *IfDp, struct ifMct *imc, int dir);
static bool                checkFilters(struct IfDesc *IfDp, int dir, struct src *src, struct mcTable *mct);
static void               *updateSourceFilter(struct mcTable *mct, struct IfDesc *IfDp);
static struct src         *addSrc(struct IfDesc *IfDp, struct mcTable *mct, uint32_t ip, bool check, bool set,
                                  struct src *src, uint32_t srcHash);
static struct src         *delSrc(struct src *src, struct IfDesc *IfDp, int mode, uint32_t srcHash);
static inline struct qlst *addSrcToQlst(struct src *src, struct IfDesc *IfDp, struct qlst *qlst, uint32_t srcHash);
static struct ifMct       *toInclude(struct mcTable *mct, struct IfDesc *IfDp, struct ifMct *imc);
static inline void         startQuery(struct IfDesc *IfDp, struct qlst *qlst);
static void                groupSpecificQuery(struct qlst *qlst);

/**
*   Private access function to find a given group in MCT, creates new if required.
*/
static struct mcTable *findGroup(register uint32_t group, bool create) {
    struct mcTable *mct, *Nmct;
    uint32_t        mctHash = murmurhash3(group) % CONFIG->mcTables;

    // Initialize the routing tables if necessary.
    if (! MCT && !create)
        return NULL;
    if (! MCT && ! (MCT = calloc(CONFIG->mcTables, sizeof(void *))))   // Freed by delGroup())
        LOG(LOG_ERR, errno, "findGroup: Out of memory.");
    else for (mct = MCT[mctHash];; mct = mct->next) {
        // Find the group (or place for new) in the table.
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
*  Adds a group to an interface. All downstream requested groups will be attached to interface,
*  whether denied or allowed. Denied exclude mode groups will age so that reference to permissions,
*  can be kept for as long as the group is being requested on the interface.
*/
static bool addGroup(struct mcTable* mct, struct IfDesc *IfDp, int dir, int mode, uint32_t srcHash) {
    struct ifMct *imc, **list = (struct ifMct **)(dir ? &IfDp->dMct : &IfDp->uMct);
    if (dir ? NOT_SET(mct, d, IfDp) : NOT_SET(mct, u, IfDp)) {
        if (! (imc = malloc(sizeof(struct ifMct))))   // Freed by delGroup or freeIfDescL()
            LOG(LOG_ERR, errno, "addGroup: Out of Memory.");
        *imc = (struct ifMct){ NULL, mct, *list };
        if (*list)
            (*list)->prev = imc;
        *list = imc;
    }

    if (!checkFilters(IfDp, dir, NULL, mct)) {
        LOG(LOG_NOTICE, 0, "The group %s may not be requested %s on %s.", inetFmt(mct->group , 1),
                            dir ? "downstream" : "upstream", IfDp->Name);
        dir ? BIT_SET(mct->vifB.d, IfDp->index) : BIT_SET(mct->vifB.u, IfDp->index);
        if (dir && mode) {
            BIT_SET(mct->mode, IfDp->index);
            mct->vifB.age[IfDp->index] = IfDp->querier.qrv;  // Group timer = GMI
        }
        return false;
    }

    if (dir) {
        // Set downstream status and join group upstream if necessary.
        setHash(mct->dHostsHT, srcHash);
        if (mode) {
            // Exclude mode group, set age to GMI.
            BIT_SET(mct->mode, IfDp->index);
            BIT_CLR(mct->vifB.lm, IfDp->index);
            mct->vifB.age[IfDp->index] = IfDp->querier.qrv;  // Group timer = GMI
        }
        if (NOT_SET(mct, d, IfDp)) {
            BIT_SET(mct->vifB.d, IfDp->index);
            if (IS_EX(mct, IfDp))
                // Activate any MFC is exclude mode group is requested for the first time.
                for (struct mfc *mfc = mct->mfc; mfc; activateRoute(mfc->IfDp, mfc->src, 0, 0, true), mfc = mfc->next);
        }
        IFGETIFL((mct->vifB.us | mct->vifB.ud) != uVifs, IfDp)
            // Check if any upstream interfaces still need to join the group.
            if (IS_UPSTREAM(IfDp->state) && NOT_SET(mct, us, IfDp))
                addGroup(mct, IfDp, 0, 1, (uint32_t)-1);
    } else if (mct->vifB.d) {
        // Set upstream status and join group if it is in exclude mode upstream.
        BIT_SET(mct->vifB.u, IfDp->index);
        if (NOT_SET(mct, us, IfDp) && mct->mode) {
            if (CONFIG->bwControlInterval && IfDp->conf->ratelimit > 0 && IfDp->rate > IfDp->conf->ratelimit)
                LOG(LOG_NOTICE, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.",
                                    IfDp->Name, IfDp->rate, IfDp->conf->ratelimit, inetFmt(mct->group, 1));
            else {
                LOG(LOG_INFO, 0, "addGroup: Joining group %s upstream on interface %s.",
                                  inetFmt(mct->group, 1), IfDp->Name);
                if (k_updateGroup(IfDp, true, mct->group, mct->mode, (uint32_t)-1))
                    BIT_SET(mct->vifB.us, IfDp->index);
            }
        }
    }

    return true;
}

/**
*   Remove a specified MCT from interface.
*/
static struct ifMct *delGroup(struct mcTable* mct, struct IfDesc *IfDp, struct ifMct *imc, int dir) {
    struct ifMct *pimc = NULL, **list = (struct ifMct **)(dir ? &IfDp->dMct : &IfDp->uMct);
    LOG(LOG_DEBUG, 0, "delGroup: Removing group entry for %s from %s.", inetFmt(mct->group, 1), IfDp->Name);

    // Update the interface group list.
    if (! imc)
        for (imc = *list; imc && imc->mct != mct; imc = imc->next);
    pimc = imc->prev;
    if (imc->next)
        imc->next->prev = imc->prev;
    if (imc->prev)
        imc->prev->next = imc->next;
    else
        *list = imc->next;
    free(imc);  // Alloced by addGroup()

    if (!dir) {
        // Leave group upstream and clear upstream status.
        if (IS_SET(mct, us, IfDp)) {
            LOG(LOG_INFO, 0, "delGroup: Leaving group %s upstream on interface %s.", inetFmt(mct->group, 1), IfDp->Name);
            k_setSourceFilter(IfDp, mct->group, MCAST_INCLUDE, 0, NULL);
        }
        BIT_CLR(mct->vifB.u, IfDp->index);
        BIT_CLR(mct->vifB.su, IfDp->index);
        BIT_CLR(mct->vifB.ud, IfDp->index);
        BIT_CLR(mct->vifB.us, IfDp->index);
    } else {
        // Clear group membership from downstream interface and ckeck if it can be removed completely.
        delQuery(IfDp, NULL, mct, NULL, 0);
        BIT_CLR(mct->vifB.d, IfDp->index);
        if (mct->vifB.d) {
            // Clear interface and sources flags and Update kernel route if group still active on other interface.
            BIT_CLR(mct->vifB.sd, IfDp->index);
            BIT_CLR(mct->vifB.dd, IfDp->index);
            BIT_CLR(mct->vifB.qry, IfDp->index),
            BIT_CLR(mct->vifB.lm, IfDp->index);
            BIT_CLR(mct->mode, IfDp->index);
            BIT_CLR(mct->v1Bits, IfDp->index);
            BIT_CLR(mct->v2Bits, IfDp->index);
            mct->vifB.age[IfDp->index] = mct->v1Age[IfDp->index] = mct->v2Age[IfDp->index] = 0;
            for (struct src *src = mct->sources; src; src = delSrc(src, IfDp, 0, (uint32_t)-1));
        } else {
            // Group can be removed from table.
            uint32_t mctHash = murmurhash3(mct->group) % CONFIG->mcTables;

            LOG(LOG_DEBUG, 0, "delGroup: Deleting group %s from table %d.",inetFmt(mct->group, 1), mctHash);
            // Send Leave requests upstream.
            GETIFLIF(IfDp, IS_SET(mct, u, IfDp))
                delGroup(mct, IfDp, NULL, 0);

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
            for (struct src *src = mct->sources; src; src = delSrc(src, NULL, 0, (uint32_t)-1));
            free(mct);  // Alloced by findGroup()
        }
    }

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
*   created in list, no src if it should go to end of list.
*/
static struct src *addSrc(struct IfDesc *IfDp, struct mcTable *mct, uint32_t ip, bool check, bool set,
                              struct src *src, uint32_t srcHash) {
    // Check if maxorigins is exceeded.
    if ((check || set) && CONFIG->maxOrigins && mct->nsrcs > CONFIG->maxOrigins) {
        if (!(mct->nsrcs & 0x80000000)) {
            mct->nsrcs |= 0x80000000;
            LOG(LOG_WARNING, 0, "Max origins (%d) exceeded for %s.", CONFIG->maxOrigins, inetFmt(mct->group, 1));
        }
        return NULL;
    } else if (! src || src->ip != ip) {
        // New source should be created. If source was requested downstream increase nrsrcs.
        struct src *nsrc;
        if (check || set)
            mct->nsrcs++;
        LOG(LOG_DEBUG, 0, "addSrc: New source %s (%d) for group %s.", inetFmt(ip, 1), mct->nsrcs, inetFmt(mct->group, 2));
        if (! (nsrc = calloc(1, sizeof(struct src) + CONFIG->dHostsHTSize)))
            LOG(LOG_ERR, errno, "addSrc: Out of memory.");   // Freed by delSrc()
        nsrc->ip = ip;
        nsrc->mct = mct;
        if (! mct->sources) {
            mct->sources = nsrc;
            nsrc->prev = nsrc;
        } else if (! src) {
            nsrc->prev = mct->sources->prev;
            nsrc->prev->next = mct->sources->prev = nsrc;
        } else {
            nsrc->prev = src->prev;
            if (mct->sources == src)
                mct->sources = nsrc;
            else
                nsrc->prev->next = nsrc;
            nsrc->next = src;
            src->prev = nsrc;
        }
        src = nsrc;
    } else if (!src->vifB.d && !src->vifB.dd)
        // Unrequested sending source was requested, increase nrsrcs.
        mct->nsrcs++;

    // Set source bits and age, update MFC if present. When source is denied, we still do aging.
    if (set) {
        if (check) {
            BIT_CLR(src->vifB.lm, IfDp->index);
            src->vifB.age[IfDp->index] = IfDp->querier.qrv;
            setHash(src->dHostsHT, srcHash);
        }
        if (NOT_SET(src, d, IfDp)) {
            BIT_SET(src->vifB.d, IfDp->index);
            if (src->mfc)
                // Activate route will check ACL for source on downstream interfaces.
                activateRoute(src->mfc->IfDp, src, src->ip, mct->group, true);
        }
    }

    struct IfDesc *If;
    if (check && !checkFilters(IfDp, 1, src, mct)) {
        // Check if the source is allowed on interface.
        LOG(LOG_NOTICE, 0, "Group %s from source %s not allowed downstream on %s.",
                            inetFmt(mct->group, 1), inetFmt(ip, 2), IfDp->Name);
        return NULL;
    } else IFGETIFL((set && ((src->vifB.ud | src->vifB.us) != uVifs || src->vifB.su != uVifs)), If) {
        // Join or block the source upstream if necessary.
        if (IS_UPSTREAM(If->state) && (NOT_SET(src, us, If) || NOT_SET(src, su, IfDp))) {
            if (!mct->mode && !checkFilters(If, 0, src, mct)) {
                LOG(LOG_NOTICE, 0, "Group %s from source %s not allowed upstream on %s.",
                                    inetFmt(mct->group, 1), inetFmt(src->ip, 2), If->Name);
                if (IS_SET(src, us, If)) {
                    // If source was joined and acl changed, leave.
                    LOG(LOG_INFO, 0, "Leaving source %s from group %s on upstream interface %s.",
                                      inetFmt(src->ip, 1), inetFmt(mct->group, 2), If->Name);
                    k_updateGroup(If, false, mct->group, 0, src->ip);
                    BIT_CLR(src->vifB.us, If->index);
                }
            } else if (NOT_SET(src, us, If) && (!mct->mode || (src->vifB.d == mct->vifB.d && !src->vifB.age[IfDp->index]))
                                            && k_updateGroup(If, true, mct->group, mct->mode, src->ip)) {
                LOG(LOG_INFO, 0, "addSrc: %s source %s in group %s on %s.", mct->mode ? "Blocked" : "Joined",
                                  inetFmt(src->ip, 1), inetFmt(mct->group, 2), If->Name);
                BIT_SET(src->vifB.us, If->index);
            }
        }
    }

    return src;
}

/**
*   Removes a source from the list of group sources. When quickleave is enabled (mode = 1), sources requested in include
*   mode will not be removed for host tracking purposes.
*   When switching from upstream filter mode (mode = 2 or mode = 3), sources will not be left here,
*   because update SourceFilter will atomically switch filter mode.
*/
static struct src *delSrc(struct src *src, struct IfDesc *IfDp, int mode, uint32_t srcHash) {
    struct src     *nsrc = src->next;
    struct mcTable *mct  = src->mct;
    LOG(LOG_DEBUG, 0, "delSrc: Remove source %s from %s on %s.", inetFmt(src->ip, 1), inetFmt(mct->group, 2),
                       IfDp ? IfDp->Name : "all interfaces");

    // Remove source from hosts hash table, and clear vifbits.
    clearHash(src->dHostsHT, srcHash);
    if (IfDp) {
        BIT_CLR(src->vifB.d, IfDp->index);
        BIT_CLR(src->vifB.sd, IfDp->index);
        BIT_CLR(src->vifB.dd, IfDp->index);
    }

    if (! IfDp || NOT_SET(src, qry, IfDp)) {
        // Remove the source if it is not actively being queried and not active on other vifs.
        if (IfDp) {
            BIT_CLR(src->vifB.lm, IfDp->index);
            if (mode == 0)
                src->vifB.age[IfDp->index] = 0;
        }
        struct IfDesc *If;
        IFGETIFL(! IfDp || !src->vifB.d || (mct->mode && src->vifB.d != mct->vifB.d && src->vifB.age[IfDp->index] == 0), If)
            // Source should not be left / unblocked when switching upstream filter mode.
            if (mode < 2 && (   ( mct->mode && IS_SET(mct, us, If) && src->vifB.d != src->vifB.d)
                             || (!mct->mode && IS_SET(src, us, If)))) {
                LOG(LOG_INFO, 0, "delSrc: %s source %s in group %s on upstream interface %s", mct->mode ? "Unblocking" : "Leaving",
                                  inetFmt(src->ip, 1), inetFmt(mct->group, 2), If->Name);
                k_updateGroup(If, false, mct->group, mct->mode, src->ip);
                BIT_CLR(src->vifB.us, If->index);
            }
        if (! IfDp || !src->vifB.d) {
            if (src->mfc && (! IfDp || !mct->mode))
                activateRoute(src->mfc->IfDp, src, src->ip, mct->group, false);
            if (CONFIG->maxOrigins && (--mct->nsrcs & ~0x80000000) < CONFIG->maxOrigins)
                // Reset maxorigins exceeded flag.
                mct->nsrcs &= ~0x80000000;
            if ((mode == 0 || mode == 3) && ! src->mfc) {
                // Remove the source if there are no senders.
                if (src->next)
                    src->next->prev = src->prev;
                if (src == mct->sources->prev)
                    mct->sources->prev = src->prev;
                if (src != mct->sources)
                    src->prev->next = src->next;
                else
                    mct->sources = src->next;
                free(src);  // Alloced by addSrc()
             }
        } else if (src->mfc)
            // Update MFC if source remains.
            activateRoute(src->mfc->IfDp, src, src->ip, mct->group, true);
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
        } else if (IS_DOWNSTREAM(IfDp->state) && (mct->group & group.mask) == group.ip && IS_SET(mct, d, IfDp)) {
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
            GETIFLIF(IfDp, IfDp == mfc->IfDp || IS_SET(mct, d, IfDp)) {
                // Find the incoming and outgoing interfaces and add to counter.
                IfDp->bytes += bwUpc->bu_measured.b_bytes;
                LOG(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to interface %s (%lld B/s), total %lld.",
                                   bwUpc->bu_measured.b_bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
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
    GETIFL(IfDp)
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
            GETIFLIF(IfDp, IfDp == mfc->IfDp || IS_SET(mct, d, IfDp)) {
                IfDp->rate += mfc->rate;
                LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld B/s to interface %s (%lld B/s), total %lld.",
                                   mfc->rate, IfDp->Name, IfDp->rate, IfDp->bytes);
            }
#endif
        }
    }

    // On Linux get the interface stats via ioctl.
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
    GETIFLIF(IfDp, IfDp->index != (uint8_t)-1) {
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
#endif

    // Set next timer;
    *tid = timer_setTimer(TDELAY(CONFIG->bwControlInterval * 10), "Bandwidth Control", (timer_f)bwControl, tid);
}

/**
*  ACL evaluation. Returns whether group/src is allowed on interface.
*  dir: 0 = upstream, 1 = downstream
*  Keep access status in permission bits .sd or .su means group access is known.
*  When dd or us is set means group is denied, when not set group is allowed.
*/
static bool checkFilters(struct IfDesc *IfDp, int dir, struct src *src, struct mcTable *mct) {
    if (IfDp->filCh) {
        // ACL change due to config reload, reset permission bits so access is rechecked.
        dir ? BIT_CLR(mct->vifB.dd, IfDp->index) : BIT_CLR(mct->vifB.ud, IfDp->index);\
        if (dir) for (src = mct->sources; src; src = src->next)
            BIT_CLR(src->vifB.sd, IfDp->index) || BIT_CLR(src->vifB.dd, IfDp->index);
        else for (src = mct->sources; src; src = src->next)
            BIT_CLR(src->vifB.su, IfDp->index) || BIT_CLR(src->vifB.ud, IfDp->index);
    } else if (src ? (dir ? IS_SET(src, sd, IfDp) : IS_SET(src, su, IfDp)) : (dir ? IS_SET(mct, sd, IfDp) : IS_SET(mct, su, IfDp))) 
        // If permissions are known return whether allowed or denied. Proceed to check filters if not.
        return src ? (dir ? NOT_SET(src, dd, IfDp) : NOT_SET(src, ud, IfDp))
                   : (dir ? NOT_SET(mct, dd, IfDp) : NOT_SET(mct, ud, IfDp));

    // Set known permission bit for source or group.
    src ? (dir ? BIT_SET(src->vifB.sd, IfDp->index) : BIT_SET(src->vifB.su, IfDp->index))
        : (dir ? BIT_SET(mct->vifB.sd, IfDp->index) : BIT_SET(mct->vifB.su, IfDp->index));

    LOG(LOG_DEBUG, 0, "checkFilters: Checking access for %s%s%s on %s interface %s.", src ? inetFmt(src->ip, 1) : "",
                       src ? ":" : "", inetFmt(mct->group, 2), dir ? "downstream" : "upstream", IfDp->Name);

    // Filters are processed top down until a definitive action (BLOCK or ALLOW) is found.
    // The default action when no filter applies is block.
    struct filters *filter;
    for (filter = IfDp->conf->filters; filter && ((dir ? !IS_DOWNSTREAM(filter->dir) : !IS_UPSTREAM(filter->dir))
            || !(src ? ((src->ip & filter->src.mask) == filter->src.ip && (mct->group & filter->dst.mask) == filter->dst.ip)
                     : ((mct->group & filter->dst.mask) == filter->dst.ip))); filter = filter->next);
    if (! filter || !filter->action)
        // When denied set denied bit for source or group.
        src ? (dir ? BIT_SET(src->vifB.dd, IfDp->index) : BIT_SET(src->vifB.ud, IfDp->index))
            : (dir ? BIT_SET(mct->vifB.dd, IfDp->index) : BIT_SET(mct->vifB.ud, IfDp->index));

    return filter && filter->action;
}

/**
*   Updates source filter for a group on an upstream interface when filter mode changes.
*/
static void *updateSourceFilter(struct mcTable *mct, struct IfDesc *IfDp) {
    uint32_t    nsrcs = 0, *slist = NULL, i;
    struct src *src;
    // Build source list for upstream interface.
    if (! (slist = malloc((mct->nsrcs & ~0x80000000) * sizeof(uint32_t))))  // Freed by self
        LOG(LOG_ERR, errno, "updateSourceFilter: Out of Memory.");
    for (nsrcs = 0, src = mct->sources; src; src = src->next) {
        if (!mct->mode) {
            if (!src->vifB.d || noHash(src->dHostsHT)) {
                // IN: Do not add sources with no listeners.
                LOG(LOG_INFO, 0, "updateSourceFilter: No downstream hosts %s:%s on %s, not adding to source list.",
                                  inetFmt(src->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
                continue;
            }
            if (!checkFilters(IfDp, 0, src, mct)) {
                // IN: Do not add denied sources on upstream interface.
                LOG(LOG_INFO, 0, "updateSourceFilter: Source %s not allowed for group %s on interface %s.",
                                  inetFmt(src->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
                continue;
            } else
                BIT_SET(src->vifB.u, IfDp->index);
        } else {
            // EX: Source must be excluded (age = 0) on all active interfaces for group.
            if (src->vifB.d != mct->vifB.d)
                continue;
            else for (i = 0; i < MAXVIFS && ( !((mct->vifB.d >> i) & 0x1) || !mct->vifB.age[i] ); i++ );
            if (i >= MAXVIFS)
                continue;
        }

        LOG(LOG_DEBUG, 0, "updateSourceFilter: Adding %s to source list for %s on %s.",
                           inetFmt(src->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
        slist[nsrcs++] = src->ip;
    }

    // Set new upstream source filter and set upstream status if new mode is exclude, clear if inlcude.
    k_setSourceFilter(IfDp, mct->group, mct->mode ? MCAST_EXCLUDE : MCAST_INCLUDE, nsrcs, slist);
    mct->mode ? BIT_SET(mct->vifB.us, IfDp->index) : BIT_CLR(mct->vifB.us, IfDp->index);
    free(slist);  // Alloced by self
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
                struct src **src;
                // Quickleave was enabled or disabled, or hastable size was changed.
                // Reallocate appriopriate amount of memory and reinitialize downstreahosts tracking.
                for (src = &(mct->sources); *src; src = &(*src)->next) {
                    if (! (*src = realloc(*src, sizeof(struct src) + CONFIG->dHostsHTSize)))
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
                    activateRoute(mfc->IfDp, mfc->src, 0, 0, true);
                }
#endif
            } else {
                // New upstream interface join all relevant groups and sources.
                addGroup(mct, IfDp, 0, 1, (uint32_t)-1);
                for (struct src *src = mct->sources; src; src = src->next)
                    if (   (mct->mode && src->vifB.d == mct->vifB.d && !src->vifB.age[IfDp->index])
                        || (!mct->mode && src->vifB.d && checkFilters(IfDp, 0, src, mct)))
                        if (k_updateGroup(IfDp, true, mct->group, mct->mode, src->ip))
                            LOG(LOG_INFO, 0, "clearGroups: %s source %s in group %s on upstream interface %s.",
                                              mct->mode ? "Blocked" : "Joined", inetFmt(src->ip, 1), inetFmt(mct->group, 2),
                                              IfDp->Name);
            }
        }
        return;
    }

    // Downstream interface transition.
    if (((CONFRELOAD || SSIGHUP) && IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate)) || !IS_DOWNSTREAM(newstate))
        for (imc = IfDp->dMct; imc; imc = imc ? imc->next : IfDp->dMct) {
            if (!IS_DOWNSTREAM(newstate)) {
                // Transition to disabled / upstream, remove from group.
                LOG(LOG_INFO, 0, "clearGroups: Vif %d - %s no longer downstream, removing group %s.",
                                  IfDp->index, IfDp->Name, inetFmt(imc->mct->group, 1));
                imc = delGroup(imc->mct, IfDp, imc, 1);
            } else if (NOT_SET(imc->mct, dd, IfDp) && !checkFilters(IfDp, 1, NULL, imc->mct)) {
                // Check against bl / wl changes on config reload / sighup.
                LOG(LOG_NOTICE, 0, "Group %s no longer allowed downstream on Vif %d - %s.",
                                    inetFmt(imc->mct->group, 1), IfDp->index, IfDp->Name);
                imc = delGroup(imc->mct, IfDp, imc, 1);
            } else if (IS_SET(imc->mct, dd, IfDp) && addGroup(imc->mct, IfDp, 1, 0, (uint32_t)-1))
                LOG(LOG_INFO, 0, "clearGroups: Group %s now allowed downstream on %s.", inetFmt(imc->mct->group, 1), IfDp->Name);
        }

    // Upstream interface transition.
    if (((CONFRELOAD || SSIGHUP) && IS_UPSTREAM(newstate) && IS_UPSTREAM(oldstate)) || !IS_UPSTREAM(newstate))
        for (imc = IfDp->uMct; imc; imc = imc ? imc->next : IfDp->uMct) {
            if (!IS_UPSTREAM(newstate)) {
                if (IS_SET(imc->mct, u, IfDp))
                    // Transition from upstream to downstream or disabled. Leave group.
                    imc = delGroup(imc->mct, IfDp, imc, 0);
            } else if (NOT_SET(imc->mct, ud, IfDp) && !checkFilters(IfDp, 0, NULL, imc->mct)) {
                // Check against bl / wl changes on config reload / sighup.
                LOG(LOG_NOTICE, 0, "Group %s no longer allowed upstream on interface %s.",
                                    inetFmt(imc->mct->group, 1), IfDp->Name);
                imc = delGroup(imc->mct, IfDp, imc, 0);
            } else if (IS_SET(imc->mct, ud, IfDp) && addGroup(imc->mct, IfDp, 0, 0, (uint32_t)-1))
                LOG(LOG_INFO, 0, "clearGroups: Group %s now allowed upstream on %s.", inetFmt(imc->mct->group, 1), IfDp->Name);
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
void updateGroup(struct IfDesc *IfDp, uint32_t ip, struct igmpv3_grec *grec) {
    uint16_t  i = 0, type    = grecType(grec), nsrcs = grecNscrs(grec);
    uint32_t         group   = grec->grec_mca.s_addr,
                     srcHash = murmurhash3(ip) % (CONFIG->dHostsHTSize);
    struct src      *src     = NULL, *tsrc = NULL;
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

    bool is_ex, is_in;
    struct IfDesc *If;
    switch (type) {
    case IGMPV3_CHANGE_TO_EXCLUDE:
        if ((BIT_TST(mct->v1Bits, IfDp->index) || BIT_TST(mct->v2Bits, IfDp->index || IfDp->querier.ver < 3)) && nsrcs > 0) {
            LOG(LOG_INFO, 0, "updateGroup: Ignoring %d sources for %s on %s, v1 or v2 host/querier present.",
                              nsrcs, inetFmt(group, 1), IfDp->Name);
            nsrcs = 0;
        } /* FALLTHRU */
    case IGMPV3_MODE_IS_EXCLUDE:
        is_ex = IS_EX(mct, IfDp);
        is_in = !mct->mode && mct->vifB.d;
        if (!addGroup(mct, IfDp, 1, 1, srcHash))
            break;

        qlst->type = 4;
        for (i = 0, src = mct->sources; src || i < nsrcs; i++) {
            if (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr)) do {
                // IN: Delete (A - B) / EX: Delete (X - A), Delete (Y - A)
                if (IS_SET(src, d, IfDp) || IS_SET(src, dd, IfDp))
                    src = delSrc(src, IfDp, !CONFIG->fastUpstreamLeave ? 0 : is_in ? 2 : 1, srcHash);
                else {
                    if (src->mfc && NOT_SET(src, d, IfDp) && !is_ex)
                        activateRoute(src->mfc->IfDp, src, src->ip, mct->group, true);
                    src = src->next;
                }
            } while (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr));
            if (i < nsrcs && (! (tsrc = src) || tsrc->ip >= grec->grec_src[i].s_addr)) {
                // IN: (B - A) = 0 / EX: (A - X - Y) = Group Timer?
                if ((src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, false,
                                  !(!is_ex && tsrc && tsrc->ip == grec->grec_src[i].s_addr), tsrc, (uint32_t)-1)))
                    if (type == IGMPV3_CHANGE_TO_EXCLUDE && src &&
                             (   ((! tsrc || tsrc->ip > grec->grec_src[i].s_addr) && is_ex)
                              || (tsrc && tsrc->ip == grec->grec_src[i].s_addr && IS_SET(src, d, IfDp)
                                       && (!is_ex || src->vifB.age[IfDp->index] > 0))))
                        // IN: Send Q(G, A * B) / EX: Send Q(G, A - Y)
                        qlst = addSrcToQlst(src, IfDp, qlst, srcHash);
                src = src ? src->next : tsrc;
            }
        }
        IFGETIFL(is_in, If)
            // Switch upstream filter mode if inlcude mode group was requested in exlcude mode on any downstream interface.
            if (IS_SET(mct, us, If))
                updateSourceFilter(mct, If);
        break;

    case IGMPV3_CHANGE_TO_INCLUDE:
        if (BIT_TST(mct->v1Bits, IfDp->index) || IfDp->querier.ver == 1) {
            LOG(LOG_INFO, 0, "updateGroup: Ignoring TO_IN for %s on %s, v1 host/querier present.", inetFmt(group, 1), IfDp->Name);
            break;
        }
        if (nsrcs == 0) {
            clearHash(mct->dHostsHT, srcHash);
            if (mct->vifB.us && noHash(mct->dHostsHT)) {
                struct IfDesc *If;
                GETIFLIF(If, IS_SET(mct, us, If)) {
                    LOG(LOG_INFO, 0, "updateGroup: Last downstream host %s, quickleave group %s on %s.",
                                      inetFmt(ip, 1), inetFmt(group, 2), If->Name);
                    delGroup(mct, If, NULL, 0);
                }
            }
        }
        if (IS_EX(mct, IfDp) && NOT_SET(mct, lm, IfDp) && !(IS_IN(mct, IfDp) && !mct->nsrcs)) {
            if (! (qlst1 = malloc(sizeof(struct qlst))))  // // Freed by startQuery() or delQuery().
                LOG(LOG_ERR, errno, "updateGroup: Out of Memory.");
            *qlst1 = (struct qlst){ NULL, NULL, mct, IfDp, 0, 2, IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount, 0, 0 };
            startQuery(IfDp, qlst1);
        }  /* FALLTHRU */
    case IGMPV3_ALLOW_NEW_SOURCES:
    case IGMPV3_MODE_IS_INCLUDE:
        if (nsrcs > 0 && !addGroup(mct, IfDp, 1, 0, (uint32_t)-1))
            break;

        qlst->type = 4;
        for (i = 0, src = mct->sources; src || i < nsrcs; src = src ? src->next : src) {
            if (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr)) {
                if (type == IGMPV3_CHANGE_TO_INCLUDE && IS_SET(src, d, IfDp) && (IS_IN(mct, IfDp) || src->vifB.age[IfDp->index] > 0))
                    // EX: Send Q(G, X - A) IN: Send Q(G, A - B)
                    qlst = addSrcToQlst(src, IfDp, qlst, (uint32_t)-1);
            } else if (i < nsrcs && (! (tsrc = src) || src->ip >= grec->grec_src[i].s_addr)) do {
                if (! (src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, true, true, tsrc, srcHash)))
                    // IN (B) = GMI, (A + B) / EX: (A) = GMI, (X + A) (Y - A)
                    src = tsrc;
                src = ! tsrc && src ? src->next : src;
            } while (++i < nsrcs && (! tsrc || tsrc->ip >= grec->grec_src[i].s_addr));
        }
        break;

    case IGMPV3_BLOCK_OLD_SOURCES:
        if (NOT_SET(mct, d, IfDp) || BIT_TST(mct->v1Bits, IfDp->index) ||
             BIT_TST(mct->v2Bits, IfDp->index) || IfDp->querier.ver < 3) {
            LOG(LOG_INFO, 0, "updateGroup: Ignoring BLOCK for %s on %s, %s.", inetFmt(group, 1), IfDp->Name,
                              NOT_SET(mct, d, IfDp) ? "not active" : "v1 or v2 host/querier present");
            break;
        }

        qlst->type = 4, i = 0;
        src  = mct->sources;
        bool nH = true;
        while (i < nsrcs && (IS_EX(mct, IfDp) || src)) {
            // IN: Send Q(G, A * B) / EX: Send Q(G, A - Y), (A - X - Y) = Group Timer?
            if (! (tsrc = src) || src->ip >= grec->grec_src[i].s_addr) {
                if (   ((! src || src->ip > grec->grec_src[i].s_addr) && IS_EX(mct, IfDp))
                    || (src->ip == grec->grec_src[i].s_addr && (   (IS_IN(mct, IfDp) && IS_SET(src, d, IfDp))
                                         || (IS_EX(mct, IfDp) && (src->vifB.age[IfDp->index] > 0 || NOT_SET(src, d, IfDp))))))
                    if ((src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, true, false, src, (uint32_t)-1))) {
                        qlst = addSrcToQlst(src, IfDp, qlst, srcHash);
                        if (src->vifB.us && noHash(src->dHostsHT)) {
                            struct IfDesc *If;
                            GETIFLIF(If, IS_SET(src, us, If)) {
                                LOG(LOG_INFO, 0, "updateGroup: Last downstream host %s, quickleave source %s in group %s on %s.",
                                                  inetFmt(ip, 1), inetFmt(src->ip, 2), inetFmt(group, 3), If->Name);
                                k_updateGroup(If, false, mct->group, 0, src->ip);
                                BIT_CLR(src->vifB.us, If->index);
                            }
                        }
                    } else
                        src = tsrc;
                i++;
            }
            if (CONFIG->fastUpstreamLeave)
                // When quickleave is enabled, check if the client is interested in any other source.
                for (; src && i < nsrcs && src->ip < grec->grec_src[i].s_addr; nH = !testHash(src->dHostsHT, srcHash),
                                                                               src = src->next);
            else
                for (; src && i < nsrcs && src->ip < grec->grec_src[i].s_addr; src = src->next);
        }
        if (CONFIG->fastUpstreamLeave && nH) {
            // When quickleave is enabled and client is not interested in any other source, it effectively left the group.
            for (; src && (nH = !testHash(src->dHostsHT, srcHash)); src = src->next);
            if (nH) {
                LOG(LOG_DEBUG, 0, "updateGroup: Last source %s in group %s for client %s on %s.",
                                   inetFmt(grec->grec_src[i - (i >= nsrcs ? 1 : 0)].s_addr, 1), inetFmt(mct->group, 2),
                                   inetFmt(ip, 3), IfDp->Name);
                clearHash(mct->dHostsHT, srcHash);
            }
        }
    }

    startQuery(IfDp, qlst);

    LOG(LOG_DEBUG, 0, "Updated group entry for %s on VIF #%d", inetFmt(group, 1), IfDp->index);
    logRouteTable("Update Group", 1, NULL, 0);
}

/**
*   Switches a group from exclude to include mode on interface.
*/
static struct ifMct *toInclude(struct mcTable *mct, struct IfDesc *IfDp, struct ifMct *imc) {
    struct src *src = mct->sources;
    bool        keep = false;
    uint32_t    mode = mct->mode;
    BIT_CLR(mode, IfDp->index);

    LOG(LOG_INFO, 0, "toInclude: Switching mode for %s to include on %s.", inetFmt(mct->group, 1), IfDp->Name);
    while (src) {
        // Remove all inactive sources from group on interface.
        if (!src->vifB.d || (IS_SET(src, d, IfDp) && src->vifB.age[IfDp->index] == 0)) {
            LOG(LOG_DEBUG, 0, "toInclude: Removed inactive source %s from group %s.", inetFmt(src->ip, 1), inetFmt(mct->group, 2));
            src = delSrc(src, IfDp, mode ? 0 : 3 , (uint32_t)-1);
        } else {
            keep = true;
            src = src->next;
        }
    }
    mct->mode = mode;
    BIT_CLR(mct->v2Bits, IfDp->index);
    mct->vifB.age[IfDp->index] = mct->v2Age[IfDp->index] = 0;
    if (!keep)
        imc = delGroup(mct, IfDp, NULL, 1);
    IFGETIFL(!mct->mode && mct->nsrcs, IfDp)
        // If group is joined on upstream interface and remains set new source filter and clear upstream status.
        if (IS_SET(mct, us, IfDp))
            updateSourceFilter(mct, IfDp);

    return imc;
}

/**
*   Adds a source to list of sources to query. Toggles appropriate flags and adds to qlst array.
*/
static inline struct qlst *addSrcToQlst(struct src *src, struct IfDesc *IfDp, struct qlst *qlst, uint32_t srcHash) {
    uint16_t nsrcs = qlst->nsrcs;

    // Add source to query list if required, prevent duplicates.
    if ((BIT_TST(qlst->type, 3) || IQUERY) && NOT_SET(src, lm, IfDp)
                                           && (!nsrcs || qlst->src[qlst->nsrcs - 1]->ip != src->ip)) {
        // In case source is in running query, remove it there and add to current list.
        if (IS_SET(src, qry, IfDp))
            delQuery(IfDp, NULL, NULL, src, 0);

        // Add to source to the query list. Allocate memory per 32 sources.
        LOG(LOG_DEBUG, 0, "addSrcToQlst: Adding source %s to query list for %s (%d).",
                          inetFmt(src->ip, 1), inetFmt(src->mct->group, 2), nsrcs + 1);
        if ((nsrcs & 0x1F) == 0 && ! (qlst = realloc(qlst, sizeof(struct qlst) + ((nsrcs >> 5) + 1) * 0x20 * sizeof(void *))))
            LOG(LOG_ERR, errno, "addSrcToQlst; Out of Memory.");  // Freed by startQuery() or delQuery().
        clearHash(src->dHostsHT, srcHash);
        BIT_SET(src->vifB.d, IfDp->index);
        BIT_SET(src->vifB.qry, IfDp->index);
        BIT_SET(src->vifB.lm, IfDp->index);
        src->vifB.age[IfDp->index] = qlst->misc;
        qlst->src[qlst->nsrcs++] = src;
    }
    return qlst;
}

/**
*   Process a group specific query received from other querier.
*/
void processGroupQuery(struct IfDesc *IfDp, struct igmpv3_query *query, uint16_t nsrcs, uint8_t ver) {
    struct mcTable  *mct = findGroup(query->igmp_group.s_addr, false);
    struct qlst     *qlst;
    struct src      *src;
    nsrcs = sortArr((uint32_t *)query->igmp_src, nsrcs);

    // If no group found for query, or not active on interface return.
    if (! mct || NOT_SET(mct, d, IfDp)) {
        LOG(LOG_DEBUG, 0, "processGroupQuery: Query on %s for %s, but %s.", IfDp->Name, inetFmt(query->igmp_group.s_addr, 1),
                           mct ? "not active." : "not found.");
        return;
    }

    // Initialize query list and sort array of sources in query.
    if (! (qlst = malloc(sizeof(struct qlst))))  // Freed by startQuery() or delQuery().
        LOG(LOG_ERR, errno, "processGroupQuery: Out of Memory.");
    *qlst = (struct qlst){ NULL, NULL, mct, IfDp, 0, 0,
                           query->igmp_code, ver == 3 ? query->igmp_misc & ~0x8 : IfDp->conf->qry.lmCount, 0, 0 };

    if (nsrcs == 0 && checkFilters(IfDp, 1, NULL, mct)) {
        // Only start last member aging when group is allowed on interface.
        LOG(LOG_DEBUG, 0, "processGroupQuery: Group specific query for %s on %s.", inetFmt(mct->group, 1), IfDp->Name);
        qlst->type = 6;
    } else if (nsrcs > 0) {
        LOG(LOG_DEBUG, 0, "processGroupQuery: Group group and source specific query for %s with %d sources on %s.",
                           inetFmt(mct->group, 1), nsrcs, IfDp->Name);
        qlst->type = 8;
        uint16_t i = 0;
        src        = mct->sources;
        while (src && i < nsrcs) {
            LOG(LOG_DEBUG,0,"BLABLA %s %s %d %d", inetFmt(query->igmp_src[i].s_addr, 1), inetFmt(src->ip, 2), src->vifB.d, src->vifB.lm);
            if (src->ip > query->igmp_src[i].s_addr) {
                for (; i < nsrcs && src->ip > query->igmp_src[i].s_addr; i++);
            } else if (src->ip == query->igmp_src[i].s_addr && checkFilters(IfDp, 1, src, mct)) {
                // Do not add denied sources to query list.
                qlst = addSrcToQlst(src, IfDp, qlst, (uint32_t)-1);
                i++;
                src = src->next;
            } else
                for(; src && src->ip < query->igmp_src[i].s_addr; src = src->next);
        }
    }
    startQuery(IfDp, qlst);
}

/**
*   Start a query or last member aging on interface.
*/
static inline void startQuery(struct IfDesc *IfDp, struct qlst *qlst) {
    // Check sanity of query list. Remove list if not ok (no sources for gssq, not querier on interface).
    if (!qlst->type || ( BIT_TST(qlst->type, 2) && qlst->nsrcs == 0) || (!BIT_TST(qlst->type, 3) && !IQUERY)) {
        free(qlst);  // Alloced by updateGroup(), addSrcToQlst() or processGroupQuery().
        return;
    }

    // Check if we should take over for a running GSQ.
    if (BIT_TST(qlst->type, 1) && IS_SET(qlst->mct, qry, IfDp))
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
        BIT_SET(qlst->mct->vifB.qry, IfDp->index);
        BIT_SET(qlst->mct->vifB.lm, IfDp->index);
        qlst->mct->vifB.age[IfDp->index] = qlst->misc;
    } else
        LOG(LOG_INFO, 0, "startQuery #%d: Querying %d sources for %s on %s.",
                          qC, qlst->nsrcs, inetFmt(qlst->mct->group, 1), IfDp->Name);
    groupSpecificQuery(qlst);
}

/**
*   Sends a group specific query and / or last member ages group and sources.
*   bit 0 - Router Supress flag
*   bit 1 - Group Specific Query
*   bit 2 - Group and Source Specific query
*   bit 3 - Other Querier
*/
static void groupSpecificQuery(struct qlst *qlst) {
    struct igmpv3_query *query = NULL, *query1 = NULL, *query2 = NULL;
    uint32_t            i = 0, nsrcs = qlst->nsrcs, size = sizeof(struct igmpv3_query) + nsrcs * sizeof(struct in_addr);

    // Do aging upon reentry.
    if (qlst->cnt > 0) {
        if (BIT_TST(qlst->type, 1)) {
            // Age group in case of GSQ.
            if (NOT_SET(qlst->mct, lm, qlst->IfDp)) {
                LOG(LOG_INFO, 0, "GSQ: %s no longer in last member state on %s.", inetFmt(qlst->mct->group, 1), qlst->IfDp->Name);
                BIT_SET(qlst->type, 0);  // Suppress router processing flag for next query.
                if (BIT_TST(qlst->type, 3))
                    // If aging for other querier, we're done.
                    qlst->cnt = qlst->misc;
            } else if (--qlst->mct->vifB.age[qlst->IfDp->index] == 0) {
                // Group in exclude mode has aged, switch to include.
                LOG(LOG_DEBUG, 0, "GSQ: Switch group %s to inlcude on %s after querying.",
                                  inetFmt(qlst->mct->group, 1), qlst->IfDp->Name);
                qlst->cnt = qlst->misc;  // Make sure we're done.
                if (!BIT_TST(qlst->mct->v1Bits, qlst->IfDp->index))
                    // RFC says v2 groups should not switch and age normally, but v2 hosts must respond to query, so should be safe.
                    toInclude(qlst->mct, qlst->IfDp, NULL);
            }

        } else if (BIT_TST(qlst->type, 2)) {
            // Age sources in case of GSSQ. Create two queries (1 - sources still last member 2 - active source).
            if (! (query1 = malloc(size)) || ! (query2 = malloc(size)))  // Freed by self.
                LOG(LOG_ERR, errno, "GSQ: Out of Memory.");
            *query1 = (struct igmpv3_query){ qlst->type      , qlst->code, 0, {qlst->mct->group}, qlst->misc, 0, 0 };
            *query2 = (struct igmpv3_query){ qlst->type | 0x1, qlst->code, 0, {qlst->mct->group}, qlst->misc, 0, 0 };
            while (i < qlst->nsrcs) {
                if (!BIT_SET(qlst->src[i]->vifB.lm, qlst->IfDp->index) || NOT_SET(qlst->src[i], d, qlst->IfDp)) {
                    // Source no longer in last member state.
                    LOG(LOG_INFO, 0, "GSQ: Source %s for group %s no longer in last member state on %s.",
                                      inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->mct->group, 2), qlst->IfDp->Name);
                    query2->igmp_src[query2->igmp_nsrcs++].s_addr = qlst->src[i++]->ip;
                } else if (--qlst->src[i]->vifB.age[qlst->IfDp->index] == 0) {
                    // Source expired. Remove from query list.
                    BIT_CLR(qlst->src[i]->vifB.qry, qlst->IfDp->index);
                    BIT_CLR(qlst->src[i]->vifB.lm, qlst->IfDp->index);
                    if (IS_IN(qlst->mct, qlst->IfDp)) {
                        // Aged source in include mode should be removed.
                        LOG(LOG_INFO, 0, "GSQ: Removed inactive source %s from group %s on %s.",
                                          inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->mct->group, 2), qlst->IfDp->Name);
                        delSrc(qlst->src[i], qlst->IfDp, 0, (uint32_t)-1);
                    } else
                        // In exclude mode sources should be kept.
                        LOG(LOG_INFO, 0, "GSQ: Source %s from group %s on %s expired.",
                                          inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->mct->group, 2), qlst->IfDp->Name);
                    qlst->src[i] = qlst->src[--qlst->nsrcs];
                } else
                    // Source still in last member state, add to  query.
                    query1->igmp_src[query1->igmp_nsrcs++].s_addr = qlst->src[i++]->ip;
            }
            if (BIT_TST(qlst->type, 3) && !qlst->nsrcs)
                // If aging for other querier and no sources left to age, we're done.
                qlst->cnt = qlst->misc;
        }
    }

    if (qlst->cnt++ < qlst->misc) {
        // Send a query if not aging for other querier.
        if (!BIT_TST(qlst->type, 3)) {
            if (qlst->cnt == 1 || BIT_TST(qlst->type, 1)) {
                // Use qlst in case of group query, or first group and source query.
                if (! (query = malloc(sizeof(struct igmpv3_query) + qlst->nsrcs * sizeof(struct in_addr))))
                    LOG(LOG_ERR, errno, "GSQ: Out of Memory.");
                *query = (struct igmpv3_query){ qlst->type, qlst->code, 0, {qlst->mct->group}, qlst->misc, 0, qlst->nsrcs };
                if (BIT_TST(qlst->type, 2))
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
        if (qlst->misc == qlst->cnt && (  (BIT_TST(qlst->type, 1) && NOT_SET(qlst->mct, lm, qlst->IfDp))
                                       || (BIT_TST(qlst->type, 2) && !qlst->nsrcs)))
            LOG(LOG_INFO, 0, "GSQ: done querying %s/%d on %s.", inetFmt(qlst->mct->group, 1), nsrcs, qlst->IfDp->Name);
        else {
            sprintf(msg, "GSQ (%s): %15s/%u", qlst->IfDp->Name, inetFmt(qlst->mct->group, 1), qlst->nsrcs);
            uint32_t timeout = BIT_TST(qlst->type, 3)            ? qlst->code
                             : qlst->IfDp->querier.ver == 3      ? getIgmpExp(qlst->IfDp->conf->qry.lmInterval, 0)
                             : qlst->IfDp->conf->qry.lmInterval;
            qlst->tid = timer_setTimer(TDELAY(timeout), msg, (timer_f)groupSpecificQuery, qlst);
        }
    } else if (qlst->cnt >= qlst->misc) {
        // Done querying. Remove current querier from list and delete the group if IS_IN no sources, or update upstream status.
        LOG(LOG_INFO, 0, "GSQ: done querying %s/%d on %s.", inetFmt(qlst->mct->group, 1), nsrcs, qlst->IfDp->Name);
        if (!qlst->mct->mode && !qlst->mct->nsrcs)
            delGroup(qlst->mct, qlst->IfDp, NULL, 1);
        else
            delQuery(qlst->IfDp, qlst, NULL, NULL, 0);
    }

    free(query1);  // Alloced by self.
    free(query2);  // Alloced by self.
}

/**
*   Removes all active queriers specified by parameters.
*/
void delQuery(struct IfDesc *IfDp, void *qry, void *_mct, void *_src, uint8_t type) {
    struct qlst     *ql   = qry ? qry : qL;
    struct mcTable  *mct = qry ? ql->mct : _mct;
    struct src      *src  = _src;
    LOG(LOG_INFO, 0, "delQry: Removing quer%s%s%s%s on %s.", qry || src ? "y" : "ies",
                      mct || src ? " for " : "", src ? inetFmt(src->ip, 1) : "",
                      mct ? inetFmt(mct->group, 2) : "", IfDp->Name);
    while (ql) {
        struct qlst *nql = qry ? NULL : ql->next;
        // Find all queriers for interface, group and type.
        if (ql->IfDp == IfDp && ((! mct || ql->mct == mct) && (!type || type == (ql->type & ~0x1)))) {
            if (src) {
                // Find and remove source from all queries.
                uint16_t i;
                for (i = 0; ql && i < ql->nsrcs && ql->src[i] != src; i++);
                if (ql && i < ql->nsrcs) {
                    LOG(LOG_NOTICE, 0, "Existing query for source %s in group %s on %s.",
                                        inetFmt(ql->src[i]->ip, 1), inetFmt(ql->mct->group, 2), ql->IfDp->Name);
                    ql->src[i] = ql->src[--ql->nsrcs];
                }
            } else if (BIT_TST(ql->type, 1) || BIT_TST(ql->type, 4)) {
                // Clear last member and query bits for group.
                BIT_CLR(ql->mct->vifB.lm, IfDp->index);
                BIT_CLR(ql->mct->vifB.qry, IfDp->index);
            } else
                // Clear last member and query bits for sources.
                for (uint16_t i = 0; i < ql->nsrcs; BIT_CLR(ql->src[i]->vifB.lm, IfDp->index),
                                                    BIT_CLR(ql->src[i]->vifB.qry, IfDp->index), i++);
            // Unlink from query list and free qlst.
            if (! src || (!ql->nsrcs && (BIT_TST(ql->type, 2) || BIT_TST(ql->type,5)))) {
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
inline void activateRoute(struct IfDesc *IfDp, void *_src, register uint32_t ip, register uint32_t group, bool activate) {
    struct src      *src = _src;
    struct mcTable  *mct = src ? src->mct : findGroup(group, false);
    if (! mct) {
        LOG(LOG_DEBUG, 0, "activateRoute: Group %s not found, ignoring activation.", inetFmt(ip, 1), inetFmt(group, 2));
        return;
    }

    if (activate) {
        // Find source or create source in group when new should be created.
        if (! src) {
            for (src = mct->sources; src && src->ip < ip; src = src->next);
            if ((! src || src->ip > ip) && ! (src = addSrc(IfDp, mct, ip, false, false, src, (uint32_t)-1))) {
                LOG(LOG_WARNING, 0, "Unable to activate route: %s to %s on %s. Cannot create source.",
                                     inetFmt(ip, 1), inetFmt(group, 2), IfDp->Name);
                return;
            }
        }

        if (mct->mode && IS_SET(mct, u, IfDp) && !checkFilters(IfDp, 0, src, mct)) {
            if (NOT_SET(src, us, IfDp)) {
                LOG(LOG_NOTICE, 0, "Explicitely blocking denied source %s for group %s on upstream interface %s.",
                                    inetFmt(src->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
                if (k_updateGroup(IfDp, true, mct->group, 1, src->ip))
                    BIT_SET(src->vifB.us, IfDp->index);
            }
            return;
        }

        // Create and initialize an upstream source for new sender.
        if (! src->mfc) {
            struct mfc *nmfc;
            if (! (src->mfc = nmfc = malloc(sizeof(struct mfc))))
                LOG(LOG_ERR, errno, "activateRoute: Out of Memory!");  // Freed by Self.
            *nmfc = (struct mfc){ NULL, NULL, {0, 0}, src, IfDp, 0, 0 };
            clock_gettime(CLOCK_REALTIME, &nmfc->stamp);
            if (mct->mfc) {
                nmfc->next = mct->mfc;
                mct->mfc->prev = nmfc;
            }
            mct->mfc = nmfc;
        }
    }

    LOG(LOG_INFO, 0, "activateRoute: %s for src: %s to group: %s on VIF %s (%d)", activate ? "Activation" : "Deactivation", 
                      inetFmt(src->ip, 1), inetFmt(src->mct->group, 2), src->mfc->IfDp->Name, src->mfc->IfDp->index);
    LOG(LOG_DEBUG, 0, "Vif bits: 0x%08x", src->mct->vifB.d);

    if (activate) {
        // Install or update kernel MFC. See RFC 3376: 6.3 IGMPv3 Source-Specific Forwarding Rules.
        uint8_t ttlVc[MAXVIFS] = {0};
        GETIFLIF(IfDp, IS_DOWNSTREAM(IfDp->state) && IS_SET(mct, d, IfDp)) {
            if (!checkFilters(IfDp, 1, src, mct))
                LOG(LOG_NOTICE, 0, "Not forwarding denied source %s to group %s on %s.", inetFmt(src->ip,1),
                                    inetFmt(mct->group, 2), IfDp->Name);
            else if ((   (IS_IN(mct, IfDp) && !noHash(src->dHostsHT) && IS_SET(src, d, IfDp) && src->vifB.age[IfDp->index] > 0)
                      || (IS_EX(mct, IfDp) && !noHash(mct->dHostsHT) && (NOT_SET(src, d, IfDp) || src->vifB.age[IfDp->index] > 0))))
                ttlVc[IfDp->index] = IfDp->conf->threshold;
            LOG(LOG_DEBUG, 0, "activateRoute: Setting TTL for Vif %s (%d) to %d", IfDp->Name, IfDp->index, ttlVc[IfDp->index]);
        }
        k_addMRoute(src->ip, mct->group, src->mfc->IfDp->index, ttlVc);
    } else {
        // Remove kernel MFC and delete the upstream source.
        k_delMRoute(src->ip, mct->group, src->mfc->IfDp->index);
        if (src->mfc->next)
            src->mfc->next->prev = src->mfc->prev;
        if (src->mfc->prev)
            src->mfc->prev->next = src->mfc->next;
        if (mct->mfc == src->mfc)
            mct->mfc = src->mfc->next;
        free(src->mfc);   // Alloced by Self
        src->mfc = NULL;
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
        if (IS_SET(imc->mct, lm, IfDp))
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
        struct src *src  = imc->mct->sources;
        while (src) {
            if (NOT_SET(src, lm, IfDp)) {
                if (src->vifB.age[IfDp->index] == 0 && (IS_SET(src, dd, IfDp) || (IS_IN(imc->mct, IfDp) && IS_SET(src, d, IfDp))
                                                         || (IS_EX(imc->mct, IfDp) && NOT_SET(src, d, IfDp) && ! imc->mct->mfc))) {
                    LOG(LOG_INFO, 0, "ageGroups: Removed source %s from %s on %s after aging.",
                                      inetFmt(src->ip, 1), inetFmt(imc->mct->group, 2), IfDp->Name);
                    src = delSrc(src, IfDp, 0, (uint32_t)-1);
                    continue;
                } else if (src->vifB.age[IfDp->index] > 0)
                    src->vifB.age[IfDp->index]--;
            }
            src = src->next;
        }

        // Next age group.
        if (IS_EX(imc->mct, IfDp) && NOT_SET(imc->mct, dd, IfDp) && imc->mct->vifB.age[IfDp->index] == 0
                                  && !BIT_TST(imc->mct->v1Bits, IfDp->index))
            imc = toInclude(imc->mct, IfDp, imc);
        if ((IS_IN(imc->mct, IfDp) && !imc->mct->nsrcs) || (IS_SET(imc->mct, dd, IfDp) && imc->mct->vifB.age[IfDp->index] == 0)) {
            LOG(LOG_INFO, 0, "ageGroups: Removed group %s from %s after aging.", inetFmt(imc->mct->group, 2), IfDp->Name);
            imc = delGroup(imc->mct, IfDp, imc, 1);
            continue;
        } else if (imc->mct->vifB.age[IfDp->index] > 0)
            imc->mct->vifB.age[IfDp->index]--;
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
                LOG(LOG_DEBUG, 0, msg, rcount, mfc ? inetFmt(mfc->src->ip, 1) : "-", inetFmt(mct->group, 2), mfc ? IfDp->Name : "", mct->vifB.d, ! CONFIG->fastUpstreamLeave || !mct->mode ? "not tracked" : noHash(mct->dHostsHT) ? "no" : "yes", mfc ? mfc->bytes : 0, mfc ? mfc->rate : 0);
            } else {
                sprintf(buf, strcat(msg, "\n"), rcount, mfc ? inetFmt(mfc->src->ip, 1) : "-", inetFmt(mct->group, 2), mfc ? IfDp->Name : "", mct->vifB.d, ! CONFIG->fastUpstreamLeave || !mct->mode ? "not tracked" : noHash(mct->dHostsHT) ? "no" : "yes", mfc ? mfc->bytes : 0, mfc ? mfc->rate : 0);
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
