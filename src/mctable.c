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
*   mctable.c
*   Maintains IGMP group and source membership state and kernel multicast routes.
*/

#include "igmpv3proxy.h"
#include "mctable.h"

static inline bool        addGroup(struct mcTable* mct, struct IfDesc *IfDp, int dir, int mode, uint32_t srcHash);
static inline struct src *addSrc(struct IfDesc *IfDp, struct mcTable *mct, uint32_t ip, int dir, int mode, bool join,
                                 struct src *src, uint32_t srcHash);
static uint64_t           getGroupBw(struct subnet group, struct IfDesc *IfDp);
static inline void        quickLeave(struct mcTable *mct, uint32_t ip);
static void               updateSourceFilter(struct mcTable *mct, int mode);
void                      ageUnknownGroup(struct ifMct *imc);
#define QUICKLEAVE(x,y)   if (IfDp->conf->quickLeave) quickLeave(x,y)

// Multicast group membership tables.
static struct mcTable **MCT = NULL;

/**
*   Private access function to find a given group in MCT, creates new if required.
*/
struct mcTable *findGroup(register uint32_t group, bool create) {
    struct mcTable *mct, *nmct;
    uint32_t        mctHash = murmurhash3(group) % CONF->mcTables;

    // Initialize the routing tables if necessary.
    if (! MCT && !create)
        return NULL;
    if (! MCT)
        _calloc(MCT, 1, mct, MCTSZ);   // Freed by delGroup())
    for (mct = MCT[mctHash];; mct = mct->next) {
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
    // Create and initialize the new MCT entry.
    LOG(LOG_INFO, 0, "Create new group %s in table %d.", inetFmt(group, 0), mctHash);
    _calloc(nmct, 1, mct, MCESZ);   // Freed by delGroup()
    nmct->group = group;
    clock_gettime(CLOCK_REALTIME, &(nmct->stamp));
    nmct->stamp.tv_nsec = (intptr_t)NULL;
    if (! MCT[mctHash] || MCT[mctHash]->group > group) {
        MCT[mctHash] = nmct;
        if (mct) {
            mct->prev = nmct;
            nmct->next = mct;
        }
    } else {
        nmct->prev = mct;
        nmct->next = mct->next;
        if (nmct->next)
            nmct->next->prev = nmct;
        mct->next = nmct;
    }

    return nmct;
}

/**
*  Adds a group to an interface. All downstream requested groups will be attached to interface,
*  whether denied or allowed. Denied exclude mode groups will age so that reference to permissions
*  can be kept for as long as the group is being requested on the interface.
*/
static inline bool addGroup(struct mcTable* mct, struct IfDesc *IfDp, int dir, int mode, uint32_t srcHash) {
    struct ifMct  *imc, **list = (struct ifMct **)(dir == 1 ? &IfDp->dMct : &IfDp->uMct);
    uint32_t       group = mct->group;

    if (dir ? NOT_SET(mct, d, IfDp) : NOT_SET(mct, u, IfDp)) {
        _malloc(imc, ifm, IFMSZ);   // Freed by delGroup()
        *imc = (struct ifMct){ NULL, IfDp, mct, *list };
        if (*list)
            (*list)->prev = imc;
        *list = imc;
    }
    if (dir == 3)
        return BIT_SET(mct->vifB.u, IfDp->index);
    if (dir && mode && BIT_SET(mct->mode, IfDp->index)) {
        // Exclude mode group, reset last member state and set age to GMI. We also age denied groups.
        BIT_CLR(mct->vifB.lm, IfDp->index);
        mct->vifB.age[IfDp->index] = IfDp->querier.qrv;  // Group timer = GMI
    }
    if (!dir && BIT_SET(mct->vifB.u, IfDp->index) && !checkFilters(IfDp, dir, NULL, mct)) {
        // Check if group is allowed upstream on interface.
        LOG(LOG_NOTICE, 0, "Not joining denied group %s on %s.", inetFmt(mct->group, 0), IfDp->Name);
        return false;
    } else if (dir) {
        if (mct->stamp.tv_nsec) {
            imc = (void *)timerClear((intptr_t)mct->stamp.tv_nsec, true);
            delGroup(imc->mct, imc->IfDp, imc, 3);
        }
        BIT_SET(mct->vifB.d, IfDp->index);
        SET_HASH(mct->dHostsHT, srcHash);
        IF_GETVIFL_IF((mct->vifB.uj | mct->vifB.ud) != uVifs, IfDp, IS_UPSTREAM(IfDp->state) && NOT_SET(mct, uj, IfDp))
            // Check if any upstream interfaces still need to join the group.
            addGroup(mct, IfDp, 0, 1, (uint32_t)-1);
    } else {
        // Set upstream status and join group if it is in exclude mode upstream.
        BIT_SET(mct->vifB.u, IfDp->index);
        if (mct->mode && IfDp->conf->bwControl > 0 && IfDp->conf->ratelimit > 0 && IfDp->stats.iRate > IfDp->conf->ratelimit)
            LOG(LOG_NOTICE, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.",
                IfDp->Name, IfDp->stats.iRate, IfDp->conf->ratelimit, inetFmt(mct->group, 0));
        else if (mct->mode &&
                (((mct->vifB.uj | mct->vifB.ud) != uVifs) && k_updateGroup(IfDp, true, mct->group, 1, (uint32_t)-1))) {
            BIT_SET(mct->vifB.uj, IfDp->index);
            LOG(LOG_INFO, 0, "Joined group %s upstream on interface %s.", inetFmt(mct->group, 0), IfDp->Name);
        }
    }

    logRouteTable("Add Group", 1, -1, group, (uint32_t)-1, NULL);
    return true;
}

/**
*   Remove a specified MCT from interface.
*/
struct ifMct *delGroup(struct mcTable* mct, struct IfDesc *IfDp, struct ifMct *_imc, int dir) {
    struct ifMct  *imc = _imc, *pimc = NULL, **list = (struct ifMct **)(dir == 1 ? &IfDp->dMct : &IfDp->uMct);
    struct IfDesc *If;
    struct src    *src;
    uint32_t       group = mct->group, iz;
    static bool    remove = false;
    LOG(LOG_DEBUG, 0, "Removing %s group %s from %s.", dir == 1 ? "downstream" : "upstream", inetFmt(mct->group, 0), IfDp->Name);

    // Update the interface group list.
    IF_FOR(! imc, (imc = *list; imc && imc->mct != mct; imc = imc->next));
    pimc = imc->prev;
    if (imc->next)
        imc->next->prev = imc->prev;
    if (imc->prev)
        imc->prev->next = imc->next;
    else
        *list = imc->next;
    _free(imc, ifm, IFMSZ);  // Alloced by addGroup()
    if (dir > 1) {
        BIT_CLR(mct->vifB.u, IfDp->index);
        return pimc;
    }

    if (!dir) {
        // Leave exclude mode group upstream and clear upstream status.
        if (IS_SET(mct, uj, IfDp)) {
            LOG(LOG_INFO, 0, "Leaving group %s upstream on interface %s.", inetFmt(mct->group, 0), IfDp->Name);
            k_updateGroup(IfDp, false, mct->group, 0, (uint32_t)-1);
        }
        BIT_CLR(mct->vifB.u, IfDp->index);
        BIT_CLR(mct->vifB.su, IfDp->index);
        BIT_CLR(mct->vifB.ud, IfDp->index);
        BIT_CLR(mct->vifB.uj, IfDp->index);
        for (src = mct->sources; src; src = src->next) {
            BIT_CLR(src->vifB.ud, IfDp->index);
            BIT_CLR(src->vifB.su, IfDp->index);
            BIT_CLR(src->vifB.uj, IfDp->index);
            if (src->mfc && src->mfc->IfDp == IfDp)
                activateRoute(IfDp, src, src->ip, mct->group, false);
        }
    } else if (mct->vifB.d) {
        // Clear group membership from downstream interface.
        BIT_CLR(mct->vifB.d, IfDp->index);
        // Clear interface and sources flags and Update kernel route if group still active on other interface.
        BIT_CLR(mct->vifB.sd, IfDp->index);
        BIT_CLR(mct->vifB.dd, IfDp->index);
        BIT_CLR(mct->vifB.qry, IfDp->index),
        BIT_CLR(mct->vifB.lm, IfDp->index);
        BIT_CLR(mct->mode, IfDp->index);
        BIT_CLR(mct->v1Bits, IfDp->index);
        BIT_CLR(mct->v2Bits, IfDp->index);
        mct->vifB.age[IfDp->index] = mct->v1Age[IfDp->index] = mct->v2Age[IfDp->index] = 0;
        for (src = mct->sources; src;
             BIT_CLR(src->vifB.dd, IfDp->index), BIT_CLR(src->vifB.sd, IfDp->index),
             src = delSrc(src, IfDp, 0, true, (uint32_t)-1));
    }
    if (!remove && !mct->vifB.d) {
        remove = true;
        // No clients downstream, group can be removed from table.
        uint32_t mctHash = murmurhash3(mct->group) % CONF->mcTables;
        LOG(LOG_INFO, 0, "Deleting group %s from table %d.",inetFmt(mct->group, 0), mctHash);
        if (IS_SET(mct, qry, IfDp))
            delQuery(IfDp, NULL, mct, NULL);
        if (mct->stamp.tv_nsec)
            timerClear((intptr_t)mct->stamp.tv_nsec, true);
        // If deleting group downstream Send Leave requests and remove group upstream. If deleting upstream remove downstream.
        GETVIFL_IF(If, dir ? IS_SET(mct, u, If) : IS_SET(mct, d, If))
            delGroup(mct, If, NULL, !dir);
        // Remove all sources from group.
        for (struct src *src = mct->sources; src; src = delSrc(src, IfDp, 0, true, (uint32_t)-1));
        // Update MCT and check if all tables are empty.
        if (mct->next)
            mct->next->prev = mct->prev;
        if (mct != MCT[mctHash])
            mct->prev->next = mct->next;
        else if (! (MCT[mctHash] = mct->next)) {
            for (iz = 0; iz < CONF->mcTables && ! MCT[iz]; iz++);
            if (iz == CONF->mcTables) {
                LOG(LOG_DEBUG, 0, "Multicast table is empty.");
                _free(MCT, mct, MCTSZ);  // Alloced by findGroup()
            }
        }
        _free(mct, mct, MCESZ); // Alloced by findGroup()
        remove = false;
    }

    if (MCT)
        logRouteTable("Remove Group", 1, -1, group, (uint32_t)-1, NULL);
    return pimc;
}

/**
*   Creates a new source for group and adds it to list of sources. Doubly linked list
*   with prev of fist pointing to last item in queue. We will be called from updateGroup()
*   which as it evaluates the list in linear order knows exactly where source should be
*   created in list, no src if it should go to end of list.
*/
static inline struct src *addSrc(struct IfDesc *IfDp, struct mcTable *mct, uint32_t ip, int dir, int mode, bool join,
                                 struct src *src, uint32_t srcHash) {
    if (! src || src->ip != ip) {
        // New source should be created, increase nrsrcs.
        struct src *nsrc;
        if (++mct->nsrcs > IfDp->conf->maxOrigins && IfDp->conf->maxOrigins) {
            // Check if maxorigins is exceeded.
            if (!(mct->nsrcs & 0x80000000)) {
                mct->nsrcs |= 0x80000000;
                LOG(LOG_WARNING, 0, "Max origins (%d) exceeded for %s.", CONF->maxOrigins, inetFmt(mct->group, 0));
            }
            return NULL;
        }
        LOG(LOG_DEBUG, 0, "New source %s (%d) for group %s.", inetFmt(ip, 0), mct->nsrcs, inetFmt(mct->group, 0));
        _calloc(nsrc, 1, src, SRCSZ);  // Freed by delSrc()
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
    }
    if (dir) {
        // Set source bits and age, update MFC if present. When source is denied, we still do aging.
        if (NOT_SET(src, d, IfDp) && BIT_SET(src->vifB.d, IfDp->index) && src->mfc)
            // Activate route will check ACL for source on downstream interfaces.
            activateRoute(src->mfc->IfDp, src, src->ip, mct->group, true);
        if (!mode) {
            // Source requested in exclude mode.
            BIT_CLR(src->vifB.lm, IfDp->index);
            src->vifB.age[IfDp->index] = IfDp->querier.qrv;
            SET_HASH(src->dHostsHT, srcHash);
        }
        IF_GETVIFL_IF(join && ((src->vifB.ud | src->vifB.uj) != uVifs), IfDp, IS_UPSTREAM(IfDp->state))
            joinBlockSrc(src, IfDp, true);
    }
    return src;
}

/**
*   Removes a source from the list of group sources. When group is in exclude mode, sources requested in include
*   mode will not be fully removed for ACL / host tracking purposes (mode = 1 or mode = 2).
*   When switching from upstream filter mode, sources will not be left here, because updateSourceFilter
*   will atomically switch filter mode (mode = 2 or mode = 3).
*/
struct src *delSrc(struct src *src, struct IfDesc *IfDp, int mode, bool leave, uint32_t srcHash) {
    struct IfDesc  *If;
    struct src     *nsrc = src->next;
    struct mcTable *mct  = src->mct;

    // Remove the source if it is not actively being queried and not active on other vifs.
    LOG(LOG_DEBUG, 0, "Remove source %s (%d) from %s on %s.", inetFmt(src->ip, 0), mct->nsrcs, inetFmt(mct->group, 0), IfDp->Name);

    // Remove source from hosts hash table, and clear vifbits.
    if (IS_SET(src, qry, IfDp))
        delQuery(IfDp, NULL, src->mct, src);
    CLR_HASH(src->dHostsHT, srcHash);
    BIT_CLR(src->vifB.d, IfDp->index);
    BIT_CLR(src->vifB.lm, IfDp->index);
    src->vifB.age[IfDp->index] = 0;
    if (leave && (!src->vifB.d || (!mct->mode && src->vifB.d == src->vifB.dd) || (mct->mode && src->vifB.d != mct->mode)))
        // Source should not be left / unblocked when switching upstream filter mode.
        // Leave Source if not active on any interfaces in include mode.
        // Unblock source if it is no longer excluded on all exclude mode interfaces
        // or included on any include mode interface.
        GETVIFL_IF(If, IS_SET(src, uj, If))
            joinBlockSrc(src, If, false);
    if (src->mfc && IS_IN(mct, IfDp))
        // MFC for group in include mode on all interface must be removed if no more listeners downstream.
        // Unrequested sending source must no longer be forwarded to include mode interface, update MFC.
        activateRoute(src->mfc->IfDp, src, src->ip, mct->group, mct->mode);
    if (!src->vifB.d) {
        if (mode == 0 && ! src->mfc) {
            // Remove the source if there are no senders and it was not requested by include mode host.
            mct->nsrcs--;
            if (CONF->maxOrigins && (mct->nsrcs & 0x80000000) && (mct->nsrcs & ~0x80000000) < CONF->maxOrigins) {
                // Reset maxorigins exceeded flag.
                LOG(LOG_INFO, 0, "Maxorigins reset for group %s.", inetFmt(src->mct->group, 0));
                mct->nsrcs &= ~0x80000000;
            }
            if (src->next)
                src->next->prev = src->prev;
            if (src == mct->sources->prev)
                mct->sources->prev = src->prev;
            if (src != mct->sources)
                src->prev->next = src->next;
            else
                mct->sources = src->next;
            _free(src, src, SRCSZ);  // Alloced by addSrc()
            }
    }

    return nsrc;
}

/**
*   Join or leave (IN, join) or block or unblock (EX, !join) the source upstream if necessary.
*   Block the souce upstream only if it is in exclude mode on all exclude mode interfaces.
*/
inline void joinBlockSrc(struct src *src, struct IfDesc *IfDp, bool join) {
    if (join && !src->mct->mode && IS_SET(src, uj, IfDp) && NOT_SET(src, su, IfDp) && !checkFilters(IfDp, 0, src, src->mct)) {
        // If source was joined upstream and acl changed, leave and remove route.
        LOG(LOG_NOTICE, 0, "Source %s from group %s no longer allowed upstream on %s.",
            inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name);
        joinBlockSrc(src, IfDp, false);
        if (src->mfc) {
            src->vifB.u = 0;
            activateRoute(src->mfc->IfDp, src, src->ip, src->mct->group, false);
        }
    } else if (join && NOT_SET(src, uj, IfDp) && (!src->mct->mode || src->vifB.d == src->mct->mode)) {
        uint32_t i;
        for (i = 0; src->mct->mode && i < MAXVIFS && (!BIT_TST(src->vifB.d, i) || src->vifB.age[i] == 0); i++);
        if (!src->mct->mode && (!src->vifB.d || !checkFilters(IfDp, 0, src, src->mct)))
            LOG(!src->vifB.d ? LOG_INFO : LOG_NOTICE, 0, "%s%s from group %s%s.",
                !src->vifB.d ? "No downstream listeners for source " : "Source ", inetFmt(src->ip, 0),
                inetFmt(src->mct->group, 0), !src->vifB.d ? ", not joining upstream on " : " denied upstream on " , IfDp->Name);
        else if ((!src->mct->mode || i >= MAXVIFS || !checkFilters(IfDp, 0, src, src->mct))
                    && k_updateGroup(IfDp, true, src->mct->group, src->mct->mode, src->ip)) {
            LOG(LOG_INFO, 0, "%s source %s from group %s on upstream interface %s.",
                src->mct->mode ? "Blocked" : "Joined", inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name);
            BIT_SET(src->vifB.uj, IfDp->index);
        }
    } else if (!join && src->mct->mode &&!checkFilters(IfDp, 0, src, src->mct)){
        // Source should not be unblocked when upstream mode is exclude and source is not allowed.
        LOG(LOG_NOTICE, 0, "Not unblocking denied source %s from group %s upstream on %s.", inetFmt(src->ip, 0),
            inetFmt(src->mct->group, 0), IfDp->Name);
    } else if (!join && IS_SET(src, uj, IfDp)) {
        LOG(LOG_INFO, 0, "%s source %s from group %s upstream on %s", src->mct->mode ? "Unblocking" : "Leaving",
            inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name);
        if (k_updateGroup(IfDp, false, src->mct->group, src->mct->mode, src->ip))
            BIT_CLR(src->vifB.uj, IfDp->index);
        if (src->mfc && src->mct->mode)
            // If source was unblocked upstream, traffic must now be forwarded, update MFC.
            activateRoute(src->mfc->IfDp, src, src->ip, src->mct->group, true);
    }
}

/**
*   Check if a group can be left upstream, because no more listeners downstream.
*/
static inline void quickLeave(struct mcTable *mct, uint32_t ip) {
    struct IfDesc * IfDp;
    IF_GETVIFL_IF(mct->vifB.uj && noHash(mct->dHostsHT), IfDp, IfDp->conf->quickLeave && IS_SET(mct, uj, IfDp)) {
        // Quickleave group upstream is last downstream host was detected.
        LOG(LOG_INFO, 0, "Group %s on %s. Last downstream host %s.", inetFmt(mct->group, 0), IfDp->Name, inetFmt(ip, 0));
        delGroup(mct, IfDp, NULL, 0);
    }
}

/**
*   Calculates bandwidth fo group/subnet filter.
*/
static uint64_t getGroupBw(struct subnet group, struct IfDesc *IfDp) {
    struct mcTable    *mct;
    struct mfc        *mfc;
    register uint64_t  bw = 0;

    // Go over all groups and calculate combined bandwidth for subnet/mask.
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
*   Bandwidth control processing for BSD systems.
*/
void processBwUpcall(struct bw_upcall *bwUpc, int nr) {
    // Process all pending BW_UPCALLS.
    for (int i = 0; i < nr; i++, bwUpc++) {
        struct IfDesc  *IfDp;
        struct mfc     *mfc = NULL;
        struct mcTable *mct = findGroup(bwUpc->bu_dst.s_addr, false);
        if (! mct)
            LOG(LOG_NOTICE, 0, "BW_UPCALL: Src %s, Dst %s, but no group found.",
                inetFmt(bwUpc->bu_dst.s_addr, 0), inetFmt(bwUpc->bu_dst.s_addr, 0));
        else
            // Find the source for the upcall and add to counter.
            for (mfc = mct->mfc; mfc && mfc->src->ip != bwUpc->bu_src.s_addr; mfc = mfc->next);

        if (mfc) {
            mfc->bytes += bwUpc->bu_measured.b_bytes;
            mfc->rate = bwUpc->bu_measured.b_bytes / CONF->bwControl;
            LOG(LOG_DEBUG, 0, "Added %lld bytes to Src %s Dst %s, total %lldB (%lld B/s)",
                bwUpc->bu_measured.b_bytes, inetFmt(mfc->src->ip, 0), inetFmt(mct->group, 0), mfc->bytes, mfc->rate);
            GETIFL_IF(IfDp, IfDp == mfc->IfDp || IS_SET(mct, d, IfDp)) {
                // Find the incoming and outgoing interfaces and add to counter.
                IfDp->stats.oBytes += bwUpc->bu_measured.b_bytes;
                LOG(LOG_DEBUG, 0, "Added %lld bytes to interface %s (%lld B/s), total %lld.",
                    bwUpc->bu_measured.b_bytes, IfDp->Name, IfDp->stats.oRate, IfDp->stats.oBytes);
            }
        }
    }
}
#endif

/**
*   Process all S,G counters and calculate interface rates.
*/
void bwControl(struct IfDesc *IfDp) {
    struct ifMct    *imc;
    struct mfc      *mfc;
    clock_gettime(CLOCK_REALTIME, &curtime);

    // Reset interface rate.
    IfDp->stats.iRate = IfDp->stats.oRate = 0;
    // Go over all upstream interface groups and sources and get the bandwidth used.
    for(imc = IfDp->uMct; imc && imc->mct; imc = imc->next) for (mfc = imc->mct->mfc; mfc; mfc = mfc->next) {
        // On Linux get the S,G statistics via ioct. On BSD they are processed by processBwUpcall().
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
        struct sioc_sg_req siocReq = { {mfc->src->ip}, {imc->mct->group}, 0, 0, 0 };
        if (ioctl(MROUTERFD, SIOCGETSGCNT, (void *)&siocReq, sizeof(siocReq))) {
            LOG(LOG_WARNING, 1, "BW_CONTROL: ioctl failed.");
            continue;
        }
        uint64_t bytes = siocReq.bytecnt - mfc->bytes;
        mfc->bytes += bytes;
        mfc->rate = bytes / IfDp->conf->bwControl;
        LOG(LOG_DEBUG, 0, "Added %lld bytes to Src %s Dst %s (%lld B/s), total %lld.",
            bytes, inetFmt(mfc->src->ip, 0), inetFmt(imc->mct->group, 0), mfc->rate, mfc->bytes);
#else
        // On FreeBSD systems the bw of the interface is the combined bw of all groups on that interface.
        LOG(LOG_DEBUG, 0, "Added %lld B/s to interface %s (%lld B/s), total %lld.",
            mfc->rate, IfDp->Name, IfDp->stats.iRate, IfDp->stats.iBytes);
#endif
    }
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
    // On Linux get the interface stats via ioctl.
    struct sioc_vif_req siocVReq = { IfDp->index, 0, 0, 0, 0 };
    if (ioctl(MROUTERFD, SIOCGETVIFCNT, (void *)&siocVReq, sizeof(siocVReq)))
        LOG(LOG_WARNING, 1, "BW_CONTROL: ioctl failed.");
    else for (int i = 0; i < 2; i++) {
        uint64_t bytes = (i == 0 ? siocVReq.ibytes : siocVReq.obytes) - (i == 0 ? IfDp->stats.iBytes : IfDp->stats.oBytes);
        if (i == 0) {
            IfDp->stats.iBytes += bytes;
            IfDp->stats.iRate = bytes / IfDp->conf->bwControl;
        } else {
            IfDp->stats.oBytes += bytes;
            IfDp->stats.oRate = bytes / IfDp->conf->bwControl;
        }
        LOG(LOG_DEBUG, 0, "Added %lld bytes to %s interface %s (%lld B/s), total %lld.",
            bytes, i== 0 ? "upstream" : "downstream", IfDp->Name, i == 0 ? IfDp->stats.iRate : IfDp->stats.oRate,
            i == 0 ? IfDp->stats.iBytes : IfDp->stats.oBytes);
    }
#endif

    // Set next timer;
    IfDp->bwTimer = timerSet(IfDp->conf->bwControl * 10, strFmt(1, "Bandwidth Control: %s", "", IfDp->Name), bwControl, IfDp);
}

/**
*  ACL evaluation. Returns whether group/src is allowed on interface.
*  dir: 0 = upstream, 1 = downstream
*  Keep access status in permission bits .sd or .su means group access is known.
*  When dd or us is set means group is denied, when not set group is allowed.
*/
bool checkFilters(struct IfDesc *IfDp, int dir, struct src *src, struct mcTable *mct) {
    if (IfDp->filCh) {
        // ACL change due to config reload, reset permission bits so access is rechecked.
        dir ? BIT_CLR(mct->vifB.dd, IfDp->index) : BIT_CLR(mct->vifB.ud, IfDp->index);
        for (src = mct->sources; src; src = src->next)
            dir ? (BIT_CLR(src->vifB.sd, IfDp->index), BIT_CLR(src->vifB.dd, IfDp->index)), BIT_CLR(src->vifB.u, IfDp->index)
                : (BIT_CLR(src->vifB.su, IfDp->index), BIT_CLR(src->vifB.ud, IfDp->index));
    } else if (src ? (dir ? IS_SET(src, sd, IfDp) : IS_SET(src, su, IfDp)) : (dir ? IS_SET(mct, sd, IfDp) : IS_SET(mct, su, IfDp))) 
        // If permissions are known return whether allowed or denied. Proceed to check filters if not.
        return src ? (dir ? NOT_SET(src, dd, IfDp) : NOT_SET(src, ud, IfDp))
                   : (dir ? NOT_SET(mct, dd, IfDp) : NOT_SET(mct, ud, IfDp));
    // Set known permission bit for source or group, and check access.
    src ? (dir ? BIT_SET(src->vifB.sd, IfDp->index) : BIT_SET(src->vifB.su, IfDp->index))
        : (dir ? BIT_SET(mct->vifB.sd, IfDp->index) : BIT_SET(mct->vifB.su, IfDp->index));
    LOG(LOG_DEBUG, 0, "Checking %s access for %s%s%s on %s interface %s.", dir ? "downstream" : "upstream",
        src ? inetFmt(src->ip, 0) : "", src ? ":" : "", inetFmt(mct->group, 0),
        IS_UPDOWNSTREAM(IfDp->state) ? "updownstream" : IS_DOWNSTREAM(IfDp->state) ? "downstream" : "upstream", IfDp->Name);
    // Filters are processed top down until a definitive action (BLOCK or ALLOW) is found.
    // The default action when no filter applies is block.
    struct filters *filter;
    for (filter = IfDp->conf->filters; filter && ((dir ? !IS_DOWNSTREAM(filter->dir) : !IS_UPSTREAM(filter->dir))
            || !(src ? ((src->ip & filter->src.mask) == filter->src.ip && (mct->group & filter->dst.mask) == filter->dst.ip)
                     : ((mct->group & filter->dst.mask) == filter->dst.ip && filter->action))); filter = filter->next);
    if (! filter || !filter->action)
        // When denied set denied bit for source or group.
        src ? (dir ? BIT_SET(src->vifB.dd, IfDp->index) : BIT_SET(src->vifB.ud, IfDp->index))
            : (dir ? BIT_SET(mct->vifB.dd, IfDp->index) : BIT_SET(mct->vifB.ud, IfDp->index));

    return filter && filter->action;
}

/**
*   Updates source filter for a group on an upstream interface when filter mode changes.
*/
static void updateSourceFilter(struct mcTable *mct, int mode) {
    struct IfDesc * IfDp;
    GETVIFL_IF(IfDp, IS_SET(mct, u, IfDp)) {
        uint32_t    nsrcs = 0, *slist = NULL, i;
        struct src *src;
        // Build source list for upstream interface.
        _malloc(slist, var, ((mct->nsrcs & ~0x80000000) + 1) * sizeof(uint32_t));  // Freed by self
        for (nsrcs = 0, src = mct->sources; src; src = src->next) {
            BIT_CLR(src->vifB.uj, IfDp->index);
            if (mode == MCAST_INCLUDE) {
                if (!src->vifB.d || NO_HASH(src->dHostsHT)) {
                    // IN: Do not add sources with no listeners.
                    LOG(LOG_INFO, 0, "No downstream hosts %s:%s on %s, not adding to source list.",
                        inetFmt(src->ip, 0), inetFmt(mct->group, 0), IfDp->Name);
                    continue;
                }
                if (!checkFilters(IfDp, 0, src, mct)) {
                    // IN: Do not add denied sources on upstream interface.
                    LOG(LOG_NOTICE, 0, "Source %s not allowed for group %s on %s. not adding to source list.",
                        inetFmt(src->ip, 0), inetFmt(mct->group, 0), IfDp->Name);
                    continue;
                }
            } else if (!checkFilters(IfDp, 0, src, mct)) {
                    LOG(LOG_NOTICE, 0, "Adding denied source %s for group %s to blocked sources on %s.", inetFmt(src->ip, 0),
                        inetFmt(mct->group, 0), IfDp->Name);
            } else if (src->vifB.d != mct->mode) {
                    // EX: Source was also requested in include mode on include mode interface.
                    LOG(LOG_INFO, 0, "Source %s not in exclude mode for %s on all exclude mode interfaces.",
                        inetFmt(src->ip, 0), inetFmt(mct->group, 0));
                    continue;
            } else {
                // EX: Source must be excluded and age = 0 on all exclude mode interfaces for group.
                for (i = 0; i < MAXVIFS && (!BIT_TST(src->vifB.d, i) || src->vifB.age[i] == 0); i++ );
                if (i < MAXVIFS) {
                    LOG(LOG_INFO, 0, "Source %s active in include mode for %s on %s.",
                        inetFmt(src->ip, 0), inetFmt(mct->group, 0), getIf(i, NULL, FINDIX | SRCHVIFL)->Name);
                    continue;
                }
            }
            LOG(LOG_DEBUG, 0, "Adding %s to source list for %s on %s.",
                inetFmt(src->ip, 0), inetFmt(mct->group,  0), IfDp->Name);
            BIT_SET(src->vifB.uj, IfDp->index);
            slist[nsrcs++] = src->ip;
        }
        // Set new upstream source filter and set upstream status if new mode is exclude, clear if inlcude.
        if (!mct->mode && nsrcs == 0)
            delGroup(mct, IfDp, NULL, 0);
        else if (k_setSourceFilter(IfDp, mct->group, mct->mode ? MCAST_EXCLUDE : MCAST_INCLUDE, nsrcs, slist) == EADDRNOTAVAIL)
            // ADDRNOTAVAIL may be returned if group was set to include no sources upstream (unjoined). Rejoin and retry.
            if (mct->mode && k_updateGroup(IfDp, true, mct->group, 1, (uint32_t)-1) && nsrcs > 0)
                k_setSourceFilter(IfDp, mct->group, mct->mode ? MCAST_EXCLUDE : MCAST_INCLUDE, nsrcs, slist);
        mct->mode ? BIT_SET(mct->vifB.uj, IfDp->index) : BIT_CLR(mct->mode, IfDp->index);

        _free(slist, var, ((mct->nsrcs & ~0x80000000) + 1) * sizeof(uint32_t));  // Alloced by self
    }
}

/**
*   Clears / Updates all groups and routing table, and sends Joins / Leaves upstream.
*   If called with NULL pointer all groups and routes are removed.
*/
void clearGroups(struct IfDesc *IfDp) {
    struct timespec    start;
    struct ifMct      *imc;
    struct mcTable    *mct;
    register uint8_t   oldstate = IfDp ? IF_OLDSTATE(IfDp) : 0, newstate = IfDp ? IF_NEWSTATE(IfDp) : 0;
    clock_gettime(CLOCK_REALTIME, &start);

    // Downstream interface transition.
    IF_FOR(!(!IS_DOWNSTREAM(oldstate) && IS_DOWNSTREAM(newstate)), (imc = IfDp->dMct; imc; imc = imc ? imc->next : IfDp->dMct)) {
        if (IS_DOWNSTREAM(oldstate) && !IS_DOWNSTREAM(newstate)) {
            // Transition to disabled / upstream, remove from group.
            LOG(LOG_NOTICE, 0, "Vif %d - %s no longer downstream, removing group %s.",
                IfDp->index, IfDp->Name, inetFmt(imc->mct->group, 0));
            imc = delGroup(imc->mct, IfDp, imc, 1);
        } else if (IS_SET(imc->mct, dd, IfDp) && addGroup(imc->mct, IfDp, 1, 0, (uint32_t)-1))
            LOG(LOG_NOTICE, 0, "Group %s now allowed downstream on %s.", inetFmt(imc->mct->group, 0), IfDp->Name);
    }
    // Upstream interface transition.
    IF_FOR(IS_UPSTREAM(oldstate) || IS_UPSTREAM(newstate), (imc = IfDp->uMct; imc; imc = imc ? imc->next : IfDp->uMct)) {
        if (IS_UPSTREAM(oldstate) && !IS_UPSTREAM(newstate) && IS_SET(imc->mct, u, IfDp)) {
            LOG(LOG_INFO, 0, "Vif %d - %s no longer upstream, removing group %s.",
                IfDp->index, IfDp->Name, inetFmt(imc->mct->group, 0));
            // Transition from upstream to downstream or disabled. Leave group.
            imc = delGroup(imc->mct, IfDp, imc, 0);
        } else if ((CONFRELOAD || SHUP) && IS_UPSTREAM(newstate) && IS_UPSTREAM(oldstate)) {
            if (NOT_SET(imc->mct, ud, IfDp) && !checkFilters(IfDp, 0, NULL, imc->mct)) {
                // Check against bl / wl changes on config reload / sighup.
                LOG(LOG_NOTICE, 0, "Group %s no longer allowed upstream on interface %s.",
                    inetFmt(imc->mct->group, 0), IfDp->Name);
                imc = delGroup(imc->mct, IfDp, imc, 0);
            } else if (IS_SET(imc->mct, ud, IfDp) && addGroup(imc->mct, IfDp, 0, 0, (uint32_t)-1)) {
                LOG(LOG_NOTICE, 0, "Group %s now allowed upstream on %s.", inetFmt(imc->mct->group, 0), IfDp->Name);
                for (struct src *src = mct->sources; src; joinBlockSrc(src, IfDp, true), src = src->next);
            }
        }
    }
    // Stop and start bandwidth control if required.
    if (!IfDp->conf->bwControl || (!STARTUP && !IFREBUILD && IfDp->oconf && IfDp->oconf->bwControl != IfDp->conf->bwControl)) {
        IfDp->bwTimer = timerClear(IfDp->bwTimer, false);
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        for (imc = IfDp->uMct; imc; imc = imc ? imc->next : IfDp->uMct)
            for (struct mfc *mfc = mct->mfc; mfc; mfc = mfc->next)
                k_deleteUpcall(mfc->src->ip, mct->group);
#endif
    }
    if ((CONFRELOAD || SHUP || STARTUP || RESTART) && IfDp->conf->bwControl && !IfDp->bwTimer) {
        IfDp->bwTimer = timerSet(IfDp->conf->bwControl * 10, strFmt(1, "Bandwidth Control: %s", "", IfDp->Name), bwControl, IfDp);
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        for (imc = IfDp->uMct; imc; imc = imc ? imc->next : IfDp->uMct)
            for (struct mfc *mfc = mct->mfc; mfc; mfc = mfc->next)
                activateRoute(mfc->IfDp, mfc->src, 0, 0, true);
#endif
    }

    if ((SHUTDOWN || RESTART) && IfDp->uMct) {
        // Dangling unresolved route, remove when shutting down jusst to be nice to the kernel.
        ((struct ifMct *)IfDp->uMct)->mct->stamp.tv_nsec = timerClear(((struct ifMct *)IfDp->uMct)->mct->stamp.tv_nsec, false);
        delGroup(((struct ifMct *)IfDp->uMct)->mct, IfDp, IfDp->uMct, 0);
    }

    if (! MCT)
        LOG(LOG_INFO, 0, "Multicast table is empty.");
    else
        logRouteTable("Clear Groups", 1, -1, (uint32_t)-1, (uint32_t)-1, IfDp);
    clock_gettime(CLOCK_REALTIME, &curtime);
    LOG(LOG_DEBUG, 0, "%s took %dus", IfDp->Name, timeDiff(start, curtime).tv_nsec / 1000);
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
    uint32_t  i = 0, type    = grecType(grec), nsrcs = sortArr((uint32_t *)grec->grec_src, grecNscrs(grec));
    uint32_t         group   = grec->grec_mca.s_addr,
                     srcHash  = IfDp->conf->quickLeave ? murmurhash3(ip) % CONF->dHostsHTSize : (uint32_t)-1;
    struct src      *src     = NULL, *tsrc  = NULL;
    struct qlst     *qlst    = NULL;
    struct mcTable  *mct;

    // Return if request is bogus (BLOCK / ALLOW / IS_IN with no sources, or no group when BLOCK or TO_IN with no sources).
    if ((nsrcs == 0 && (type == IGMPV3_ALLOW_NEW_SOURCES || type == IGMPV3_MODE_IS_INCLUDE || type == IGMPV3_BLOCK_OLD_SOURCES))
        || ! (mct = findGroup(group, !((type == IGMPV3_CHANGE_TO_INCLUDE && nsrcs == 0) || type == IGMPV3_BLOCK_OLD_SOURCES))))
        return;
    LOG(LOG_DEBUG, 0, "Processing %s with %d sources for %s on %s.",
        grecKind(type), nsrcs, inetFmt(group,  0), IfDp->Name);
    // Toggle compatibility modes if older version reports are received.
    if (type == IGMP_V1_MEMBERSHIP_REPORT || type == IGMP_V2_MEMBERSHIP_REPORT || type == IGMP_V2_LEAVE_GROUP) {
        LOG(LOG_NOTICE, 0, "Detected v%d host on %s. Setting compatibility mode for %s.", type == IGMP_V1_MEMBERSHIP_REPORT ? 1 : 2,
            IfDp->Name, inetFmt(group, 0));
        type == IGMP_V1_MEMBERSHIP_REPORT ? BIT_SET(mct->v1Bits, IfDp->index), mct->v1Age[IfDp->index] = IfDp->querier.qrv
                                          : BIT_SET(mct->v2Bits, IfDp->index), mct->v2Age[IfDp->index] = IfDp->querier.qrv;
    }

    bool is_in;
    switch (type) {
    case IGMPV3_CHANGE_TO_EXCLUDE:
        if ((BIT_TST(mct->v1Bits, IfDp->index) || BIT_TST(mct->v2Bits, IfDp->index || IfDp->querier.ver < 3)) && nsrcs > 0) {
            LOG(LOG_INFO, 0, "Ignoring %d sources for %s on %s, v1 or v2 host/querier present.",
                nsrcs, inetFmt(group, 0), IfDp->Name);
            nsrcs = 0;
        } /* FALLTHRU */
    case IGMPV3_MODE_IS_EXCLUDE:;
        is_in = !mct->mode && mct->vifB.d;  // Filter mode needs to be changed upstream.
        if (!addGroup(mct, IfDp, 1, 1, srcHash))
            break;
        for (i = 0, src = mct->sources; src || i < nsrcs; i++) {
            if (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr)) do {
                // IN: Delete (A - B) / EX: Delete (X - A), Delete (Y - A)
                if (IS_SET(src, d, IfDp))
                    // Sources should not be fully removed for host tracking / ACL purposes.
                    // Sources should not be left/unblocked when switching upstream filter mode.
                    src = delSrc(src, IfDp, !IS_IN(mct, IfDp), !is_in, srcHash);
                else {
                    if (src->mfc && NOT_SET(src, u, IfDp) && (IS_EX(mct, IfDp) || NOT_SET(src, d, IfDp)))
                        // When switching from include to exclude mode, unrequested sending sources must now be forwarded.
                       // In exclude mode, source must be forwarded if not already.
                        activateRoute(src->mfc->IfDp, src, src->ip, mct->group, true);
                    src = src->next;
                }
            } while (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr));
            if (i < nsrcs && (! (tsrc = src) || tsrc->ip >= grec->grec_src[i].s_addr)) {
                // IN: (B - A) = 0 / EX: (A - X - Y) = Group Timer?
                if ((src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, 1, 1,
                                  !(IS_IN(mct, IfDp) && tsrc && tsrc->ip == grec->grec_src[i].s_addr), tsrc, (uint32_t)-1)))
                    if (type == IGMPV3_CHANGE_TO_EXCLUDE && src &&
                             (   ((! tsrc || tsrc->ip > grec->grec_src[i].s_addr) && IS_EX(mct, IfDp))
                              || (tsrc && tsrc->ip == grec->grec_src[i].s_addr && IS_SET(src, d, IfDp)
                                       && (IS_IN(mct, IfDp) || src->vifB.age[IfDp->index] > 0))))
                        // IN: Send Q(G, A * B) / EX: Send Q(G, A - Y)
                        qlst = addSrcToQlst(src, IfDp, qlst, (uint32_t)-1);
                src = src ? src->next : tsrc;
            }
        }
        if (is_in)
            // Switch upstream filter mode if inlcude mode group was requested in exclude mode on any downstream interface.
            updateSourceFilter(mct, MCAST_EXCLUDE);
        break;

    case IGMPV3_CHANGE_TO_INCLUDE:
        if (BIT_TST(mct->v1Bits, IfDp->index) || IfDp->querier.ver == 1) {
            LOG(LOG_INFO, 0, "Ignoring TO_IN for %s on %s, v1 host/querier present.", inetFmt(group, 0), IfDp->Name);
            break;
        }
        if (nsrcs == 0) {
            // Leave message, check for quicleave.
            CLR_HASH(mct->dHostsHT, srcHash);
            QUICKLEAVE(mct, ip);
        }
        if (IS_EX(mct, IfDp) && NOT_SET(mct, lm, IfDp))
            // EX: Send Q(G).
            startQuery(IfDp, &(struct qlst){ NULL, NULL, mct, NULL, 0, 2, IfDp->conf->qry.lmInterval,
                                             IfDp->conf->qry.lmCount, 0, 0 });  /* FALLTHRU */
    case IGMPV3_ALLOW_NEW_SOURCES:
    case IGMPV3_MODE_IS_INCLUDE:
        if (nsrcs > 0 && !addGroup(mct, IfDp, 1, 0, srcHash))
            break;

        for (i = 0, src = mct->sources; src || i < nsrcs; src = src ? src->next : src) {
            if (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr)) {
                if (type == IGMPV3_CHANGE_TO_INCLUDE && IS_SET(src, d, IfDp)
                                                     && (IS_IN(mct, IfDp) || src->vifB.age[IfDp->index] > 0))
                    // EX: Send Q(G, X - A) IN: Send Q(G, A - B)
                    qlst = addSrcToQlst(src, IfDp, qlst, srcHash);
            } else if (i < nsrcs && (! (tsrc = src) || src->ip >= grec->grec_src[i].s_addr)) do {
                if (! (src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, 1, 0, true, tsrc, srcHash)))
                    // IN (B) = GMI, (A + B) / EX: (A) = GMI, (X + A) (Y - A)
                    src = tsrc;
                src = ! tsrc && src ? src->next : src;
            } while (++i < nsrcs && (! tsrc || tsrc->ip >= grec->grec_src[i].s_addr));
        }
        break;

    case IGMPV3_BLOCK_OLD_SOURCES:
        if (NOT_SET(mct, d, IfDp) || BIT_TST(mct->v1Bits, IfDp->index)
                                  || BIT_TST(mct->v2Bits, IfDp->index) || IfDp->querier.ver < 3) {
            LOG(LOG_INFO, 0, "Ignoring BLOCK for %s on %s, %s.", inetFmt(group, 0), IfDp->Name,
                NOT_SET(mct, d, IfDp) ? "not active" : "v1 or v2 host/querier present");
            break;
        }
        i       = 0;
        src     = mct->sources;
        bool nH = IfDp->conf->quickLeave;
        while (i < nsrcs && (IS_EX(mct, IfDp) || src)) {
            // IN: Send Q(G, A * B) / EX: Send Q(G, A - Y), (A - X - Y) = Group Timer?
            if (! (tsrc = src) || src->ip >= grec->grec_src[i].s_addr) {
                if (   ((! src || src->ip > grec->grec_src[i].s_addr) && IS_EX(mct, IfDp))
                    || (src->ip == grec->grec_src[i].s_addr && (   (IS_IN(mct, IfDp) && IS_SET(src, d, IfDp))
                                         || (IS_EX(mct, IfDp) && (src->vifB.age[IfDp->index] > 0 || NOT_SET(src, d, IfDp)))))) {
                    if ((src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, 1, 0, false, src, (uint32_t)-1)))
                        qlst = addSrcToQlst(src, IfDp, qlst, srcHash);
                    else
                        src = tsrc;
                    }
                i++;
            }
            // When quickleave is enabled, check if the client is interested in any other source.
            for (; src && i < nsrcs && src->ip < grec->grec_src[i].s_addr && (nH &= !testHash(src->dHostsHT, srcHash))
                 ; src = src->next);
        }
        if (nH) {
            // When quickleave is enabled and client is not interested in any other source, it effectively left the group.
            for (; src && (nH = !testHash(src->dHostsHT, srcHash)); src = src->next);
            if (nH) {
                LOG(LOG_INFO, 0, "Last source %s in group %s for client %s on %s.",
                    inetFmt(grec->grec_src[i - (i >= nsrcs)].s_addr, 0), inetFmt(mct->group, 0), inetFmt(ip, 0), IfDp->Name);
                CLR_HASH(mct->dHostsHT, srcHash);
                QUICKLEAVE(mct, ip);
            }
        }
    }

    startQuery(IfDp, qlst);
    LOG(LOG_DEBUG, 0, "Updated group entry for %s on VIF #%d", inetFmt(group, 0), IfDp->index);
    logRouteTable("Update Group", 1, -1, group, (uint32_t)-1, NULL);
}

/**
*   Switches a group from exclude to include mode on interface.
*/
void toInclude(struct mcTable *mct, struct ifMct *imc) {
    struct src *src  = mct->sources;
    bool        keep = false;

    LOG(LOG_INFO, 0, "Switching to %s include mode on %s.", inetFmt(mct->group, 0), imc->IfDp->Name);
    BIT_CLR(mct->mode, imc->IfDp->index);
    BIT_CLR(mct->v2Bits, imc->IfDp->index);
    mct->v2Age[imc->IfDp->index] = 0;
    while (src) {
        // Remove all inactive sources from group on interface.
        if (NOT_SET(src, d, imc->IfDp) || src->vifB.age[imc->IfDp->index] == 0) {
            LOG(LOG_DEBUG, 0, "Removed inactive source %s from group %s.", inetFmt(src->ip, 0), inetFmt(mct->group, 0));
            src = delSrc(src, imc->IfDp, mct->mode ? 0 : 1, true, (uint32_t)-1);
        } else {
            keep = true;
            src = src->next;
        }
    }
    if (!mct->mode && mct->nsrcs)
        // If this was the last interface switching to include for the group, upstream must switch filter mode to include too.
        updateSourceFilter(mct, MCAST_INCLUDE);
    else if (!mct->mode)
        delGroup(mct, imc->IfDp, imc, 1);
    return;
}

/**
*   Activates, updates or removes a route in the kernel MFC.
*   If called from acceptRouteActivation a new MFC route will be created.
*   If called with pointer to source and activate the route will be updated.
*   If called with pointer to source and !activate the route will be removed.
*/
inline void activateRoute(struct IfDesc *IfDp, void *_src, register uint32_t ip, register uint32_t group, bool activate) {
    struct src      *src = _src;
    struct mcTable  *mct = src ? src->mct : findGroup(group, true);
    bool             add = true;
    if (activate && !mct->vifB.d && ! mct->stamp.tv_nsec) {
        addGroup(mct, IfDp, 3, 0, (uint32_t)-1);
        mct->stamp.tv_nsec = timerSet(CONF->topQueryInterval * 30, strFmt(1, "Unresolved group (%s)", "", inetFmt(group, 0)),
                                      ageUnknownGroup, IfDp->uMct);
    }

    LOG(LOG_INFO, 0, "%s for src: %s to group: %s on VIF #%d %s.", activate ? "Activation" : "Deactivation",
        inetFmt(ip, 0), inetFmt(group, 0), IfDp->index, IfDp->Name);
    if (!activate) {
        // Remove kernel MFC and delete the upstream source.
        if (k_delMRoute(src->ip, mct->group, src->mfc->IfDp))
            BIT_CLR(src->vifB.u, IfDp->index);
        if (src->mfc->next)
            src->mfc->next->prev = src->mfc->prev;
        if (src->mfc->prev)
            src->mfc->prev->next = src->mfc->next;
        if (mct->mfc == src->mfc)
            mct->mfc = src->mfc->next;
        _free(src->mfc, mfc, MFCSZ);  // Alloced by Self
        return;
    } else if (! src) {
        // Find source or create source in group.
        for (src = mct->sources; src && src->ip < ip; src = src->next);
        if (! src || src->ip > ip) {
            if (! (src = addSrc(IfDp, mct, ip, 0, 0, false, src, (uint32_t)-1))) {
                LOG(LOG_WARNING, 0, "Unable to activate route: %s to %s on %s. Cannot create source.",
                    inetFmt(ip, 0), inetFmt(group, 0), IfDp->Name);
                return;
            } else if (!mct->mode) {
                // For include mode group, ignore any senders which have not been explicitely requested downstream.
                LOG(LOG_INFO, 0, "Ignoring unrequested sender %s for include mode group %s on %s.",
                    inetFmt(ip, 0), inetFmt(group, 0), IfDp->Name);
                add = false;
            }
        } else if (mct->mode) {
            if (IS_SET(src, uj, IfDp)) {
                LOG(LOG_INFO, 0, "Ignoring blocked sender %s for include mode group %s on %s.",
                    inetFmt(ip, 0), inetFmt(group, 0), IfDp->Name);
                add = false;
            } else if ((IS_SET(mct, uj, IfDp) || addGroup(mct, IfDp, 0, 1, (uint32_t)-1)) && !checkFilters(IfDp, 0, src, mct)) {
                // In exclude mode, we can explicitely block a denied source and request upstream routers not to send traffic.
                LOG(LOG_NOTICE, 0, "Explicitely blocking denied source %s for group %s on upstream interface %s.",
                    inetFmt(src->ip, 0), inetFmt(mct->group, 0), IfDp->Name);
                joinBlockSrc(src, IfDp, true);
                add = false;
            }
        } else if (!checkFilters(IfDp, 0, src, mct)) {
            // In include mode we will add a blackhole route for sources that are denied upstream.
            LOG(LOG_NOTICE, 0, "Blackhole %s:%s. Denied upstream on %s.", inetFmt(src->ip, 0), inetFmt(mct->group, 0), IfDp->Name);
            add = false;
        }
    }

    // Create and initialize an upstream source for new sender.
    if (! src->mfc) {
        _malloc(src->mfc, mfc, MFCSZ);  // Freed by Self.
        *src->mfc = (struct mfc){ NULL, NULL, {0, 0}, src, IfDp, 0, 0 };
        clock_gettime(CLOCK_REALTIME, &src->mfc->stamp);
        if (mct->mfc) {
            src->mfc->next = mct->mfc;
            mct->mfc->prev = src->mfc;
        }
        mct->mfc = src->mfc;
    }
    // Install or update kernel MFC. See RFC 3376: 6.3 IGMPv3 Source-Specific Forwarding Rules.
    uint8_t ttlVc[MAXVIFS] = {0};
    if (!IS_UPSTREAM(IfDp->state) || !checkFilters(IfDp, 0, src, mct)) {
        // Blackhole any mc traffic that is received on downstream only interface.
        LOG(LOG_DEBUG, 0, "Blackhole %s:%s on %s interface %s.", inetFmt(src->ip, 0), inetFmt(mct->group,0),
            !IS_UPSTREAM(IfDp->state) ? "downstream only" : "denied", IfDp->Name);
        src->vifB.u = (uint32_t)-1;
    }
    IF_GETVIFL_IF(IS_UPSTREAM(IfDp->state), IfDp,
                  IS_DOWNSTREAM(IfDp->state) && IS_SET(mct, d, IfDp) && BIT_SET(src->vifB.u, IfDp->index) && add) {
        if (!checkFilters(IfDp, 1, src, mct)) {
            LOG(LOG_NOTICE, 0, "Not forwarding denied source %s to group %s on %s.", inetFmt(src->ip, 0),
                inetFmt(mct->group, 0), IfDp->Name);
        } else if ( (IS_IN(mct, IfDp) && !NO_HASH(src->dHostsHT) && IS_SET(src, d, IfDp) && src->vifB.age[IfDp->index] > 0)
                 || (IS_EX(mct, IfDp) && !NO_HASH(mct->dHostsHT) && (NOT_SET(src, d, IfDp) || src->vifB.age[IfDp->index] == 0))) {
            ttlVc[IfDp->index] = IfDp->conf->threshold;
        } else
            LOG(LOG_DEBUG, 0, "Not forwarding source %s to group %s on %s.", inetFmt(src->ip, 0),
                inetFmt(mct->group, 0), IfDp->Name);
        LOG(LOG_DEBUG, 0, "Setting TTL for Vif %s (%d) to %d", IfDp->Name, IfDp->index, ttlVc[IfDp->index]);
    }
    if (!k_addMRoute(src->ip, mct->group, src->mfc->IfDp, ttlVc))
        src->vifB.u = 0;
    LOG(LOG_DEBUG, 0, "mct Vif bits: 0x%08x src Vif bits:0x%08x src ubits:%08x", src->mct->vifB.d, src->vifB.d, src->vifB.u);

    logRouteTable("Activate Route", 1, -1, group, (uint32_t)-1, NULL);
}

/**
*   Ages active groups in tables.
*/
void ageGroups(struct IfDesc *IfDp) {
    struct ifMct *imc;
    LOG(LOG_INFO, 0, "Aging active groups on %s.", IfDp->Name);
    IfDp->querier.ageTimer = (intptr_t)NULL;

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
        // Age sources in include mode group.
        bool        keep = false;
        struct src *src  = imc->mct->sources;
        if (IS_IN(imc->mct, IfDp)) while (src) {
            keep = IS_SET(src, d, IfDp) && src->vifB.age[IfDp->index] > 0;
            if (NOT_SET(src, lm, IfDp)) {
                if (src->vifB.age[IfDp->index] == 0 && IS_SET(src, d, IfDp)) {
                    LOG(LOG_INFO, 0, "Removed source %s from %s on %s after aging.",
                        inetFmt(src->ip, 0), inetFmt(imc->mct->group, 0), IfDp->Name);
                    src = delSrc(src, IfDp, 0, true, (uint32_t)-1);
                    continue;
                } else if (src->vifB.age[IfDp->index] > 0)
                    src->vifB.age[IfDp->index]--;
            }
            src = src->next;
        }
        // Next age group. Switch to include mode if exclude mode group has aged. Remove group if it's left with no sources.
        if (IS_EX(imc->mct, IfDp) && imc->mct->vifB.age[IfDp->index] == 0
                                  && !BIT_TST(imc->mct->v1Bits, IfDp->index))
            toInclude(imc->mct, imc);
        else if ((IS_IN(imc->mct, IfDp) && !keep) || (IS_EX(imc->mct, IfDp) && imc->mct->vifB.age[IfDp->index] == 0)) {
            LOG(LOG_INFO, 0, "Removed group %s from %s after aging.", inetFmt(imc->mct->group, 0), IfDp->Name);
            imc = delGroup(imc->mct, IfDp, imc, 1);
        } else if (imc->mct->vifB.age[IfDp->index] > 0)
            imc->mct->vifB.age[IfDp->index]--;
    }

    if (MCT)
        logRouteTable("Age Groups", 1, -1, (uint32_t)-1, (uint32_t)-1, IfDp);
    else
        LOG(LOG_DEBUG, 0, "Multicast table is empty.");
}

/**
*   Ages unknown multicast group
*/
 void ageUnknownGroup(struct ifMct *imc) {
    imc->mct->stamp.tv_nsec = (intptr_t)NULL;
    delGroup(imc->mct, imc->IfDp, imc, imc->mct->vifB.d ? 3 : 0);
}

/**
*   Debug function that writes the routing table entries to the log or sends them to the cli socket specified in arguments.
*/
void logRouteTable(const char *header, int h, int fd, uint32_t addr, uint32_t mask, struct IfDesc *If) {
    struct mcTable *mct;
    struct mfc     *mfc;
    char           *buf;
    unsigned int    rcount = 1;
    uint64_t        totalb = 0, totalr = 0;
    struct IfDesc  *IfDp = NULL;

    if (fd < 0 && CONF->logLevel < LOG_DEBUG)
        return;
    if (fd < 0) {
        LOG(LOG_DEBUG, 0, strFmt(1, "Current multicast table (%s: %s):", "", header,
                                 If ? If->Name : addr ? inetFmt(addr, mask) : ""));
        LOG(LOG_DEBUG, 0, "_____|______SRC______|______DST______|_______In_______|_____Out____|____dHost____|"
                          "__Vif Bits__|_______Data_______|______Rate_____");
    } else if (h) {
        buf = strFmt(h, "Current Multicast Table: %s\n_____|______SRC______|______DST______|_______In_______"
                        "|_____Out____|____dHost____|__Vif Bits__|_______Data_______|______Rate_____\n", "",
                     If ? If->Name : addr ? inetFmt(addr, mask) : "");
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
    GETMRT(mct) {
        if (   (addr != (uint32_t)-1 && (mct->group & mask) != addr)
            || (If && !IS_SET(mct, d, If)) )
            continue;
        mfc = mct->mfc;
        do {
            if (mfc) {
                IfDp = mfc->IfDp;
                totalb += mfc->bytes;
                totalr += mfc->rate;
            }
            if (fd < 0) {
                LOG(LOG_DEBUG, 0, strFmt(h, "%4d |%15s|%15s|%16s| 0x%08x | %11s | 0x%08x | %14lld B | %10lld B/s",
                                  "%d %s %s %s %08x %08x %s %ld %ld", rcount, mfc ? inetFmt(mfc->src->ip, 0) : "-",
                                  inetFmt(mct->group, 0), mfc ? IfDp->Name : "",
                                  mfc && IS_UPSTREAM(mfc->IfDp->state) ? mfc->src->vifB.u : 0,
                                  !CONF->dHostsHTSize ? "not tracked" : noHash(mct->dHostsHT) ? "no" : "yes", mct->vifB.d,
                                  mfc ? mfc->bytes : 0, mfc ? mfc->rate : 0));
            } else {
                buf = strFmt(h, "%4d |%15s|%15s|%16s| 0x%08x | %11s | 0x%08x | %14lld B | %10lld B/s\n",
                             "%d %s %s %s %08x %s %08x %lld %lld\n", rcount, mfc ? inetFmt(mfc->src->ip, 0) : "-",
                             inetFmt(mct->group, 0), mfc ? IfDp->Name : "",
                             mfc && IS_UPSTREAM(mfc->IfDp->state) ? mfc->src->vifB.u : 0,
                             !CONF->dHostsHTSize ? "not tracked" : noHash(mct->dHostsHT) ? "no" : "yes", mct->vifB.d,
                             mfc ? mfc->bytes : 0, mfc ? mfc->rate : 0);
                send(fd, buf, strlen(buf), MSG_DONTWAIT);
            }
            mfc = mfc ? mfc->next : NULL;
            rcount++;
        } while (mfc);
    }
    if (fd < 0) {
        LOG(LOG_DEBUG, 0, "Total|---------------|---------------|----------------|------------|-------------|------------|"
                          " %14lld B | %10lld B/s", totalb, totalr);
        LOG(LOG_DEBUG, 0, "Memory Stats: %lldb total, %lldb table, %lldb sources, %lldb interfaces, %lldb routes, %lldb queries.",
            memuse.mct + memuse.src + memuse.ifm + memuse.mfc + memuse.qry,
            memuse.mct, memuse.src, memuse.ifm, memuse.mfc, memuse.qry);
        LOG(LOG_DEBUG, 0, "              %lld allocs total, %lld tables, %lld sources, %lld interfaces, %lld routes, %lld queries.",
            memalloc.mct + memalloc.src + memalloc.ifm + memalloc.mfc + memalloc.qry,
            memalloc.mct, memalloc.src, memalloc.ifm, memalloc.mfc, memalloc.qry);
        LOG(LOG_DEBUG, 0, "              %lld  frees total, %lld tables, %lld sources, %lld interfaces, %lld routes, %lld queries.",
            memfree.mct + memfree.src + memfree.ifm + memfree.mfc + memfree.qry,
            memfree.mct, memfree.src, memfree.ifm, memfree.mfc, memfree.qry);
    } else if (h) {
        buf = strFmt(1, "Total|---------------|---------------|----------------|------------|-------------|------------|"
                        " %14lld B | %10lld B/s\n", "", totalb, totalr);
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
}
