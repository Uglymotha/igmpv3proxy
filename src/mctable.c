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
*   mctable.c
*   Maintains IGMP group membership and routes.
*/

#include "igmpv3proxy.h"
#include "mctable.h"

static inline bool        addGroup(struct mcTable* mct, struct IfDesc *IfDp, int dir, int mode, uint32_t srcHash);
static inline struct src *addSrc(struct IfDesc *IfDp, struct mcTable *mct, uint32_t ip, bool check, bool set,
                                 struct src *src, uint32_t srcHash);
static uint64_t           getGroupBw(struct subnet group, struct IfDesc *IfDp);
static inline void        joinBlockSrc(struct src *src, struct IfDesc *If, bool join);
static inline void        quickLeave(struct mcTable *mct, uint32_t src);
static void               updateSourceFilter(struct mcTable *mct, int mode);

// Multicast group membership tables.
static struct mcTable **MCT = NULL;

/**
*   Private access function to find a given group in MCT, creates new if required.
*/
struct mcTable *findGroup(register uint32_t group, bool create) {
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
static inline bool addGroup(struct mcTable* mct, struct IfDesc *IfDp, int dir, int mode, uint32_t srcHash) {
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
        IFGETIFLIF((mct->vifB.us | mct->vifB.ud) != uVifs, IfDp, IS_UPSTREAM(IfDp->state) && NOT_SET(mct, us, IfDp))
            // Check if any upstream interfaces still need to join the group.
            addGroup(mct, IfDp, 0, 1, (uint32_t)-1);
    } else {
        // Set upstream status and join group if it is in exclude mode upstream.
        BIT_SET(mct->vifB.u, IfDp->index);
        if (NOT_SET(mct, us, IfDp)) {
            if (mct->mode && CONFIG->bwControlInterval && IfDp->conf->ratelimit > 0 && IfDp->rate > IfDp->conf->ratelimit) {
                LOG(LOG_NOTICE, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.",
                                    IfDp->Name, IfDp->rate, IfDp->conf->ratelimit, inetFmt(mct->group, 1));
            } else if (!mct->mode || k_updateGroup(IfDp, true, mct->group, 0, (uint32_t)-1)) {
                LOG(LOG_INFO, 0, "addGroup: Joined group %s upstream on interface %s.",
                                  inetFmt(mct->group, 1), IfDp->Name);
                BIT_SET(mct->vifB.us, IfDp->index);
            }
        }
    }

    return true;
}

/**
*   Remove a specified MCT from interface.
*/
struct ifMct *delGroup(struct mcTable* mct, struct IfDesc *IfDp, struct ifMct *imc, int dir) {
    struct ifMct *pimc = NULL, **list = (struct ifMct **)(dir ? &IfDp->dMct : &IfDp->uMct);
    struct src   *src;
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
        if (mct->vifB.d)
            for (src = mct->sources; src; BIT_CLR(src->vifB.ud, IfDp->index), BIT_CLR(src->vifB.su, IfDp->index), src = src->next);
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
            for (src = mct->sources; src; BIT_CLR(src->vifB.dd, IfDp->index), BIT_CLR(src->vifB.sd, IfDp->index), src = src->next);
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
static inline struct src *addSrc(struct IfDesc *IfDp, struct mcTable *mct, uint32_t ip, bool check, bool set,
                                 struct src *src, uint32_t srcHash) {
    if (! src || src->ip != ip) {
        // New source should be created, increase nrsrcs.
        struct src *nsrc;
        if (++mct->nsrcs > CONFIG->maxOrigins && CONFIG->maxOrigins) {
            // Check if maxorigins is exceeded.
            if (!(mct->nsrcs & 0x80000000)) {
                mct->nsrcs |= 0x80000000;
                LOG(LOG_WARNING, 0, "Max origins (%d) exceeded for %s.", CONFIG->maxOrigins, inetFmt(mct->group, 1));
            }
            return NULL;
        }
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
    }

    // Set source bits and age, update MFC if present. When source is denied, we still do aging.
    if (set && check) {
        // Source requested in exclude mode.
        BIT_CLR(src->vifB.lm, IfDp->index);
        src->vifB.age[IfDp->index] = IfDp->querier.qrv;
        setHash(src->dHostsHT, srcHash);
    }
    if (set && NOT_SET(src, d, IfDp)) {
        BIT_SET(src->vifB.d, IfDp->index);
        if (src->mfc)
            // Activate route will check ACL for source on downstream interfaces.
            activateRoute(src->mfc->IfDp, src, src->ip, mct->group, true);
    }

    if (check && !checkFilters(IfDp, 1, src, mct)) {
        // Check if the source is allowed on interface.
        LOG(LOG_NOTICE, 0, "Group %s from source %s not allowed downstream on %s.",
                            inetFmt(mct->group, 1), inetFmt(ip, 2), IfDp->Name);
        return NULL;
    } else if (set)
        joinBlockSrc(src, NULL, true);

    return src;
}

/**
*   Removes a source from the list of group sources. When group is in exclude mode, sources requested in include
*   mode will not be fully removed for ACL / host tracking purposes (mode = 1 or mode = 2).
*   When switching from upstream filter mode, sources will not be left here, because updateSourceFilter
*   will atomically switch filter mode (mode = 2 or mode = 3).
*/
struct src *delSrc(struct src *src, struct IfDesc *IfDp, int mode, uint32_t srcHash) {
    struct src     *nsrc = src->next;
    struct mcTable *mct  = src->mct;

    if (! IfDp || NOT_SET(src, qry, IfDp)) {
        // Remove the source if it is not actively being queried and not active on other vifs.
        LOG(LOG_DEBUG, 0, "delSrc: Remove source %s (%d) from %s on %s.", inetFmt(src->ip, 1), mct->nsrcs, inetFmt(mct->group, 2),
                           IfDp ? IfDp->Name : "all interfaces");
        if (IfDp) {
            // Remove source from hosts hash table, and clear vifbits.
            clearHash(src->dHostsHT, srcHash);
            BIT_CLR(src->vifB.d, IfDp->index);
            BIT_CLR(src->vifB.lm, IfDp->index);
            src->vifB.age[IfDp->index] = 0;
        }
        if (mode < 2 && (! IfDp || !src->vifB.d || (!mct->mode && src->vifB.d == src->vifB.dd)
                                                || ( mct->mode && src->vifB.d != mct->mode)))
            // Source should not be left / unblocked when switching upstream filter mode.
            // Leave Source if not active on any interfaces in include mode.
            // Unblock source if it is no longer excluded on all exclude mode interfaces, or included on any include mode interface.
            joinBlockSrc(src, NULL, false);
        if (! IfDp || !src->vifB.d) {
            if (src->mfc && (! IfDp || !mct->mode || IS_IN(mct, IfDp)))
                // MFC for group in include mode on all interface must be removed if no more listeners downstream.
                // Unrequested sending source must no longer be forwarded to include mode interface, update MFC.
                activateRoute(src->mfc->IfDp, src, src->ip, mct->group, !(! IfDp || !mct->mode));
            if ((mode == 0 || mode == 3) && ! src->mfc) {
                // Remove the source if there are no senders and it was not requested by include mode host.
                mct->nsrcs--;
                if (CONFIG->maxOrigins && (mct->nsrcs & 0x80000000) && (mct->nsrcs & ~0x80000000) < CONFIG->maxOrigins) {
                    // Reset maxorigins exceeded flag.
                    LOG(LOG_INFO, 0, "delSrc: Maxorigins reset for group %s.", inetFmt(src->mct->group, 1));
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
                free(src);  // Alloced by addSrc()
             }
        } else if (src->mfc && IS_IN(mct, IfDp))
            // If group is in include mode downstream traffic must no longer be forwarded, update MFC.
            activateRoute(src->mfc->IfDp, src, src->ip, mct->group, true);
    }

    return nsrc;
}

/**
*   Join the source upstream if group is in include mode.
*   Block the souce upstream if it is in exclude mode on all exclude mode interfaces.
*/
static inline void joinBlockSrc(struct src *src, struct IfDesc *If, bool join) {
    struct IfDesc *IfDp;
    IFGETIFLIF(join && ((src->vifB.ud | src->vifB.us) != uVifs || src->vifB.su != uVifs), IfDp, (! If || IfDp == If)
                                         && IS_UPSTREAM(IfDp->state) && (NOT_SET(src, us, IfDp) || NOT_SET(src, su, IfDp))) {
        // Join or block the source upstream if necessary.
        if (!src->mct->mode && !checkFilters(IfDp, 0, src, src->mct)) {
            // For group in include mode on all interfaces, check if source is allowed upstream.
            LOG(LOG_NOTICE, 0, "Source %s from group %s not allowed upstream on %s.",
                                inetFmt(src->ip, 1), inetFmt(src->mct->group, 2), IfDp->Name);
            if (IS_SET(src, us, IfDp)) {
                // If source was joined upstream and acl changed, leave.
                LOG(LOG_INFO, 0, "Leaving source %s from group %s upstream on %s.",
                                  inetFmt(src->ip, 1), inetFmt(src->mct->group, 2), IfDp->Name);
                k_updateGroup(IfDp, false, src->mct->group, 0, src->ip);
                BIT_CLR(src->vifB.us, IfDp->index);
                if (src->mfc)
                    // If source has active MFC it must be removed as it's no longer forwarded.
                    activateRoute(src->mfc->IfDp, src, src->ip, src->mct->group, false);
            }
        } else if (NOT_SET(src, us, IfDp) && (!src->mct->mode || src->vifB.d == src->mct->mode)) {
            // Only block exclude mode sources upstream if they are blocked on all downstream interfaces in exclude mode.
            for (int i = 0; src->mct->mode && i < MAXVIFS && (!BIT_TST(src->vifB.d, i) || src->vifB.age[i] == 0); i++)
            if (!src->mct->mode && (!src->vifB.d || !checkFilters(IfDp, 0, src, src->mct)))
                LOG(!src->vifB.d ? LOG_INFO : LOG_NOTICE, 0, "%s%s from group %s%s.",
                    !src->vifB.d ? "joinBlockSource: No downstream listeners for source " : "Source ", inetFmt(src->ip, 1),
                    inetFmt(src->mct->group, 2), !src->vifB.d ? ", not joining upstream on " : " denied upstream on " , IfDp->Name);
            else if ((!src->mct->mode || i >= MAXVIFS) && k_updateGroup(IfDp, true, src->mct->group, src->mct->mode, src->ip)) {
                LOG(LOG_INFO, 0, "joinBlockSrc: %s source %s from group %s on upstream interface %s.",
                                  src->mct->mode ? "Blocked" : "Joined", inetFmt(src->ip, 1), inetFmt(src->mct->group, 2),
                                  IfDp->Name);
                BIT_SET(src->vifB.us, IfDp->index);
            }
        }
    } else IFGETIFLIF(!join, IfDp, IS_SET(src, us, IfDp)) {
        // Source should not be unblocked when upstream mode is exclude and source is not allowed.
        if (src->mct->mode &&!checkFilters(IfDp, 0, src, src->mct))
            LOG(LOG_NOTICE, 0, "Not unblocking denied source %s from group %s upstream on %s.", inetFmt(src->ip, 1),
                                inetFmt(src->mct->group, 2), IfDp->Name);
        else {
            LOG(LOG_INFO, 0, "delSrc: %s source %s from group %s upstream on %s", src->mct->mode ? "Unblocking" : "Leaving",
                              inetFmt(src->ip, 1), inetFmt(src->mct->group, 2), If->Name);
            k_updateGroup(If, false, src->mct->group, src->mct->mode, src->ip);
            BIT_CLR(src->vifB.us, IfDp->index);
            if (src->mfc && src->mct->mode)
                // If source was unblocked upstream, traffic must now be forwarded, update MFC.
                activateRoute(src->mfc->IfDp, src, src->ip, src->mct->group, true);
        }
    }
}

/**
*   Check if a group can be left upstream, because no more listeners downstream.
*/
static inline void quickLeave(struct mcTable *mct, uint32_t src) {
    struct IfDesc * IfDp;
    clearHash(mct->dHostsHT, murmurhash3(src) % (CONFIG->dHostsHTSize));
    IFGETIFLIF(mct->vifB.us && noHash(mct->dHostsHT), IfDp, IS_SET(mct, us, IfDp)) {
        // Quickleave group upstream is last downstream host was detected.
        LOG(LOG_INFO, 0, "iquickLeave: Group %s on %s. Last downstream host %s.",
                          inetFmt(mct->group, 1), inetFmt(src, 2), IfDp->Name);
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
bool checkFilters(struct IfDesc *IfDp, int dir, struct src *src, struct mcTable *mct) {
    if (IfDp->filCh) {
        // ACL change due to config reload, reset permission bits so access is rechecked.
        dir ? BIT_CLR(mct->vifB.dd, IfDp->index) : BIT_CLR(mct->vifB.ud, IfDp->index);
        for (src = mct->sources; src; src = src->next)
            dir ? (BIT_CLR(src->vifB.sd, IfDp->index), BIT_CLR(src->vifB.dd, IfDp->index))
                : (BIT_CLR(src->vifB.su, IfDp->index), BIT_CLR(src->vifB.ud, IfDp->index));
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
static void updateSourceFilter(struct mcTable *mct, int mode) {
    struct IfDesc * IfDp;
    GETIFLIF(IfDp, IS_SET(mct, us, IfDp)) {
        uint32_t    nsrcs = 0, *slist = NULL, i;
        struct src *src;
        // Build source list for upstream interface.
        if (! (slist = malloc((mct->nsrcs & ~0x80000000) * sizeof(uint32_t))))  // Freed by self
            LOG(LOG_ERR, errno, "updateSourceFilter: Out of Memory.");
        for (nsrcs = 0, src = mct->sources; src; src = src->next) {
            BIT_CLR(src->vifB.us, IfDp->index);
            if (mode == MCAST_INCLUDE) {
                if (!src->vifB.d || noHash(src->dHostsHT)) {
                    // IN: Do not add sources with no listeners.
                    LOG(LOG_INFO, 0, "updateSourceFilter: No downstream hosts %s:%s on %s, not adding to source list.",
                                      inetFmt(src->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
                    continue;
                }
                if (!checkFilters(IfDp, 0, src, mct)) {
                    // IN: Do not add denied sources on upstream interface.
                    LOG(LOG_NOTICE, 0, "Source %s not allowed for group %s on %s. not adding to source list.",
                                      inetFmt(src->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
                    continue;
                }
            } else if (!checkFilters(IfDp, 0, src, mct)) {
                    LOG(LOG_NOTICE, 0, "Adding denied source %s for group %s to blocked sources on %s.", inetFmt(src->ip, 1),
                                        inetFmt(mct->group, 2), IfDp->Name);
            } else if (src->vifB.d != mct->mode) {
                    // EX: Source was also requested in include mode on include mode interface.
                    LOG(LOG_INFO, 0, "updateSourceFilter: Source %s not in exclude mode for %s on all exclude mode interfaces.",
                                      inetFmt(src->ip, 1), inetFmt(mct->group, 2));
                    continue;
            } else {
                // EX: Source must be excluded and age = 0 on all exclude mode interfaces for group.
                for (i = 0; i < MAXVIFS && (!BIT_TST(src->vifB.d, i) || src->vifB.age[i] == 0); i++ );
                if (i < MAXVIFS) {
                    LOG(LOG_INFO, 0, "updateSourceFilter: Source %s active in include mode for %s on %s.",
                                      inetFmt(src->ip, 1), inetFmt(mct->group, 2), getIf(i, 0)->Name);
                    continue;
                }
            }

            LOG(LOG_DEBUG, 0, "updateSourceFilter: Adding %s to source list for %s on %s.",
                               inetFmt(src->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
            BIT_SET(src->vifB.us, IfDp->index);
            slist[nsrcs++] = src->ip;
        }

        // Set new upstream source filter and set upstream status if new mode is exclude, clear if inlcude.
        if (!mct->mode && nsrcs == 0)
            delGroup(mct, IfDp, NULL, 0);
        else if (k_setSourceFilter(IfDp, mct->group, mct->mode ? MCAST_EXCLUDE : MCAST_INCLUDE, nsrcs, slist) == EADDRNOTAVAIL)
            // ADDRNOTAVAIL may be returned if group was set to include no sources upstream (unjoined). Rejoin and retry.
            if (mct->mode && k_updateGroup(IfDp, true, mct->group, 1, (uint32_t)-1) && nsrcs > 0)
                k_setSourceFilter(IfDp, mct->group, mct->mode ? MCAST_EXCLUDE : MCAST_INCLUDE, nsrcs, slist);

        free(slist);  // Alloced by self
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
                for (struct mfc *mfc = mct->mfc; mfc; mfc = mfc->next) {
                    k_deleteUpcalls(mfc->src->ip, mct->group);
                    activateRoute(mfc->IfDp, mfc->src, 0, 0, true);
                }
#endif
            } else if (!IS_UPSTREAM(oldstate) && addGroup(mct, IfDp, 0, 1, (uint32_t)-1))
                // New upstream interface join all relevant groups and sources.
                for (struct src *src = mct->sources; src; joinBlockSrc(src, IfDp, true), src = src->next);
        }
        if (Dp == CONFIG || Dp == getConfig)
            return;
    }

    // Downstream interface transition.
    if (((CONFRELOAD || SSIGHUP) && IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate))
                                        || (IS_DOWNSTREAM(oldstate) && !IS_DOWNSTREAM(newstate)))
        for (imc = IfDp->dMct; imc; imc = imc ? imc->next : IfDp->dMct) {
            if (IS_DOWNSTREAM(oldstate) && !IS_DOWNSTREAM(newstate)) {
                // Transition to disabled / upstream, remove from group.
                LOG(LOG_INFO, 0, "clearGroups: Vif %d - %s no longer downstream, removing group %s.",
                                  IfDp->index, IfDp->Name, inetFmt(imc->mct->group, 1));
                delQuery(IfDp, NULL, imc->mct, NULL, 0);
                for (struct src *src = imc->mct->sources; src; src = delSrc(src, IfDp, imc->mct->mode ? 3 : 0, (uint32_t)-1));
                imc = delGroup(imc->mct, IfDp, imc, 1);
            } else if (NOT_SET(imc->mct, dd, IfDp) && !checkFilters(IfDp, 1, NULL, imc->mct)) {
                // Check against bl / wl changes on config reload / sighup.
                LOG(LOG_NOTICE, 0, "Group %s no longer allowed downstream on Vif %d - %s.",
                                    inetFmt(imc->mct->group, 1), IfDp->index, IfDp->Name);
                delQuery(IfDp, NULL, imc->mct, NULL, 0);
                for (struct src *src = imc->mct->sources; src; src = delSrc(src, IfDp, imc->mct->mode ? 3 : 0, (uint32_t)-1));
                imc = delGroup(imc->mct, IfDp, imc, 1);
            } else if (IS_SET(imc->mct, dd, IfDp) && addGroup(imc->mct, IfDp, 1, 0, (uint32_t)-1))
                LOG(LOG_INFO, 0, "clearGroups: Group %s now allowed downstream on %s.", inetFmt(imc->mct->group, 1), IfDp->Name);
        }

    // Upstream interface transition.
    if (((CONFRELOAD || SSIGHUP) && IS_UPSTREAM(newstate) && IS_UPSTREAM(oldstate))
            || (IS_UPSTREAM(oldstate) && !IS_UPSTREAM(newstate)))
        for (imc = IfDp->uMct; imc; imc = imc ? imc->next : IfDp->uMct) {
            if (IS_UPSTREAM(oldstate) && !IS_UPSTREAM(newstate) && IS_SET(imc->mct, u, IfDp)) {
                // Transition from upstream to downstream or disabled. Leave group.
                imc = delGroup(imc->mct, IfDp, imc, 0);
            } else if ((CONFRELOAD || SSIGHUP) && IS_UPSTREAM(newstate) && IS_UPSTREAM(oldstate)) {
                if (NOT_SET(imc->mct, ud, IfDp) && !checkFilters(IfDp, 0, NULL, imc->mct)) {
                    // Check against bl / wl changes on config reload / sighup.
                    LOG(LOG_NOTICE, 0, "Group %s no longer allowed upstream on interface %s.",
                                        inetFmt(imc->mct->group, 1), IfDp->Name);
                    imc = delGroup(imc->mct, IfDp, imc, 0);
                } else if (IS_SET(imc->mct, ud, IfDp) && addGroup(imc->mct, IfDp, 0, 0, (uint32_t)-1)) {
                    LOG(LOG_INFO, 0, "clearGroups: Group %s now allowed upstream on %s.", inetFmt(imc->mct->group, 1), IfDp->Name);
                    for (struct src *src = mct->sources; src; joinBlockSrc(src, IfDp, true), src = src->next);
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
void updateGroup(struct IfDesc *IfDp, uint32_t ip, struct igmpv3_grec *grec) {
    uint32_t  i = 0, type    = grecType(grec), nsrcs = sortArr((uint32_t *)grec->grec_src, grecNscrs(grec));
    uint32_t         group   = grec->grec_mca.s_addr, srcHash = murmurhash3(ip) % CONFIG->dHostsHTSize;
    struct src      *src     = NULL, *tsrc  = NULL;
    struct qlst     *qlst    = NULL,  qlst1;
    struct mcTable  *mct;

    // Return if request is bogus (BLOCK / ALLOW / IS_IN with no sources, or no group when BLOCK or TO_IN with no sources).
    if ((nsrcs == 0 && (type == IGMPV3_ALLOW_NEW_SOURCES || type == IGMPV3_MODE_IS_INCLUDE || type == IGMPV3_BLOCK_OLD_SOURCES))
       || ! (mct = findGroup(group, !((type == IGMPV3_CHANGE_TO_INCLUDE && nsrcs == 0) || type == IGMPV3_BLOCK_OLD_SOURCES))))
        return;

    LOG(LOG_DEBUG, 0, "updateGroup: Processing %s with %d sources for %s on %s.",
                       grecKind(type), nsrcs, inetFmt(group, 1), IfDp->Name);

    // Toggle compatibility modes if older version reports are received.
    if (type == IGMP_V1_MEMBERSHIP_REPORT || type == IGMP_V2_MEMBERSHIP_REPORT || type == IGMP_V2_LEAVE_GROUP) {
        LOG(LOG_INFO, 0, "Detected v%d host on %s. Setting compatibility mode for %s.", type == IGMP_V1_MEMBERSHIP_REPORT ? 1 : 2,
                          IfDp->Name, inetFmt(group, 1));
        type == IGMP_V1_MEMBERSHIP_REPORT ? BIT_SET(mct->v1Bits, IfDp->index), mct->v1Age[IfDp->index] = IfDp->querier.qrv
                                          : BIT_SET(mct->v2Bits, IfDp->index), mct->v2Age[IfDp->index] = IfDp->querier.qrv;
    }

    bool is_ex, is_in;
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

        for (i = 0, src = mct->sources; src || i < nsrcs; i++) {
            if (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr)) do {
                // IN: Delete (A - B) / EX: Delete (X - A), Delete (Y - A)
                if (IS_SET(src, d, IfDp) || IS_SET(src, dd, IfDp) || IS_SET(src, us, IfDp))
                    // Sources should not be fully removed for host tracking / ACL purposes.
                    // Sources should not be left/unblocked when switching upstream filter mode.
                    src = delSrc(src, IfDp, is_in ? 2 : 1, srcHash);
                else {
                    if (src->mfc && NOT_SET(src, d, IfDp) && !is_ex)
                        // When switching from include to exclude mode, unrequested sending sources must now be forwarded.
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
                        qlst = addSrcToQlst(src, IfDp, qlst, (uint32_t)-1);
                src = src ? src->next : tsrc;
            }
        }
        if (is_in)
            // Switch upstream filter mode if inlcude mode group was requested in exclude mode on any downstream interface.
            updateSourceFilter(mct, MCAST_EXCLUDE);
        break;

    case IGMPV3_CHANGE_TO_INCLUDE:
        qlst1 = (struct qlst){ NULL, NULL, mct, IfDp, 0, 2, IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount, 0, 0 };
        if (BIT_TST(mct->v1Bits, IfDp->index) || IfDp->querier.ver == 1) {
            LOG(LOG_INFO, 0, "updateGroup: Ignoring TO_IN for %s on %s, v1 host/querier present.", inetFmt(group, 1), IfDp->Name);
            break;
        }
        if (nsrcs == 0)
            // Leave message, check for quicleave.
            quickLeave(mct, ip);
        if (IS_EX(mct, IfDp) && NOT_SET(mct, lm, IfDp))
            // EX: Send Q(G).
            startQuery(IfDp, &qlst1);  /* FALLTHRU */
    case IGMPV3_ALLOW_NEW_SOURCES:
    case IGMPV3_MODE_IS_INCLUDE:
        if (nsrcs > 0 && !addGroup(mct, IfDp, 1, 0, srcHash))
            break;

        for (i = 0, src = mct->sources; src || i < nsrcs; src = src ? src->next : src) {
            if (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr)) {
                if (type == IGMPV3_CHANGE_TO_INCLUDE && IS_SET(src, d, IfDp) && (IS_IN(mct, IfDp) || src->vifB.age[IfDp->index] > 0))
                    // EX: Send Q(G, X - A) IN: Send Q(G, A - B)
                    qlst = addSrcToQlst(src, IfDp, qlst, srcHash);
            } else if (i < nsrcs && (! (tsrc = src) || src->ip >= grec->grec_src[i].s_addr)) do {
                if (! (src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, true, true, tsrc, srcHash)))
                    // IN (B) = GMI, (A + B) / EX: (A) = GMI, (X + A) (Y - A)
                    src = tsrc;
                src = ! tsrc && src ? src->next : src;
            } while (++i < nsrcs && (! tsrc || tsrc->ip >= grec->grec_src[i].s_addr));
        }
        break;

    case IGMPV3_BLOCK_OLD_SOURCES:
        if (NOT_SET(mct, d, IfDp) || BIT_TST(mct->v1Bits, IfDp->index)
                                  || BIT_TST(mct->v2Bits, IfDp->index) || IfDp->querier.ver < 3) {
            LOG(LOG_INFO, 0, "updateGroup: Ignoring BLOCK for %s on %s, %s.", inetFmt(group, 1), IfDp->Name,
                              NOT_SET(mct, d, IfDp) ? "not active" : "v1 or v2 host/querier present");
            break;
        }

        i       = 0;
        src     = mct->sources;
        bool nH = CONFIG->fastUpstreamLeave;
        while (i < nsrcs && (IS_EX(mct, IfDp) || src)) {
            // IN: Send Q(G, A * B) / EX: Send Q(G, A - Y), (A - X - Y) = Group Timer?
            if (! (tsrc = src) || src->ip >= grec->grec_src[i].s_addr) {
                if (   ((! src || src->ip > grec->grec_src[i].s_addr) && IS_EX(mct, IfDp))
                    || (src->ip == grec->grec_src[i].s_addr && (   (IS_IN(mct, IfDp) && IS_SET(src, d, IfDp))
                                         || (IS_EX(mct, IfDp) && (src->vifB.age[IfDp->index] > 0 || NOT_SET(src, d, IfDp))))))
                    if ((src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, true, false, src, (uint32_t)-1)))
                        qlst = addSrcToQlst(src, IfDp, qlst, srcHash);
                    else
                        src = tsrc;
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
                LOG(LOG_DEBUG, 0, "updateGroup: Last source %s in group %s for client %s on %s.",
                                   inetFmt(grec->grec_src[i - (i >= nsrcs ? 1 : 0)].s_addr, 1), inetFmt(mct->group, 2),
                                   inetFmt(ip, 3), IfDp->Name);
                quickLeave(mct, ip);
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
inline bool toInclude(struct mcTable *mct, struct IfDesc *IfDp) {
    struct src *src  = mct->sources;
    bool        keep = false;

    LOG(LOG_INFO, 0, "toInclude: Switching to %s include mode on %s.", inetFmt(mct->group, 1), IfDp->Name);
    BIT_CLR(mct->mode, IfDp->index);
    BIT_CLR(mct->v2Bits, IfDp->index);
    mct->v2Age[IfDp->index] = 0;
    while (src) {
        // Remove all inactive sources from group on interface.
        if (NOT_SET(src, d, IfDp) || src->vifB.age[IfDp->index] == 0) {
            LOG(LOG_DEBUG, 0, "toInclude: Removed inactive source %s from group %s.", inetFmt(src->ip, 1), inetFmt(mct->group, 2));
            src = delSrc(src, IfDp, mct->mode ? 0 : 3 , (uint32_t)-1);
        } else {
            keep = true;
            src = src->next;
        }
    }

    if (!mct->mode)
        // If this was the last interface switching to include for the group, upstream must switch filter mode to include too.
        updateSourceFilter(mct, MCAST_INCLUDE);

    return !keep;
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

    LOG(LOG_INFO, 0, "activateRoute: %s for src: %s to group: %s on VIF %s (%d)", activate ? "Activation" : "Deactivation",
                      inetFmt(ip, 1), inetFmt(group, 2), IfDp->Name, IfDp->index);
    if (!activate) {
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
        return;
    } else if (! src) {
        // Find source or create source in group.
        for (src = mct->sources; src && src->ip < ip; src = src->next);
        if (! src || src->ip > ip) {
            if (!mct->mode) {
                // For include mode group, ignore any senders which have not been explicitely requested downstream.
                LOG(LOG_DEBUG, 0, "activateRoute: Ignoring unrequested sender %s for include mode group %s on %s.",
                                   inetFmt(ip, 1), inetFmt(group, 2), IfDp->Name);
                return;
            } else if (! (src = addSrc(IfDp, mct, ip, false, false, src, (uint32_t)-1))) {
                LOG(LOG_WARNING, 0, "Unable to activate route: %s to %s on %s. Cannot create source.",
                                     inetFmt(ip, 1), inetFmt(group, 2), IfDp->Name);
                return;
            }
        } else if (mct->mode) {
            if (IS_SET(src, us, IfDp)) {
                LOG(LOG_DEBUG, 0, "activateRoute: Ignoring blocked sender %s for include mode group %s on %s.",
                                   inetFmt(ip, 1), inetFmt(group, 2), IfDp->Name);
                return;
            } else if ((IS_SET(mct, us, IfDp) || addGroup(mct, IfDp, 0, 1, (uint32_t)-1)) && !checkFilters(IfDp, 0, src, mct)) {
                // In exclude mode, we can explicitely block a denied source and request upstream routers not to send traffic.
                LOG(LOG_NOTICE, 0, "Explicitely blocking denied source %s for group %s on upstream interface %s.",
                                    inetFmt(src->ip, 1), inetFmt(mct->group, 2), IfDp->Name);
                if (k_updateGroup(IfDp, true, mct->group, 1, src->ip))
                    BIT_SET(src->vifB.us, IfDp->index);
                return;
            }
        }
    }
    LOG(LOG_DEBUG, 0, "Vif bits: 0x%08x", src->mct->vifB.d);

    // Create and initialize an upstream source for new sender.
    if (! src->mfc) {
        if (! (src->mfc = malloc(sizeof(struct mfc))))
            LOG(LOG_ERR, errno, "activateRoute: Out of Memory!");  // Freed by Self.
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

        // Age sources in include mode group.
        bool        keep = false;
        struct src *src  = imc->mct->sources;
        if (IS_IN(imc->mct, IfDp)) while (src) {
            keep |= IS_SET(src, d, IfDp) && src->vifB.age[IfDp->index] > 0;
            if (NOT_SET(src, lm, IfDp)) {
                if (src->vifB.age[IfDp->index] == 0 && IS_SET(src, d, IfDp)) {
                    LOG(LOG_INFO, 0, "ageGroups: Removed source %s from %s on %s after aging.",
                                      inetFmt(src->ip, 1), inetFmt(imc->mct->group, 2), IfDp->Name);
                    src = delSrc(src, IfDp, 0, (uint32_t)-1);
                    continue;
                } else if (src->vifB.age[IfDp->index] > 0)
                    src->vifB.age[IfDp->index]--;
            }
            src = src->next;
        }

        // Next age group. Switch to include mode if exclude mode group has aged. Remove group if it's left with no sources.
        if (IS_EX(imc->mct, IfDp) && NOT_SET(imc->mct, dd, IfDp) && imc->mct->vifB.age[IfDp->index] == 0
                                  && !BIT_TST(imc->mct->v1Bits, IfDp->index) && toInclude(imc->mct, IfDp))
            imc = delGroup(imc->mct, IfDp, imc, 1);
        else if ((IS_IN(imc->mct, IfDp) && !keep) || (IS_SET(imc->mct, dd, IfDp) && imc->mct->vifB.age[IfDp->index] == 0)) {
            LOG(LOG_INFO, 0, "ageGroups: Removed group %s from %s after aging.", inetFmt(imc->mct->group, 2), IfDp->Name);
            imc = delGroup(imc->mct, IfDp, imc, 1);
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
                LOG(LOG_DEBUG, 0, msg, rcount, mfc ? inetFmt(mfc->src->ip, 1) : "-", inetFmt(mct->group, 2), mfc ? IfDp->Name : "", mct->vifB.d, ! CONFIG->fastUpstreamLeave ? "not tracked" : noHash(mct->dHostsHT) ? "no" : "yes", mfc ? mfc->bytes : 0, mfc ? mfc->rate : 0);
            } else {
                sprintf(buf, strcat(msg, "\n"), rcount, mfc ? inetFmt(mfc->src->ip, 1) : "-", inetFmt(mct->group, 2), mfc ? IfDp->Name : "", mct->vifB.d, ! CONFIG->fastUpstreamLeave ? "not tracked" : noHash(mct->dHostsHT) ? "no" : "yes", mfc ? mfc->bytes : 0, mfc ? mfc->rate : 0);
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
