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

static inline bool        addGroup(struct mct* mct, struct IfDesc *IfDp, int dir, int mode, uint32_t srcHash);
static inline struct src *addSrc(struct IfDesc *IfDp, struct mct *mct, uint32_t ip, int dir, int mode, bool join,
                                 struct src *src, uint32_t srcHash);
static inline void        quickLeave(struct mct *mct, struct IfDesc *IfDp, uint32_t ip);
void                      ageUnknownGroup(struct src *src);
#define QUICKLEAVE(x,y)   if (IfDp->conf->dhtSz) quickLeave(x, IfDp, y)

// Multicast group membership tables.
static struct mct **MCT = NULL;

/**
*   Private access function to find a given group in MCT, creates new if required.
*/
struct mct *findGroup(struct IfDesc *IfDp, register uint32_t group, int dir, bool create) {
    struct mct *mct = ! IfDp ? NULL : dir ? IfDp->dmct : IfDp->umct, *pmct = NULL, *pimct = NULL;
    uint32_t    mctHash = murmurhash3(group) & ((1 << CONF->mcTables) - 1);
    vif_t       ix = ! IfDp ? (vif_t)-1 : dir ? IfDp->dvifix : IfDp->uvifix;

    LOG(LOG_DEBUG, 0, "%s:%s (%d:%d)", IfDp->Name, inetFmt(group, 0), dir, create);
    // Initialize the routing tables if necessary.
    if (! MCT)
        _calloc(MCT, 1, mct, MCTSZ);   // Freed by logRouteTable()
    // Look for group on interface first, if not found search global table. i keeps the nr of lists we need to update.
    IF_FOR(IfDp, (; mct && mct->group < group; pimct = mct, mct = (dir ? mct->dvif[ix].next : mct->uvif[ix].next)));
    IF_FOR(! mct || mct->group > group, (mct = MCT[mctHash]; mct && mct->group < group; pmct = mct, mct = mct->next));
    if (!create && (! mct || mct->group > group))
        return NULL;
    else if (! mct || mct->group > group) {
        // Create and initialize new MCT entry.
        LOG(LOG_DEBUG, 0, "New group %s in table #%d.", inetFmt(group, 0), mctHash);
        LST_IN(0, mct, MCT[mctHash], pmct, dvif[ix], mct, MCESZ);                      // Freed by delGroup()
        mct->group = group;
        clock_gettime(CLOCK_REALTIME, &(mct->stamp));
        mct->stamp.tv_nsec = (intptr_t)NULL;
    }
    if (dir && mct->stamp.tv_nsec) {
        mct->stamp.tv_nsec = (intptr_t)timerClear((intptr_t)mct->stamp.tv_nsec, false);
        delGroup(mct, mct->sources->IfDp, 0);
    }
    // Allocate downstream and upstream vif tables.
    if (! mct->dvif || mct->nvif.d < downvifcount) {
        _recalloc(mct->dvif, ifm, VIFSZ(1, struct vif), PVIFSZ(mct, d, struct vif));   // Freed by delGroup()
        _recalloc(mct->firstsrc, ifm, VIFSZ(1, void *), PVIFSZ(mct, d, void *));       // Freed by delGroup()
        mct->nvif.d = downvifcount;
    }
    if (! mct->uvif || mct->nvif.u < upvifcount) {
        _recalloc(mct->uvif, ifm, VIFSZ(0, struct vif), PVIFSZ(mct, u, struct vif));   // Freed by delGroup()
        mct->nvif.u = upvifcount;
    }
    // Allocate downstream vif & hash table.
    if (dir && create && ix != (vif_t)-1 && ! mct->dvif[ix].vp) {
        mct->nvif.i++;
        LST_IN(3, mct, IfDp->dmct, pimct, dvif[ix], ifm, DVIFSZ);                      // Freed by delGroup()
        mct->dvif[ix].vp->v1age = mct->dvif[ix].vp->v2age = -1;
        if (IfDp->conf->dhtSz)
            _calloc(mct->dvif[ix].vp->dht, sizeof(uint64_t), dht, IfDp->conf->dhtSz);  // Freed by delGroup()
    }

    return mct;
}

/**
*  Adds a group to an interface. All downstream requested groups will be attached to interface,
*  whether denied or allowed. Denied exclude mode groups will age so that reference to permissions
*  can be kept for as long as the group is being requested on the interface.
*/
static inline bool addGroup(struct mct* mct, struct IfDesc *IfDp, int dir, int mode, uint32_t srcHash) {
    uint32_t       ix = dir ? IfDp->dvifix : IfDp->uvifix;
    struct IfDesc *If;

    LOG(LOG_DEBUG, 0, "%s:%s (%d:%d) (%d:%d) (#%d/#%d) (#%d/#%d)", IfDp->Name, inetFmt(mct->group, 0), dir, mode,
        dir && mct->dvif[ix].vp ? 1 : mct->uvif[ix].j, dir ? mct->dvif[ix].vp->mode : mct->mode,
        mct->nvif.i, mct->nvif.e, mct->nsrcs[0], mct->nsrcs[1]);
    if (dir) {
        SET_HASH(mct, IfDp, srcHash);
        if (mode) {
            // Exclude mode group, reset last member state and set age to GMI. We also age denied groups.
            IF_FOR_IF(!mct->dvif[ix].vp->mode && (mct->dvif[ix].vp->mode = 1),
                      (struct src *src = mct->sources; src; src = src->next), src->IfDp)
                activateRoute(src->IfDp, src, src->ip, src->mct->group, true);
            mct->dvif[ix].vp->lm    = 0;
            mct->dvif[ix].vp->age   = IfDp->querier.qrv;  // Group timer = GMI
            mct->mode               = true;
        }
        GETUVIFL_IF(If, !mct->uvif[If->uvifix].j && !mct->uvif[If->uvifix].d)
            // Check if any upstream interfaces still need to join the group.
            addGroup(mct, If, 0, 1, NHASH);
    } else {
        if (!mct->uvif[ix].s)
            LST_IN(4, mct, IfDp->umct, NULL, uvif[ix], ifm, 0);
        if (!checkFilters(IfDp, 0, NULL, mct)) {
            // Check if group is allowed upstream on interface.
            LOG(LOG_NOTICE, 0, "Not joining denied group %s on %s.", inetFmt(mct->group, 0), IfDp->Name);
        } else if (IfDp->conf->bwControl > 0 && IfDp->conf->ratelimit > 0 && IfDp->stats.iRate > IfDp->conf->ratelimit)
            LOG(LOG_NOTICE, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.",
                IfDp->Name, IfDp->stats.iRate, IfDp->conf->ratelimit, inetFmt(mct->group, 0));
        else if (mct->mode && !mct->uvif[ix].j && !mct->uvif[ix].d
                           && k_updateGroup(IfDp, true, mct->group, 1, (uint32_t)-1)) {
            mct->uvif[ix].j = 1;
            LOG(LOG_INFO, 0, "Joined group %s upstream on interface %s.", inetFmt(mct->group, 0), IfDp->Name);
        }
    }
    if (dir)
        logRouteTable("Add Group", 1, -1, (uint32_t)-1, (uint32_t)-1, IfDp);
    return true;
}

/**
*   Remove a specified MCT from interface.
*/
struct mct *delGroup(struct mct* mct, struct IfDesc *IfDp, int dir) {
    struct IfDesc *If;
    uint32_t       group = mct->group, ix = dir ? IfDp->dvifix : IfDp->uvifix;
    static bool    remove = false;
    struct mct    *nmct = dir ? mct->dvif[ix].next : mct->uvif[ix].next;

    LOG(LOG_DEBUG, 0, "%s:%s (%d:%d:%d) (#%d/#%d) (#%d/#%d)", IfDp->Name, inetFmt(mct->group, 0), dir,
        dir && mct->dvif[ix].vp ? 1 : mct->uvif[ix].j, mct->mode, mct->nvif.i, mct->nvif.e, mct->nsrcs[0], mct->nsrcs[1]);
    // Update the interface group list for downstream vif.
    if (mct->stamp.tv_nsec)
        timerClear((intptr_t)mct->stamp.tv_nsec, true);
    if (dir) {
        if (mct->dvif[ix].vp->mode)
            mct->nvif.e--;
        else
            mct->nvif.i--;
        if (!mct->nvif.i && !mct->nvif.e)
            mct->mode = false;
        if (mct->dvif[ix].vp->qry)
            delQuery(mct->dvif[ix].vp->qry, mct, NULL);
        if (mct->dvif[ix].vp->dht)
            _free(mct->dvif[ix].vp->dht, dht, DHTSZ);            // Alloced by findGroup()
        LST_RM(3, mct, IfDp->dmct, dvif[ix], ifm, DVIFSZ);       // Alloced by findGroup()
    } else {
        // Leave exclude mode group upstream and clear upstream status.
        if (mct->uvif[ix].j && mct->mode) {
            LOG(LOG_INFO, 0, "Leaving group %s upstream on interface %s.", inetFmt(mct->group, 0), IfDp->Name);
            k_updateGroup(IfDp, false, mct->group, 0, (uint32_t)-1);
        }
        mct->uvif[ix].j = 0;
        LST_RM(4, mct, IfDp->umct, uvif[ix], ifm, DVIFSZ);
        IF_FOR(!mct->nvif.i && !mct->nvif.e, (struct src *src = mct->sources; src; src=delSrc(src, IfDp, 0, 0, 1, NHASH)));
    }
    if (!mct->nvif.e && !mct->nvif.i && !remove) {
        // No clients downstream, group can be removed from table.
        uint32_t mctHash = murmurhash3(group) & ((1 << CONF->mcTables) - 1);
        LOG(LOG_INFO, 0, "Deleting group %s from table #%d.",inetFmt(mct->group, 0), mctHash);
        // If deleting group downstream Send Leave requests and remove group upstream.
        remove = true;  // Guard against infinite recursion.
        GETUVIFL_IF(If, mct->uvif[If->uvifix].j || mct->uvif[If->uvifix].d)
            delGroup(mct, If, 0);
        remove = false;
        _free(mct->firstsrc, ifm, PVIFSZ(mct, d, void *));       // Alloced by findGroup()
        _free(mct->dvif,     ifm, PVIFSZ(mct, d, struct vif));   // Alloced by findGroup()
        _free(mct->uvif,     ifm, PVIFSZ(mct, u, struct vif));   // Alloced by findGroup()
        LST_RM(0, mct, MCT[mctHash], dvif[ix], mct, MCESZ);      // Alloced by findGroup()
    }

    if (dir || SHUTDOWN)
        logRouteTable("Remove Group", dir, -1, (uint32_t)-1, (uint32_t)-1, IfDp);
    return nmct;
}

/**
*   Creates a new source for group and adds it to list of sources. Doubly linked list
*   with prev of fist pointing to last item in queue. We will be called from updateGroup()
*   which as it evaluates the list in linear order knows exactly where source should be
*   created in list, no src if it should go to end of list.
*/
static inline struct src *addSrc(struct IfDesc *IfDp, struct mct *mct, uint32_t ip, int dir, int mode, bool join,
                                 struct src *src, uint32_t srcHash) {
    struct src *psrc = NULL, *pisrc = src;
    uint32_t    ix = dir ? IfDp->dvifix : IfDp->uvifix;

    LOG(LOG_DEBUG, 0, "%s:%s,%s (#%d/#%d) (%d:%d:%d) (%s:#%d/#%d)", IfDp->Name, inetFmt(ip, 0),
        inetFmt(mct->group, 0), mct->nsrcs[0], mct->nsrcs[1], dir, mode, join, src ? inetFmt(src->ip, 0) : "-",
        src ? src->nvif.i : 0, src ? src->nvif.e : 0);
    if (dir && src && src->dvif[ix].next && ((struct src *)src->dvif[ix].next)->ip == ip)
        src = src->dvif[ix].next;
    IF_FOR(! src || src->ip < ip, (src = mct->sources; src && src->ip < ip; psrc = src, src = src->next));
    if (! src || src->ip > ip) {
        // New source should be created, increase nrsrcs.
        if (++mct->nsrcs[1] > IfDp->conf->maxOrigins && IfDp->conf->maxOrigins) {
            // Check if maxorigins is exceeded.
            if (!(mct->nsrcs[1] & 0x80000000)) {
                mct->nsrcs[1] |= 0x80000000;
                LOG(LOG_WARNING, 0, "Max origins (#%d) exceeded for %s.", CONF->maxOrigins, inetFmt(mct->group, 0));
            }
            return NULL;
        }
        LST_IN(1, src, mct->sources, psrc, dvif[ix], src, SRCSZ);                                     // Freed by delSrc()
        src->ip = ip;
        src->mct = mct;
        if (dir && !mode)
            mct->nsrcs[0]++;
        LOG(LOG_INFO, 0, "New source %s,%s (#%d/#%d).", inetFmt(mct->group, 0), inetFmt(ip, 0), mct->nsrcs[0], mct->nsrcs[1]);
    }
    if (! src->dvif || src->nvif.d < downvifcount) {
        if (src->ttl)
            _recalloc(src->ttl, ifm, downvifcount * sizeof(uint8_t), src->nvif.d * sizeof(uint8_t));  // Freed by delSrc()
        _recalloc(src->dvif, ifm, VIFSZ(1, struct vif), PVIFSZ(src, d, struct vif));                  // Freed by delSrc()
        src->nvif.d = downvifcount;
    }
    if (! src->uvif || src->nvif.u < upvifcount) {
        _recalloc(src->uvif, ifm, VIFSZ(0, struct vif), PVIFSZ(src, u, struct vif));                  // Freed by delSrc()
        src->nvif.u = upvifcount;
    }
    if (dir) {
        if (! src->dvif[ix].vp) {
            if (! mode)
                src->nvif.i++;
            else
                src->nvif.e++;
            LST_IN(3, src, mct->firstsrc[ix], pisrc, dvif[ix], ifm, DVIFSZ);                          // Freed by delSrc()
            src->dvif[ix].vp->mode = mode;
        }
        // Activate route will check ACL for source on downstream interfaces.
        if (src->IfDp && (   (!mode && src->ttl[ix] == 0 && !src->dvif[ix].d)
                          || ( mode && src->ttl[ix] > 0)))
            activateRoute(src->IfDp, src, src->ip, mct->group, true);
        if (!mode) {
            if (IfDp->conf->dhtSz && ! src->dvif[ix].vp->dht)
                _calloc(src->dvif[ix].vp->dht, IfDp->conf->dhtSz, dht, sizeof(uint64_t));             // Freed by delSrc()

            src->dvif[ix].vp->lm  = 0;
            src->dvif[ix].vp->age = IfDp->querier.qrv;
            SET_HASH(src, IfDp, srcHash);
        } else {
            src->dvif[ix].vp->age = 0;
            CLR_HASH(src, IfDp, srcHash);
        }
        IF_GETUVIFL_IF(join && (mode || IS_IN(mct, IfDp)), IfDp, !src->uvif[IfDp->uvifix].j && !src->uvif[IfDp->uvifix].d) {
            mct->uvif[IfDp->uvifix].j = 1;
            joinBlockSrc(src, IfDp, true, mode);
        }
    }

    return src;
}

/**
*   Removes a source from the list of group sources. When group is in exclude mode, sources requested in include.
*   mode will not be fully removed for ACL / host tracking purposes (mode = 2 or mode = 3).
*   mode 0 = include mode source has aged.
*   mode 1 = remove because of interface status change.
*   mode 2 = source expired in gssq and is now excluded.
*   mode 3 = source deleted when switching group from include to exclude mode on interface.
*   mode 4 = quickleave source in include mode.
*/
struct src *delSrc(struct src *src, struct IfDesc *IfDp, int dir, int mode, bool leave, uint32_t srcHash) {
    uint32_t        ix = IfDp ? (dir ? IfDp->dvifix : IfDp->uvifix) : (vif_t)-1, iz = 1;
    struct IfDesc  *If;
    struct src     *nsrc = !dir && !mode ? src->next : src->dvif[ix].next;
    struct mct     *mct  = src->mct;

    LOG(LOG_DEBUG, 0, "%s:%s,%s (#%d/#%d) (#%d/#%d) (%d:%d:%d) (%d:%d:%d)", IfDp->Name, inetFmt(src->ip, 0),
        inetFmt(mct->group, 0), mct->nsrcs[0], mct->nsrcs[1], src->nvif.i, src->nvif.e, dir, mode, leave,
        dir && src->dvif[ix].vp ? 1 : src->uvif[ix].j, dir && NO_HASH(src, IfDp) ? 0 : 1, dir && src->dvif[ix].vp->dht ? 0 : 1,
        dir && src->dvif[ix].vp ? src->dvif[ix].vp->age : 0,
        dir && src->dvif[ix].vp ? src->dvif[ix].d : !dir ? src->uvif[ix].d : 0);
    // Remove source from hosts hash table, and clear vifbits.
    if (dir) {
        CLR_HASH(src, IfDp, srcHash);
        if (mode == 4 && IfDp->conf->dhtSz && NO_HASH(src, IfDp)) {
            LOG(LOG_INFO, 0, "Last downstream host, quickleave source %s in group %s on %s.",
                inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name);
            IF_GETUVIFL_IF(src->nvif.i == 1, If, src->uvif[If->uvifix].j)
                joinBlockSrc(src, If, false, 0);
            if (src->IfDp)
                activateRoute(src->IfDp, src, src->ip, mct->group, true);
            return src;
        }
        if (mode < 2 && src->dvif[ix].vp->qry)
            delQuery(src->dvif[ix].vp->qry, src->mct, src);
        IF_GETUVIFL_IF(leave && ((mct->mode && src->dvif[ix].vp) || (!mct->mode && !src->nvif.i)), If, src->uvif[If->uvifix].j)
            // In include mode upstream leave Source if not active on any interfaces.
            // In exclude mode upstream unblock source if it is no longer excluded on all exclude mode interfaces.
            joinBlockSrc(src, If, false, mct->mode);
        if (src->dvif[ix].vp && mode < 2) {
            LOG(LOG_INFO, 0, "Removing source %s (#%d/#%d #%d/#%d) from %s on %s.", inetFmt(src->ip, 0), mct->nsrcs[0],
                mct->nsrcs[1], src->nvif.i, src->nvif.e, inetFmt(mct->group, 0), IfDp->Name);
            if (!src->dvif[ix].vp->mode)
                src->nvif.i--;
            else
                src->nvif.e--;
            if (src->dvif[ix].vp->dht)
                _free(src->dvif[ix].vp->dht, dht, IfDp->conf->dhtSz * sizeof(uint64_t));   // Alloced by addSrc()
            LST_RM(3, src, mct->firstsrc[ix], dvif[ix], ifm, DVIFSZ);                      // Alloced by addSrc()
        }
        IF_GETUVIFL_IF(!leave && (mode == 0 || mode == 2) && mct->mode, If, !src->uvif[If->uvifix].j)
            // In exclude mode upstream the source can be blocked if it is excluded on all exclude interfaces
            // and not included on any include mode interfaces.
            joinBlockSrc(src, If, true, 1);
        if (src->IfDp && (
               (IS_IN(mct, IfDp) && ! src->dvif[ix].vp && src->ttl[ix] > 0)
            || (IS_EX(mct, IfDp) && ! src->dvif[ix].vp && src->ttl[ix] == 0)
            || (IS_EX(mct, IfDp) &&   src->dvif[ix].vp && src->ttl[ix] > 0 && src->dvif[ix].vp->age == 0)))
            // Unrequested sending source must not be forwarded to include mode interface.
            // In exclude mode, excluded source must no longer be forwarded if it is expired (age = 0).
            // When switching from include to exclude mode, unrequested sending sources must now be forwarded.
            activateRoute(src->IfDp, src, src->ip, mct->group, true);
    }
    if (!dir || mode == 3 || (!src->nvif.i && !src->nvif.e)) {
        if (dir && ((mode < 2 && leave) || (mode == 2 && !leave) || (mode == 3 && src->dvif[ix].vp->age > 0)))
            mct->nsrcs[0]--;
        if (src->IfDp && (mode < 2 || !src->mct->mode))
            // MFC for group in include mode on all interface must be removed if no more listeners downstream.
            activateRoute(src->IfDp, src, src->ip, mct->group, false);
        if (! src->ttl && mode < 3) {
            // Remove the source if there are no senders and it was not requested by include mode host.
            mct->nsrcs[1]--;
            LOG(LOG_DEBUG, 0, "Delete source %s (#%d/#%d) from group %s.", inetFmt(src->ip, 0),
                mct->nsrcs[0], mct->nsrcs[1], inetFmt(mct->group, 0));
            if (CONF->maxOrigins && (mct->nsrcs[1] & 0x80000000) && (mct->nsrcs[1] & ~0x80000000) < CONF->maxOrigins) {
                // Reset maxorigins exceeded flag.
                LOG(LOG_INFO, 0, "Maxorigins reset for group %s.", inetFmt(src->mct->group, 0));
                mct->nsrcs[1] &= ~0x80000000;
            }
            _free(src->dvif, ifm, PVIFSZ(src, d, struct vif));   // Alloced by addSrc()
            _free(src->uvif, ifm, PVIFSZ(src, u, struct vif));   // Alloced by addSrc()
            LST_RM(1, src, mct->sources, dvif[ix], src, SRCSZ);  // Alloced by addSrc()
        }
    }
    if (dir && src && src->dvif[ix].vp && !src->dvif[ix].vp->lm)
        src->dvif[ix].vp->age = 0;

    return nsrc;
}

/**
*   Join or leave (IN, join) or block or unblock (EX, !join) the source upstream if necessary.
*   Block the souce upstream only if it is in exclude mode on all exclude mode interfaces.
*/
inline void joinBlockSrc(struct src *src, struct IfDesc *IfDp, bool join, int mode) {
    uint32_t ix = IfDp->uvifix;

    LOG(LOG_DEBUG, 0, "%s on %s (%d:%d)", inetFmt(src->ip, 0), IfDp->Name, join, mode);
    if (join && !src->mct->mode && src->dvif[ix].j && !src->uvif[ix].s && !checkFilters(IfDp, 0, src, src->mct)) {
        // If source was joined upstream and acl changed, leave and remove route.
        LOG(LOG_NOTICE, 0, "Source %s from group %s no longer allowed upstream on %s.",
            inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name);
        joinBlockSrc(src, IfDp, false, 0);
        if (src->IfDp)
            activateRoute(src->IfDp, src, src->ip, src->mct->group, true);
    } else if (join && (!mode || (!src->nvif.i && src->nvif.e == src->mct->nvif.e))) {
        if ((!mode && !src->nvif.i) || !checkFilters(IfDp, 0, src, src->mct))
            LOG(!src->dvif[ix].d ? LOG_INFO : LOG_NOTICE, 0, "%s%s from group %s%s.",
                !src->dvif[ix].d ? "No downstream listeners for source " : "Source ", inetFmt(src->ip, 0),
                inetFmt(src->mct->group, 0), !src->dvif[ix].d ? ", not joining upstream on " : " denied upstream on " , IfDp->Name);
        else if (k_updateGroup(IfDp, true, src->mct->group, src->mct->mode, src->ip)) {
            LOG(LOG_INFO, 0, "%s source %s from group %s on upstream interface %s.",
                src->mct->mode ? "Blocked" : "Joined", inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name);
            src->uvif[ix].j = 1;
        }
    } else if (!join && mode && !checkFilters(IfDp, 0, src, src->mct)){
        // Source should not be unblocked when upstream mode is exclude and source is not allowed.
        LOG(LOG_NOTICE, 0, "Not unblocking denied source %s from group %s upstream on %s.", inetFmt(src->ip, 0),
            inetFmt(src->mct->group, 0), IfDp->Name);
    } else if (!join && src->uvif[ix].j) {
        LOG(LOG_INFO, 0, "%s source %s from group %s upstream on %s", src->mct->mode ? "Unblocking" : "Leaving",
            inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name);
        if (k_updateGroup(IfDp, false, src->mct->group, src->mct->mode, src->ip))
            src->uvif[ix].j = 0;
        if (src->IfDp && mode)
            // If source was unblocked upstream, traffic must now be forwarded, update MFC.
            activateRoute(src->IfDp, src, src->ip, src->mct->group, true);
    }
}

/**
*   Check if a group can be left upstream, because no more listeners downstream.
*/
static inline void quickLeave(struct mct *mct, struct IfDesc *IfDp, uint32_t ip) {
    LOG(LOG_DEBUG, 0, "%s:%s", inetFmt(ip, 0), inetFmt(mct->group, 0));
    IF_GETUVIFL_IF(NO_HASH(mct, IfDp) && mct->nvif.i + mct->nvif.e == 1, IfDp, mct->uvif[IfDp->uvifix].j) {
        // Quickleave group upstream is last downstream host was detected.
        LOG(LOG_INFO, 0, "Group %s on %s. Last downstream host %s.", inetFmt(mct->group, 0), IfDp->Name, inetFmt(ip, 0));
        delGroup(mct, IfDp, 0);
    }
}

/**
*   Process all S,G counters and calculate interface rates.
*/
void bwControl(struct IfDesc *IfDp) {
    struct src *src;
    uint64_t    ibytes, obytes;

    // Reset interface rate.
    IfDp->stats.iRate = IfDp->stats.oRate = 0;
    // Go over all upstream interface groups and sources and get the bandwidth used.
    for(src = IfDp->mfc; src; src = src->uvif[IfDp->uvifix].nextmfc) {
        // Get the S,G statistics via ioct. On BSD they are processed by processBwUpcall().
        struct sioc_sg_req siocReq = { {src->ip}, {src->mct->group}, 0, 0, 0 };
        if (ioctl(MROUTERFD, SIOCGETSGCNT, (void *)&siocReq, sizeof(siocReq))) {
            LOG(LOG_WARNING, 1, "BW_CONTROL: IOCGETSGCNT failed.");
            continue;
        }
        ibytes = siocReq.bytecnt - src->bytes;
        src->bytes += ibytes;
        src->rate = ibytes / IfDp->conf->bwControl;
        LOG(LOG_INFO, 0, "Added %lldB to %s:%s (%lldB/s), total %lldB.",
            ibytes, inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), src->rate, src->bytes);
    }
    // Get the interface stats via ioctl.
    struct sioc_vif_req siocVReq = { IfDp->index, 0, 0, 0, 0 };
    if (ioctl(MROUTERFD, SIOCGETVIFCNT, (void *)&siocVReq, sizeof(siocVReq)))
        LOG(LOG_WARNING, 1, "BW_CONTROL: SIOCGETVIFCNT failed.");
    else {
        ibytes = siocVReq.ibytes - IfDp->stats.iBytes;
        IfDp->stats.iBytes += ibytes;
        IfDp->stats.iRate = ibytes / IfDp->conf->bwControl;
        obytes = siocVReq.obytes - IfDp->stats.oBytes;
        IfDp->stats.oBytes += obytes;
        IfDp->stats.oRate = obytes / IfDp->conf->bwControl;
        LOG(LOG_INFO, 0, "Added %lldB/%lldB to %s interface %s (%lldB/s/%lldB/s), total %lldB/%lldB.", ibytes, obytes,
            IS_UPDOWNSTREAM(IfDp->state) ?  "updownstream" : IS_DOWNSTREAM(IfDp->state) ? "downstream" : "upstream",
            IfDp->Name, IfDp->stats.iRate, IfDp->stats.oRate, IfDp->stats.iBytes, IfDp->stats.oBytes);
    }

    // Set next timer;
    IfDp->bwTimer = timerSet(IfDp->conf->bwControl * 10, strFmt(1, "Bandwidth Control: %s", "", IfDp->Name), bwControl, IfDp);
    logRouteTable("Bandwidth Control", 0, -1, (uint32_t)-1, (uint32_t)-1, IfDp);
}

/**
*  ACL evaluation. Returns whether group/src is allowed on interface.
*  dir: 0 = upstream, 1 = downstream
*  Keep access status in permission bits .sd or .su means group access is known.
*  When dd or us is set means group is denied, when not set group is allowed.
*/
bool checkFilters(struct IfDesc *IfDp, int dir, struct src *src, struct mct *mct) {
    uint32_t ix = dir ? IfDp->dvifix : IfDp->uvifix;

    LOG(LOG_DEBUG, 0, "%s%s on %s (%d)", strFmt(src, "%s:", "", src ? inetFmt(src->ip, 0) : ""), inetFmt(mct->group, 0),
        IfDp->Name, dir);
    if (IfDp->filCh) {
        // ACL change due to config reload, reset permission bits so access is rechecked.
        dir ? (mct->dvif[ix].d = 0) : (mct->uvif[ix].d = 0);
        for (src = mct->sources; src; src = src->next)
            dir ? (src->dvif[ix].s = src->dvif[ix].d = 0) : (src->uvif[ix].s = src->uvif[ix].d = 0);
    } else if (src ? (dir ? src->dvif[ix].s : src->uvif[ix].s) : (dir ? mct->dvif[ix].s : mct->dvif[ix].s))
        // If permissions are known return whether allowed or denied. Proceed to check filters if not.
        return src ? (dir ? !src->dvif[ix].d : !src->uvif[ix].d) : (dir ? !mct->dvif[ix].d : !mct->uvif[ix].d);
    // Set known permission bit for source or group, and check access.
    src ? (dir ? (src->dvif[ix].s = 1) : (src->uvif[ix].s = 1)) : (dir ? (mct->dvif[ix].s = 1) : (mct->uvif[ix].s = 1));
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
        src ? (dir ? (src->dvif[ix].d = 1) : (src->uvif[ix].d = 1)) : (dir ? (mct->dvif[ix].d = 1) : (mct->uvif[ix].d = 1));

    return (filter && filter->action);
}

/**
*   Clears / Updates all groups and routing table, and sends Joins / Leaves upstream.
*   If called with NULL pointer all groups and routes are removed.
*/
void clearGroups(struct IfDesc *IfDp) {
    struct mct        *mct;
    struct timespec    start;
    uint32_t           ix = IfDp->dvifix;
    register uint8_t   oldstate = IfDp ? IF_OLDSTATE(IfDp) : 0, newstate = IfDp ? IF_NEWSTATE(IfDp) : 0;
    clock_gettime(CLOCK_REALTIME, &start);

    LOG(LOG_DEBUG, 0, "%s:%d:%d", IfDp->Name, oldstate, newstate);
    // Downstream interface transition.
    if (IS_DOWNSTREAM(oldstate) && (!IS_DOWNSTREAM(newstate) || IS_UPSTREAM(newstate))) {
        LOG(LOG_INFO, 0, "Vif %d - %s %s, removing %sroutes.", IfDp->index, IfDp->Name,
            !IS_DOWNSTREAM(newstate) ? "no longer downstream" : "now also upstream", !IS_DOWNSTREAM(newstate) ? "groups and " : "");
        IF_FOR(!IS_UPSTREAM(oldstate), (struct src *src = NULL, *nsrc = IfDp->mfc; (src = nsrc); nsrc = src->dvif[ix].nextmfc,
                                        delSrc(src, IfDp, 0, 1, false, NHASH)));
        IF_FOR(!IS_DOWNSTREAM(newstate), (mct = IfDp->dmct; mct; mct = delGroup(mct, IfDp, 1)))
            for (struct src *src = mct->firstsrc[ix]; src; LOG(LOG_INFO, 0, "Removing source %s from group %s on %s.",
                                                               inetFmt(src->ip, 0), inetFmt(mct->group, 0), IfDp->Name),
                 src->dvif[ix].s = src->dvif[ix].d = 0,
                 src = delSrc(src, IfDp, 1, 1, src->dvif[ix].vp && src->dvif[ix].vp->age > 0, NHASH));
    }
    IF_FOR_IF(IfDp->filCh && (CONFRELOAD || SHUP) && IS_DOWNSTREAM(oldstate) && IS_DOWNSTREAM(newstate),
                     (mct = IfDp->dmct; mct; mct = mct->dvif[ix].next), mct->dvif[ix].s)
        // Check against bl / wl changes on config reload / sighup.
        checkFilters(IfDp, 1, NULL, mct);
    // Upstream interface transition.
    ix = IfDp->uvifix;
    if (IS_UPSTREAM(oldstate) && !IS_UPSTREAM(newstate)) {
        LOG(LOG_INFO, 0, "Vif %d - %s no longer upstream, removing groups and routes.", IfDp->index, IfDp->Name);
        for (struct src *src = IfDp->mfc, *nsrc = src; (src = nsrc); nsrc = src->uvif[ix].nextmfc,
                                                                     delSrc(src, IfDp, 0, 1, false, NHASH));
        for (mct = IfDp->umct; mct; mct = delGroup(mct, IfDp, 0));
    } else IF_FOR(IfDp->filCh && (CONFRELOAD || SHUP) && IS_UPSTREAM(oldstate) && IS_UPSTREAM(newstate),
                  (mct = IfDp->umct; mct;)) {
        // Check against bl / wl changes on config reload / sighup.
        if (mct->uvif[ix].s && !mct->uvif[ix].d && !checkFilters(IfDp, 0, NULL, mct)) {
            LOG(LOG_NOTICE, 0, "Group %s no longer allowed upstream on interface %s.",
                inetFmt(mct->group, 0), IfDp->Name);
            mct = delGroup(mct, IfDp, 0);
        } else if (mct->uvif[ix].s && mct->uvif[ix].d && addGroup(mct, IfDp, 0, 0, NHASH)) {
            LOG(LOG_NOTICE, 0, "Group %s now allowed upstream on %s.", inetFmt(mct->group, 0), IfDp->Name);
            for (struct src *src = mct->sources; src; joinBlockSrc(src, IfDp, true, !mct->mode), src = src->next);
            mct = mct->uvif[ix].next;
        }
    }
    // Stop and start bandwidth control if required.
    if (!IfDp->conf->bwControl || SHUTDOWN
        || (!STARTUP && !IFREBUILD && IfDp->oconf && IfDp->oconf->bwControl != IfDp->conf->bwControl)) {
        IfDp->bwTimer = timerClear(IfDp->bwTimer, false);
    }
    if (!SHUTDOWN && !IS_DISABLED(IfDp->state) && IfDp->conf->bwControl && ! IfDp->bwTimer)
        IfDp->bwTimer = timerSet(IfDp->conf->bwControl * 10, strFmt(1, "Bandwidth Control: %s", "", IfDp->Name), bwControl, IfDp);
    if (SHUTDOWN && IfDp->umct) {
        // Dangling unresolved route..
        ((struct mct *)IfDp->umct)->stamp.tv_nsec = timerClear(mct->stamp.tv_nsec, false);
        delGroup(IfDp->umct, IfDp, 0);
    }

    if (IS_DOWNSTREAM(IfDp->state))
        logRouteTable(strFmt(1, "Clear Groups (%s)", "", IfDp->Name), 1, -1, (uint32_t)-1, (uint32_t)-1, IfDp);
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
    uint32_t       type    = grecType(grec), nsrcs = sortArr((uint32_t *)grec->grec_src, grecNscrs(grec)),
                   group   = grec->grec_mca.s_addr, *sl[upvifcount], i, j, unsrcs, size, ix = IfDp->dvifix;
    struct src    *src     = NULL, *tsrc  = NULL, *psrc = NULL;
    struct qry    *qry     = NULL;
    struct mct    *mct;
    struct IfDesc *If;
    bool           swupstr = false, nH = false;

    // Return if request is bogus (BLOCK / ALLOW / IS_IN with no sources, or no group when BLOCK or TO_IN with no sources).
    if ((nsrcs == 0 && (type == IGMPV3_ALLOW_NEW_SOURCES || type == IGMPV3_MODE_IS_INCLUDE || type == IGMPV3_BLOCK_OLD_SOURCES))
        || ! (mct = findGroup(IfDp, group, 1,
                              !((type == IGMPV3_CHANGE_TO_INCLUDE && nsrcs == 0) || type == IGMPV3_BLOCK_OLD_SOURCES))))
        return;
    LOG(LOG_DEBUG, 0, "%s:%s:%s %s (#%d)", IfDp->Name, inetFmt(ip, 0), grecKind(type), inetFmt(group,  0), nsrcs);
    // Toggle compatibility modes if older version reports are received.
    if (type == IGMP_V1_MEMBERSHIP_REPORT || type == IGMP_V2_MEMBERSHIP_REPORT || type == IGMP_V2_LEAVE_GROUP) {
        LOG(LOG_NOTICE, 0, "Detected v%d host on %s. Setting compatibility mode for %s.",
            type == IGMP_V1_MEMBERSHIP_REPORT ? 1 : 2, IfDp->Name, inetFmt(group, 0));
        type == IGMP_V1_MEMBERSHIP_REPORT ? (mct->dvif[ix].vp->v1age = IfDp->querier.qrv)
                                          : (mct->dvif[ix].vp->v2age = IfDp->querier.qrv);
    }

    switch (type) {
    case IGMPV3_CHANGE_TO_EXCLUDE:
        if ((mct->dvif[ix].vp->v1age > 0 || mct->dvif[ix].vp->v2age > 0 || IfDp->querier.ver < 3) && nsrcs > 0) {
            LOG(LOG_INFO, 0, "Ignoring %d sources for %s on %s, v1 or v2 host/querier present.",
                nsrcs, inetFmt(group, 0), IfDp->Name);
            nsrcs = 0;
        } /* FALLTHRU */
    case IGMPV3_MODE_IS_EXCLUDE:
        swupstr = (!mct->mode && mct->nvif.e);
        unsrcs = 0;
        if (!mct->dvif[ix].vp->mode) {
            mct->nvif.i--;
            mct->nvif.e++;
        }
        if (IfDp->conf->ssmRange.ip != 0 && (group & IfDp->conf->ssmRange.mask) == IfDp->conf->ssmRange.ip) {
            LOG(LOG_WARNING, 0, "Ignoring %s for SSM group %s on %s.", grecKind(type), inetFmt(group, 0), IfDp->Name);
            return;
        } else
            addGroup(mct, IfDp, 1, 1, HASH(IfDp, ip));
        IF_FOR(swupstr && (mct->nsrcs[0] || nsrcs), (j = 0; j < upvifcount; j++)) {
            // Filter mode needs to be changed upstream.
            size = (mct->nsrcs[0] + nsrcs) * sizeof(uint32_t);
            _malloc(sl[j], var, size);   // Freed by self.
        }
        for (i = 0, src = mct->firstsrc[ix]; src || i < nsrcs; i++) {
            if (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr)) do {
                // IN: Delete (A - B) / EX: Delete (X - A), Delete (Y - A)
                // Source should not be left / unblocked when switching upstream filter mode.
                psrc = src;
                src = src->dvif[ix].vp || src->IfDp ? delSrc(src, IfDp, 1, 3, !swupstr, HASH(IfDp, ip)) : src->dvif[ix].next;
            } while (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr));
            if (i < nsrcs && (! (tsrc = src) || tsrc->ip >= grec->grec_src[i].s_addr)) {
                // IN: (B - A) = 0 / EX: (A - X - Y)
                if (! tsrc || tsrc->ip > grec->grec_src[i].s_addr || (nH = NO_HASH(tsrc, IfDp)))
                    src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, 1, nH, !(swupstr || !nH), psrc, HASH(IfDp, ip));
                if (type == IGMPV3_CHANGE_TO_EXCLUDE && src &&
                    (   ((! tsrc || tsrc->ip > grec->grec_src[i].s_addr) && IS_EX(mct, IfDp))
                     || (tsrc && tsrc->ip == grec->grec_src[i].s_addr && IS_IN(mct, IfDp) && src->dvif[ix].vp)))
                    // IN: Send Q(G, A * B) / EX: Send Q(G, A - Y), (A - X - Y) = Group Timer (last member)
                    qry = addSrcToQlst(src, IfDp, qry);
                IF_GETUVIFL(swupstr && src && !src->nvif.i && src->nvif.e == mct->nvif.e, If) {
                    if (!checkFilters(If, 0, src, src->mct))
                        LOG(LOG_NOTICE, 0, "Source %s denied on %s, adding to source list.", inetFmt(src->ip, 0), If->Name);
                    src->uvif[If->uvifix].j = 1;
                    sl[j][unsrcs++] = src->ip;
                } else if (swupstr) {
                    // EX: Source was also requested in include mode on include mode interface.
                    LOG(LOG_INFO, 0, "Source %s not in exclude mode for %s on all exclude mode interfaces.",
                         inetFmt(src->ip, 0), inetFmt(mct->group, 0));
                   src->uvif[If->uvifix].j = 0;
                }
                psrc = src;
                src = src ? src->dvif[ix].next : tsrc;
            }
        }
        IF_GETUVIFL_IF(swupstr && (j = upvifcount), If, j-- > 0) {
            // Switch upstream filter mode if inlcude mode group was requested in exclude mode on any downstream interface.
            k_setSourceFilter(If, mct->group, MCAST_EXCLUDE, unsrcs, sl[j]);
            _free(sl[j], var, size);   // Alloced by self.
        }
        break;

    case IGMPV3_CHANGE_TO_INCLUDE:
        if ((mct->dvif[ix].vp && mct->dvif[ix].vp->v1age > 0) || IfDp->querier.ver == 1) {
            LOG(LOG_INFO, 0, "Ignoring TO_IN for %s on %s, v1 host/querier present.", inetFmt(group, 0), IfDp->Name);
            break;
        }
        if (nsrcs == 0) {
            // Leave message, check for quicleave.
            CLR_HASH(mct, IfDp, HASH(IfDp, ip));
            QUICKLEAVE(mct, ip);
        }
        if (mct->dvif[ix].vp && IS_EX(mct, IfDp) && !mct->dvif[ix].vp->lm && IQUERY)
            // EX: Send Q(G).
            startQuery(IfDp, &(struct qry){IfDp, mct, (intptr_t)NULL, (1 << 1), IfDp->conf->qry.lmInterval,
                                           IfDp->conf->qry.lmCount, 0, mct->group, {0} });  /* FALLTHRU */
    case IGMPV3_ALLOW_NEW_SOURCES:
    case IGMPV3_MODE_IS_INCLUDE:
        if (nsrcs > 0)
            addGroup(mct, IfDp, 1, 0, HASH(IfDp, ip));
        for (i = 0, src = mct->firstsrc[ix]; src || i < nsrcs; psrc = src, src = src ? src->dvif[ix].next : src) {
            if (src && (i >= nsrcs || src->ip < grec->grec_src[i].s_addr)) {
                if (type == IGMPV3_CHANGE_TO_INCLUDE && src->dvif[ix].vp
                                                     && (IS_IN(mct, IfDp) || src->dvif[ix].vp->age > 0)) {
                    // EX: Send Q(G, X - A) IN: Send Q(G, A - B)
                    delSrc(src, IfDp, 1, 4, true, HASH(IfDp, ip));
                    qry = addSrcToQlst(src, IfDp, qry);
                }
            } else if (i < nsrcs && (! (tsrc = src) || tsrc->ip >= grec->grec_src[i].s_addr)) do {
                if (! (src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, 1, 0, true, psrc, HASH(IfDp, ip))))
                    // IN (B) = GMI, (A + B) / EX: (A) = GMI, (X + A) (Y - A)
                    src = tsrc;
                psrc = src;
                src = ! tsrc && src ? src->dvif[ix].next : src;
            } while (++i < nsrcs && (! tsrc || tsrc->ip >= grec->grec_src[i].s_addr));
        }
        break;

    case IGMPV3_BLOCK_OLD_SOURCES:
        if (!mct->dvif[ix].vp || mct->dvif[ix].vp->v1age > 0 || mct->dvif[ix].vp->v2age > 0 || IfDp->querier.ver < 3) {
            LOG(LOG_INFO, 0, "Ignoring BLOCK for %s on %s, %s.", inetFmt(group, 0), IfDp->Name,
                !mct->dvif[ix].vp ? "not active" : "v1 or v2 host/querier present");
            break;
        }
        for (i = 0, src = mct->firstsrc[ix]; i < nsrcs && (IS_EX(mct, IfDp) || src); ) {
            // IN: Send Q(G, A * B) / EX: Send Q(G, A - Y)
            if (! (tsrc = src) || src->ip >= grec->grec_src[i].s_addr) {
                if (   ((! src || src->ip > grec->grec_src[i].s_addr) && IS_EX(mct, IfDp))
                    || (src->ip == grec->grec_src[i].s_addr && ((IS_IN(mct, IfDp) && src->dvif[ix].vp)
                                       || (IS_EX(mct, IfDp) && (src->dvif[ix].vp->age > 0 || !src->dvif[ix].vp))))) {
                    if (src || (src = addSrc(IfDp, mct, grec->grec_src[i].s_addr, 1, 0, false, psrc, NHASH))) {
                        // (A - X - Y) = Group Timer (last member)
                        delSrc(src, IfDp, 1, 4, true, HASH(IfDp, ip));
                        qry = addSrcToQlst(src, IfDp, qry);
                    } else
                        src = tsrc;
                }
                i++;
            }
            // When quickleave is enabled, check if the client is interested in any other source.
            for (nH = IfDp->conf->dhtSz; nH && src && i < nsrcs && src->ip < grec->grec_src[i].s_addr;
                 nH &= !TST_HASH(src, IfDp, HASH(IfDp, ip)), psrc = src, src = src->dvif[ix].next);
        }
        for (; nH && src && !TST_HASH(src, IfDp, HASH(IfDp, ip)); src = src->dvif[ix].next);
            // When quickleave is enabled and client is not interested in any other source, it effectively left the group.
        if (nH) {
            LOG(LOG_INFO, 0, "Last source in group %s for client %s on %s.", inetFmt(mct->group, 0), inetFmt(ip, 0), IfDp->Name);
            CLR_HASH(mct, IfDp, HASH(IfDp, ip));
            QUICKLEAVE(mct, ip);
        }
    }

    if (IQUERY)
        startQuery(IfDp, qry);
    LOG(LOG_DEBUG, 0, "Updated group entry for %s on VIF #%d %s", inetFmt(group, 0), IfDp->index, IfDp->Name);
}

/**
*   Switches a group from exclude to include mode on interface.
*/
void toInclude(struct mct *mct, struct IfDesc *IfDp) {
    struct IfDesc *If;
    uint32_t      *sl[upvifcount], nsrcs[2] = {0}, size = (mct->nsrcs[1] + 1) * sizeof(uint32_t), i, ix = IfDp->dvifix;
    struct src    *src = mct->firstsrc[ix];
    bool           swupstr = false;

    LOG(LOG_DEBUG, 0, "%s on %s", inetFmt(mct->group, 0), IfDp->Name);
    mct->nvif.e--;
    mct->nvif.i++;
    mct->dvif[ix].vp->mode = 0;
    mct->dvif[ix].vp->v1age = mct->dvif[ix].vp->v2age = -1;
    IF_FOR((swupstr = !mct->nvif.e), (i = 0; i < mct->nvif.u; i++))
        // If this is the last interface to switch to include for the group, upstream must switch too.
        _calloc(sl[i], 1, var, size);   // Freed by self.
    while (src) {
        if (src->dvif[ix].vp && src->dvif[ix].vp->age > 0) {
            // Keep active sources on this or other interfaces.
            LOG(LOG_INFO, 0, "Source #%d %s in group %s on %s age %d.", nsrcs + 1, inetFmt(src->ip, 0),
                inetFmt(mct->group, 0), IfDp->Name, src->dvif[ix].vp->age);
            nsrcs[0]++;
        }
        IF_GETUVIFL(swupstr && src->nvif.i && !src->nvif.e, If) {
            src->uvif[IfDp->uvifix].j = 0;
            // Build source list per upstream interface in case we need to switch mode upstream.
            if (!checkFilters(If, 0, src, mct)) {
                LOG(LOG_NOTICE, 0, "Source %s for group %s not allowed upstream on %s. not adding to source list.",
                    inetFmt(src->ip, 0), inetFmt(mct->group, 0), If->Name);
            } else {
                // Add to source list, nsrcs[1] is used for sources active on interface.
                nsrcs[1]++;
                src->dvif[If->uvifix].j = 1;
                sl[If->uvifix][sl[If->uvifix][mct->nsrcs[1]++]] = src->ip;
            }
        } else if ((swupstr && src->nvif.i && src->nvif.e) || !src->dvif[ix].vp || src->dvif[ix].vp->age == 0) {
            if (swupstr && src->nvif.i && src->nvif.e)
                LOG(LOG_WARNING, 0, "Source %s group %s still active in exclude mode.", inetFmt(src->ip, 0),
                    inetFmt(mct->group, 0));
            if (!src->dvif[ix].vp || src->dvif[ix].vp->age == 0)
                // Remove all inactive sources from group on interface.
                LOG(LOG_INFO, 0, "Remove inactive source %s from group %s on %s.", inetFmt(src->ip, 0),
                    inetFmt(mct->group, 0), IfDp->Name);
            src = delSrc(src, swupstr ? src->IfDp : IfDp, !swupstr, 0, false, NHASH);
        } else
            src = swupstr ? src->next : src->dvif[ix].next;
    }
    if (swupstr)
        mct->mode = 0;
    IF_GETUVIFL(swupstr && nsrcs[1], If) {
        LOG(LOG_INFO, 0, "Switching %s to include mode on %s (#%d).", inetFmt(mct->group, 0), IfDp->Name, nsrcs);
        // If this was the last interface switching to include for the group, upstream must switch filter mode to include too.
        k_setSourceFilter(If, mct->group, MCAST_INCLUDE, sl[If->uvifix][mct->nsrcs[1]], sl[If->uvifix]);
        _free(sl[If->uvifix], var, size);   // Alloced by self.
    }
    if (!nsrcs[0]) {
        LOG(LOG_INFO, 0, "Group %s from %s has no more sources, removing.", inetFmt(mct->group, 0), IfDp->Name);
        delGroup(mct, IfDp, 1);
    }
}

/**
*   Activates, updates or removes a route in the kernel MFC.
*   If called from acceptRouteActivation a new MFC route will be created.
*   If called with pointer to source and activate the route will be updated.
*   If called with pointer to source and !activate the route will be removed.
*/
inline void activateRoute(struct IfDesc *IfDp, void *_src, register uint32_t ip, register uint32_t group, bool activate) {
    struct src    *src = _src;
    struct mct    *mct = src ? src->mct : findGroup(IfDp, group, 0, true);
    struct IfDesc *If;
    uint32_t       ix  = IfDp->uvifix;

    LOG(LOG_DEBUG, 0, "%s->%s on %s (%d)", inetFmt(ip, 0), inetFmt(group, 0), IfDp->Name, activate);
    if (!activate) {
        LOG(LOG_INFO, 0, "Removing route %s -> %s, Vif %s.", inetFmt(ip, 0), inetFmt(group, 0), IfDp->Name);
        // Remove kernel MFC and delete the upstream source.
        k_delMRoute(src->ip, mct->group, src->IfDp);
        src->IfDp = NULL;
        src->bytes = src->rate = 0;
        if (IS_UPSTREAM(IfDp->state)) {
            LST_RM(2, src, IfDp->mfc, uvif[ix], ifm, TTLSZ);            // Alloced by self
        } else {
            LST_RM(2, src, IfDp->mfc, dvif[ix], ifm, TTLSZ);            // Alloced by self
        }
    } else {
        // Install or update kernel MFC. See RFC 3376: 6.3 IGMPv3 Source-Specific Forwarding Rules.
        if (! src && ! (src = addSrc(IfDp, mct, ip, 0, 0, false, src, NHASH))) {
            // Find source or create source in group.
            LOG(LOG_WARNING, 0, "Unable to activate route: %s to %s on %s. Cannot create source.",
                inetFmt(ip, 0), inetFmt(group, 0), IfDp->Name);
            return;
        } else if (! src->IfDp) {
            if (!mct->nvif.i && !mct->nvif.e) {
                mct->stamp.tv_nsec = timerSet(CONF->topQueryInterval * 30, strFmt(1, "Unresolved group (%s)", "",
                                              inetFmt(group, 0)), ageUnknownGroup, IfDp);
                LST_IN(4, mct, IfDp->umct, NULL, uvif[ix], ifm, DVIFSZ);
            }
            clock_gettime(CLOCK_REALTIME, &src->stamp);
            if (IS_UPSTREAM(IfDp->state)) {
                LST_IN(2, src, IfDp->mfc, NULL, uvif[ix], ifm, TTLSZ);  // Freed by self
            } else {
                LST_IN(2, src, IfDp->mfc, NULL, dvif[ix], ifm, TTLSZ);  // Freed by self
            }
            src->IfDp = IfDp;
        }
        memset(src->ttl, 0, src->nvif.d);
        if (!mct->mode && !src->nvif.i) {
            // For include mode group, ignore any senders which have not been explicitely requested downstream.
            LOG(LOG_INFO, 0, "Ignoring unrequested sender %s for include mode group %s on %s.",
                inetFmt(ip, 0), inetFmt(group, 0), IfDp->Name);
        } else if (mct->mode && src->uvif[ix].j) {
            LOG(LOG_INFO, 0, "Ignoring blocked sender %s for include mode group %s on %s.",
                inetFmt(ip, 0), inetFmt(group, 0), IfDp->Name);
        } else if (mct->mode && !checkFilters(IfDp, 0, src, mct)) {
            // In exclude mode, we can explicitely block a denied source and request upstream routers not to send traffic.
            LOG(LOG_NOTICE, 0, "Explicitely blocking denied source %s for group %s on upstream interface %s.",
                inetFmt(src->ip, 0), inetFmt(mct->group, 0), IfDp->Name);
            joinBlockSrc(src, IfDp, true, 1);
        } else if (!mct->mode && !checkFilters(IfDp, 0, src, mct)) {
            // In include mode we will add a blackhole route for sources that are denied upstream.
            LOG(LOG_NOTICE, 0, "Blackhole %s:%s. Denied upstream on %s.", inetFmt(src->ip, 0), inetFmt(mct->group, 0), IfDp->Name);
        } else if (!IS_UPSTREAM(IfDp->state) || !checkFilters(IfDp, 0, src, mct)) {
                // Blackhole any mc traffic that is received on downstream only interface.
            LOG(LOG_INFO, 0, "Blackhole %s -> %s on %s interface %s.", inetFmt(src->ip, 0), inetFmt(mct->group,0),
                !IS_UPSTREAM(IfDp->state) ? "downstream only" : "denied", IfDp->Name);
        } else GETDVIFL_IF(If, mct->dvif[If->dvifix].vp) {
            ix = If->dvifix;
            if ( If == IfDp)
                LOG(LOG_INFO, 0, "Not forwarding source %s to incoming interface %s", inetFmt(src->ip, 0), If->Name);
            else if (!checkFilters(If, 1, src, mct))
                LOG(LOG_NOTICE, 0, "Not forwarding denied source %s to group %s on %s.", inetFmt(src->ip, 0),
                    inetFmt(mct->group, 0), If->Name);
            else if (   (IS_IN(mct, If) && src->dvif[ix].vp  && src->dvif[ix].vp->age > 0 && !NO_HASH(src, If))
                     || (IS_EX(mct, If) && !NO_HASH(mct, If) && (!src->dvif[ix].vp || src->dvif[ix].vp->age > 0)))
                src->ttl[ix] = If->conf->threshold;
            else
                LOG(LOG_INFO, 0, "Not forwarding source %s to group %s on %s.", inetFmt(src->ip, 0),
                    inetFmt(mct->group, 0), If->Name);
            LOG(LOG_INFO, 0, "Setting TTL for Vif #%d %s to %d", If->index, If->Name, src->ttl[ix]);
        }
        LOG(LOG_INFO, 0, "Adding route %s:%s -> %s.", IfDp->Name, inetFmt(ip, 0), inetFmt(group, 0));
        k_addMRoute(src->ip, mct->group, IfDp, src->ttl);
    }

    logRouteTable("Activate Route", 0, -1, (uint32_t)-1, (uint32_t)-1, IfDp);
}

/**
*   Ages active groups in tables.
*/
void ageGroups(struct IfDesc *IfDp) {
    struct mct *mct, *nmct = IfDp->dmct;
    uint32_t    ix = IfDp->dvifix;

    LOG(LOG_DEBUG, 0, "%s", IfDp->Name);
    IfDp->querier.ageTimer = (intptr_t)NULL;
    while ((mct = nmct)) {
        nmct = mct->dvif[ix].next;
        if (mct->dvif[ix].vp->lm)
            continue;
        // Age v1 and v2 compatibility mode.
        if (mct->dvif[ix].vp->v1age > 0 && --mct->dvif[ix].vp->v1age == 0)
            mct->dvif[ix].vp->v1age = -1;
        if (mct->dvif[ix].vp->v2age > 0 && --mct->dvif[ix].vp->v1age == 0)
            mct->dvif[ix].vp->v2age = -1;
        // Age sources in include mode group.
        uint32_t    nsrcs = 0;
        struct src *src   = mct->firstsrc[ix];
        if (IS_IN(mct, IfDp)) while (src) {
            nsrcs += (src->dvif[ix].vp && src->dvif[ix].vp->age > 0);
            if (src->dvif[ix].vp && !src->dvif[ix].vp->lm &&  src->dvif[ix].vp->age > 0 && -- src->dvif[ix].vp->age == 0) {
                LOG(LOG_INFO, 0, "Removing source %s from %s on %s after aging.",
                    inetFmt(src->ip, 0), inetFmt(mct->group, 0), IfDp->Name);
                src = delSrc(src, IfDp, 1, 0, true, NHASH);
            } else
                src = src->dvif[ix].next;
        }
        // Next age group. Switch to include mode if exclude mode group has aged. Remove group if it's left with no sources.
        if (IS_EX(mct, IfDp) && nsrcs && (mct->dvif[ix].vp->age == 0 || --mct->dvif[ix].vp->age == 0)
                                          && mct->dvif[ix].vp->v1age == -1 && mct->dvif[ix].vp->v2age == -1) {
            LOG(LOG_INFO, 0, "Switching group %s to include on %s with #%d sources.", inetFmt(mct->group, 0),
                IfDp->Name, nsrcs);
            toInclude(mct, IfDp);
        } else if (!nsrcs && (!mct->dvif[ix].vp->mode || mct->dvif[ix].vp->age == 0)) {
            LOG(LOG_INFO, 0, "Removed group %s from %s after aging.", inetFmt(mct->group, 0), IfDp->Name);
            nmct = delGroup(mct, IfDp, 1);
        }
    }
    logRouteTable("Age Groups", 1, -1, (uint32_t)-1, (uint32_t)-1, IfDp);
}

/**
*   Ages unknown multicast group
*/
 void ageUnknownGroup(struct src *src) {
    src->mct->stamp.tv_nsec = (intptr_t)NULL;
    delGroup(src->mct, src->IfDp, 0);
}

/**
*   Debug function that writes the routing table entries to the log or sends them to the cli socket specified in arguments.
*/
void logRouteTable(const char *header, int h, int fd, uint32_t addr, uint32_t mask, struct IfDesc *IfDp) {
    struct mct    *mct;
    struct src    *src = h == 0 && fd < 0 ? IfDp->mfc : NULL;
    struct IfDesc *If;
    char          *buf;
    unsigned int   rcount = 1;
    uint64_t       totalb = 0, totalr = 0, i = 0;
    bool           qL = false, nH = false;

    if (fd < 0 && CONF->logLevel < LOG_DEBUG && !SHUTDOWN)
        return;
    if (MCT && SHUTDOWN) {
        while (! MCT[i] && ++i < (1 << CONF->mcTables));
        if (i >= (1 << CONF->mcTables))
            _free(MCT, mct, MCTSZ);  // Alloced by findGroup()
    }
    if (! MCT) {
        LOG(LOG_DEBUG, 0, "Multicast table is empty.");
        if (fd > 0 && h)
            send(fd, "Multicast table is empty.\n", 26, MSG_DONTWAIT);
        return;
    } else if (fd < 0) {
        LOG(LOG_DEBUG, 0, strFmt(1, "Current multicast table (%s: %s):", "", header,
                                 IfDp ? IfDp->Name : addr ? inetFmt(addr, mask) : ""));
        LOG(LOG_DEBUG, 0, "_____|______GRP______|______SRC______|_______In_______|inVif|exVif|____dHost____|"
                          "_______Data_______|______Rate_____");
    } else if (h) {
        buf = strFmt(h, "Current Multicast Table: %s\n_____|______GRP______|______SRC______|_______In_______"
                        "|inVif|exVif|____dHost____|_______Data_______|______Rate_____\n", "",
                     IfDp ? IfDp->Name : addr ? inetFmt(addr, mask) : "");
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
    if (addr != (uint32_t)-1 && mask == (uint32_t)-1)
        mct = findGroup(IfDp, addr, 1, false);
    else if (IfDp)
        mct = h == 0 && fd < 0 ? (src ? src->mct : IfDp->umct) : IfDp->dmct;
    else for (i = 0, mct = MCT[i]; ! mct; mct = MCT[++i]);
    while (mct) {
        if (addr == (uint32_t)-1 || (mct->group & mask) == addr) do {
            IF_GETDVIFL(! IfDp || (fd < 0 && h == 0), If) {
                qL |= If->conf->dhtSz;
                nH |= NO_HASH(mct, If);
            } else {
               qL = IfDp->conf->dhtSz;
               nH = NO_HASH(mct, IfDp);
            }
            if (src) {
                totalb += src->bytes;
                totalr += src->rate;
            }
            if (fd < 0) {
                LOG(LOG_DEBUG, 0, "%4d |%15s|%15s|%16s| %03d | %03d | %11s | %14lld B | %10lld B/s",
                    rcount, inetFmt(mct->group, 0), src ? inetFmt(src->ip, 0) : "", src && src->IfDp ? src->IfDp->Name : "",
                    src ? src->nvif.i : mct->nvif.i, src ? src->nvif.e : mct->nvif.e,
                    !qL ? "not tracked" : nH ? "no" : "yes", src ? src->bytes : 0, src ? src->rate : 0);
            } else {
                buf = strFmt(h, "%4d |%15s|%15s|%16s| %03d | %03d | %11s | %14lld B | %10lld B/s\n",
                             "%d %s %s %s %d %d %s %lld %lld\n", rcount, inetFmt(mct->group, 0),
                                  src ? inetFmt(src->ip, 0) : "", src && src->IfDp ? src->IfDp->Name : "",
                                  src ? src->nvif.i : mct->nvif.i, src ? src->nvif.e : mct->nvif.e,
                                  !qL ? "not tracked" : nH ? "no" : "yes", src ? src->bytes : 0, src ? src->rate : 0);
                send(fd, buf, strlen(buf), MSG_DONTWAIT);
            }
            rcount++;
            if (!(h == 0 && fd < 0))
                src = ! src ? (IfDp ? mct->firstsrc[IfDp->dvifix]  : mct->sources)
                            : (IfDp ? src->dvif[IfDp->dvifix].next : src->next);
        } while (src && !(fd < 0 && h == 0));
        if (addr != (uint32_t)-1 && mask == (uint32_t)-1)
            break;
        if (h == 0 && fd < 0) {
            src = src ? src->uvif[IfDp->uvifix].nextmfc : NULL;
            mct = src ? src->mct : mct->uvif[IfDp->uvifix].next;
        } else if (IfDp) {
            mct = mct->dvif[IfDp->dvifix].next;
        } else {
            mct = mct->next;
            IF_FOR(! mct && ++i < (1 << CONF->mcTables), (mct = MCT[i]; ! mct && ++i < (1 << CONF->mcTables); mct = MCT[i]));
        }
    }
    if (fd < 0) {
        LOG(LOG_DEBUG, 0, "Total|---------------|---------------|----------------|-----|-----|-------------|"
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
        buf = strFmt(1, "Total|---------------|---------------|----------------|-----|-----|-------------|"
                        " %14lld B | %10lld B/s\n", "", totalb, totalr);
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
}
