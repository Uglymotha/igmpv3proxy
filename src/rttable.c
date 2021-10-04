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
*
*   Updates the routingtable according to
*     received request.
*/

#include "igmpv3proxy.h"

/**
*   Routing table structure definitions.
*/
struct sources {
    // Keeps information on sources
    struct sources     *prev;
    struct sources     *next;
    struct routeTable  *croute;                     // Pointer to route
    struct uSources    *usrc;                       // Pointer to active route
    uint32_t            ip;                         // Source IP adress
    uint32_t            lmBits;                     // Per vif last member state
    uint32_t            qryBits;                    // Active query interfaces flag
    uint8_t             age[MAXVIFS];               // Age value for source
    uint32_t            vifBits;                    // Active vifs for source
    uint64_t            downstreamHostsHashTable[]; // Host tracking table
};

struct uSources {
    // Keeps information on upstream sources
    struct uSources    *prev;
    struct uSources    *next;
    struct sources     *src;                      // Pointer to source struct
    uint8_t             vif;                      // Incoming vif index
    uint64_t            bytes, rate;              // Bwcontrol counters
};

struct routeTable {
    // Keeps group and source information.
    struct routeTable  *prev;                     // Pointer to the next group in line.
    struct routeTable  *next;                     // Pointer to the next group in line.
    uint32_t            group;                    // The group to route
    uint32_t            nsrcs;                    // Number of sources for group
    struct sources     *sources;                  // Downstream source list for group
    struct uSources    *usources;                 // Active upstream sources for group

    // Keeps the group states. Per vif flags.
    uint32_t            mode;                     // Mode (include/exclude) for group
    uint32_t            upstrState;               // Upstream membership state
    uint32_t            qryBits;                  // Active query interfaces flag
    uint32_t            lmBits;                   // Last member flag
    uint32_t            v1Bits;                   // v1 compatibility flags
    uint8_t             v1Age[MAXVIFS];           // v1 compatibility timer
    uint32_t            v2Bits;                   // v2 compatibility flags
    uint8_t             v2Age[MAXVIFS];           // v2 compitibility timer
    uint8_t             age[MAXVIFS];             // Downcounter for death.
    uint32_t            vifBits;                  // Bits representing recieving VIFs

    // Keeps downstream hosts information
    uint64_t            downstreamHostsHashTable[];
};

struct qlst {
    struct qlst       *prev;
    struct qlst       *next;
    struct routeTable *croute;                    // Pointer to route being queried
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
static struct routeTable **mrt           = NULL;   // Route tables
static struct qlst        *qL            = NULL;   // List of running GSQ
static uint32_t            qC            = 0;      // Querier count.
static char                msg[TMNAMESZ] = "";     // Timer name buffer

// Prototypes
static struct routeTable     *findRoute(register uint32_t group, bool create);
static inline void            addRoute(struct routeTable* croute, struct IfDesc *IfDp, int dir);
static struct ifRoutes       *delRoute(struct routeTable *croute, struct IfDesc *IfDp, struct ifRoutes *ifr, int dir);
static uint64_t               checkFilters(struct IfDesc *IfDp, int old, int dir, uint32_t src, uint32_t group);
static void                   sendJoinLeaveUpstream(struct routeTable* croute, int join);
static inline struct sources *addSrc(struct routeTable *croute, uint32_t ip, struct sources *dsrc);
static inline struct sources *delSrc(struct sources *dsrc, struct IfDesc *IfDp, uint32_t srcHash);
static inline struct qlst    *addSrcToQlst(struct sources *dsrc, struct IfDesc *IfDp, struct qlst *qlst, uint32_t srcHash);
static void                   toInclude(struct routeTable *croute, struct IfDesc *IfDp);
static inline void            startQuery(struct IfDesc *IfDp, struct qlst *qlst);
static void                   groupSpecificQuery(struct qlst *qlst);
static void                   internUpdateKernelRoute(struct routeTable *route, int activate);

/**
*   Private access function to find a route from a given group, creates new if required.
*/
static struct routeTable *findRoute(register uint32_t group, bool create) {
    struct   routeTable *croute, *nroute;
    uint32_t mrtHash = murmurhash3(group) % CONFIG->routeTables;

    // Initialize the routing tables if necessary.
    if (! mrt) {
        if (! (mrt = calloc(CONFIG->routeTables, sizeof(void *))))  // Freed by clearRoutes()
            LOG(LOG_ERR, errno, "findRoute: Out of memory.");
        memset(mrt, 0, CONFIG->routeTables * sizeof(void *));
    }
    // Find the route (or place for new route) in the table.
    for (croute = mrt[mrtHash];; croute = croute->next) {
        if (croute && croute->group == group)
            return croute;
        if (! croute || ! croute->next || croute->next->group > group) {
            if (!create)
                return NULL;
            else
                break;
        }
    }

    // Create and initialize the new route table entry. Freed by delRoute()
    LOG(LOG_INFO, 0, "findRoute: No existing route for %s. Create new in table %d.", inetFmt(group, 1), mrtHash);
    if (! (nroute = malloc(sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize)))
        LOG(LOG_ERR, errno, "insertRoute: Out of memory.");
    memset(nroute, 0, sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize);
    nroute->group = group;
    if (! mrt[mrtHash] || mrt[mrtHash]->group > group) {
        mrt[mrtHash] = nroute;
        if (croute) {
            croute->prev = nroute;
            nroute->next = croute;
        }
    } else {
        nroute->prev = croute;
        nroute->next = croute->next;
        if (nroute->next)
            nroute->next->prev = nroute;
        croute->next = nroute;
    }

    return nroute;
}

/**
*  Adds a group to an interface.
*/
static inline void addRoute(struct routeTable* croute, struct IfDesc *IfDp, int dir) {
    struct ifRoutes *ifr;
    if (dir)
        BIT_SET(croute->vifBits, IfDp->index);
    else if (croute->vifBits)
        BIT_SET(croute->upstrState, IfDp->index);
    if (! (ifr = malloc(sizeof(struct ifRoutes))))   // Freed by delRoute or freeIfDescL()
        LOG(LOG_ERR, errno, "addRoute: out of memory.");
    *ifr = (struct ifRoutes){ NULL, croute, dir ? IfDp->dRoutes : IfDp->uRoutes };
    if (dir) {
        if (IfDp->dRoutes)
            IfDp->dRoutes->prev = ifr;
        IfDp->dRoutes = ifr;
    } else {
        if (IfDp->uRoutes)
            IfDp->uRoutes->prev = ifr;
        IfDp->uRoutes = ifr;
    }
}

/**
*   Remove a specified route from interface.
*/
static struct ifRoutes *delRoute(struct routeTable* croute, struct IfDesc *IfDp, struct ifRoutes *ifr, int dir) {
    struct ifRoutes *pifr = NULL;
    // Log the cleanup in debugmode...
    LOG(LOG_DEBUG, 0, "delRoute: Removing route entry for %s from %s.",
                       inetFmt(croute->group, 1), IfDp ? IfDp->Name : "all interfaces");

    // Clear route from interface (or all on shutdown) and ckeck if it can be removed completely.
    if (!SHUTDOWN) {
        if (dir) {
            BIT_CLR(croute->vifBits, IfDp->index);
            if (croute->vifBits) {
                // Clear interface and sources flags and Update kernel route table if route still active on other interface.
                BIT_CLR(croute->qryBits, IfDp->index);
                BIT_CLR(croute->lmBits, IfDp->index);
                BIT_CLR(croute->mode, IfDp->index);
                BIT_CLR(croute->v1Bits, IfDp->index);
                BIT_CLR(croute->v2Bits, IfDp->index);
                croute->age[IfDp->index] = croute->v1Age[IfDp->index] = croute->v2Age[IfDp->index] = 0;
                internUpdateKernelRoute(croute, 1);
                for (struct sources *dsrc = croute->sources; dsrc; dsrc = delSrc(dsrc, IfDp, (uint32_t)-1));
            }
        } else
            BIT_CLR(croute->upstrState, IfDp->index);

        if (! ifr)
            for (ifr = dir ? IfDp->dRoutes : IfDp->uRoutes; ifr && ifr->croute != croute; ifr = ifr->next);
        pifr = ifr->prev;
        if (ifr->next)
            ifr->next->prev = ifr->prev;
        if (ifr->prev)
            ifr->prev->next = ifr->next;
        else if (dir)
            IfDp->dRoutes = ifr->next;
        else
            IfDp->uRoutes = ifr->next;
        free(ifr);  // Alloced by addRoute()
    }

    // Check if route should be removed from table.
    if (dir && (! croute->sources || SHUTDOWN)) {
        uint32_t mrtHash = murmurhash3(croute->group) % CONFIG->routeTables;

        LOG(LOG_DEBUG, 0, "delRoute: Deleting route %s from table %d.",inetFmt(croute->group, 1), mrtHash);
        // Send Leave request upstream.
        sendJoinLeaveUpstream(croute, 0);
        internUpdateKernelRoute(croute, 0);

        // Update pointers.
        if (croute == mrt[mrtHash])
            mrt[mrtHash] = croute->next;
        else
            croute->prev->next = croute->next;
        if (croute->next)
            croute->next->prev = croute->prev;

        // Free the memory, and return. Alloced by addSrc() and findRoute().
        for (struct sources *src; croute->sources; src = croute->sources->next, free(croute->sources), croute->sources = src);
        free(croute);  // Alloced by findRoute()
    }

    logRouteTable("Remove route", 1, NULL, 0);
    return pifr;
}

/**
*   Calculates bandwidth fo group/subnet filter.
*/
uint64_t getGroupBw(struct subnet group, struct IfDesc *IfDp) {
    struct routeTable *croute;
    struct uSources   *usrc;
    register uint64_t  bw = 0;

    // Go over all routes and calculate combined bandwith for all routes for subnet/mask.
    GETMRT(croute) {
        if (IS_UPSTREAM(IfDp->state) && (croute->group & group.mask) == group.ip) {
            for (usrc = croute->usources; usrc; usrc = usrc->next)
                bw = usrc->vif == (IfDp->index) ? bw + usrc->rate : bw;
        } else if (IS_DOWNSTREAM(IfDp->state) && (croute->group & group.mask) == group.ip && IS_SET(croute, IfDp)) {
            for (usrc = croute->usources; usrc; usrc = usrc->next)
                bw += usrc->rate;
        }
    }

    return bw;
}

#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
/**
*   Bandwith control processing for BSD systems.
*/
void processBwUpcall(struct bw_upcall *bwUpc, int nr) {
    struct IfDesc   *IfDp;
    struct uSources *usrc;

    // Process all pending BW_UPCALLS.
    for (int i = 0; i < nr; i++, bwUpc++) {
        struct routeTable  *croute = findRoute(bwUpc->bu_dst.s_addr, false);
        if (! croute)
            LOG(LOG_ERR, 0, "BW_UPCALL: Src %s, Dst %s, but no route found.", inetFmt(bwUpc->bu_dst.s_addr, 1), inetFmt(bwUpc->bu_dst.s_addr, 2));

        // Find the source for the upcall and add to counter.
        for (usrc = croute->usources; usr && usrc->src->ip != bwUpc->bu_src.s_addr; usrc = usrc->next);
        if (usrc) {
            usrc->bytes += bwUpc->bu_measured.b_bytes;
            usrc->rate = bwUpc->bu_measured.b_bytes / CONFIG->bwControlInterval;
            LOG(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to Src %s Dst %s, total %lldB (%lld B/s)", bwUpc->bu_measured.b_bytes, inetFmt(usrc->src->ip, 1), inetFmt(croute->group, 2), usrc->bytes, usrc->rate);
            for (GETIFL(IfDp)) {
                // Find the incoming and outgoing interfaces and add to counter.
                if (IfDp->index == usrc->vif || IS_SET(croute, IfDp)) {
                    IfDp->bytes += bwUpc->bu_measured.b_bytes;
                    LOG(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to interface %s (%lld B/s), total %lld.", bwUpc->bu_measured.b_bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
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
    struct IfDesc     *IfDp = NULL;
    struct routeTable *croute;
    struct uSources   *usrc;

    // Reset all interface rate counters.
    for (GETIFL(IfDp))
        IfDp->rate = 0;

    // Go over all routes.
    GETMRT(croute) {
        // Go over all sources.
        for (usrc = croute->usources; usrc; usrc = usrc->next) {
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
            // On Linux get the S,G statistics via ioct. On BSD they are processed by processBwUpcall().
            struct sioc_sg_req siocReq = { {usrc->src->ip}, {croute->group}, 0, 0, 0 };
            if (ioctl(MROUTERFD, SIOCGETSGCNT, (void *)&siocReq, sizeof(siocReq))) {
                LOG(LOG_WARNING, errno, "BW_CONTROL: ioctl failed.");
                continue;
            }
            uint64_t bytes = siocReq.bytecnt - usrc->bytes;
            usrc->bytes += bytes;
            usrc->rate = bytes / CONFIG->bwControlInterval;
            LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to Src %s Dst %s (%lld B/s), total %lld.", bytes, inetFmt(usrc->src->ip, 1), inetFmt(croute->group, 2), usrc->rate, usrc->bytes);
#else
            // On BSD systems go over all interfaces.
            for (GETIFL(IfDp)) {
                if (IfDp->index == usrc->vif || IS_SET(croute, IfDp)) {
                    IfDp->rate += usrc->rate;
                    LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld B/s to interface %s (%lld B/s), total %lld.", usrc->rate, IfDp->Name, IfDp->rate, IfDp->bytes);
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
            LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to interface %s (%lld B/s), total %lld.", bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
        }
    }
#endif

    // Set next timer;
    *tid = timer_setTimer(TDELAY(CONFIG->bwControlInterval * 10), "Bandwidth Control", (timer_f)bwControl, tid);
}

/**
*  ACL and BW evaluation. Returns whether group/src is allowed, blocked or ratelimited.
*/
static uint64_t checkFilters(struct IfDesc *IfDp, register int old, register int dir, register uint32_t src, register uint32_t group) {
    struct filters      *filter;
    uint64_t             bw = ALLOW;

    // Filters are processed top down until a definitive action (BLOCK or ALLOW) is found. The default action when no filter applies is block.
    // Whenever a ratelimit statement is encountered the the total bandwidth of all groups the filter applies to over the interface is calculated.
    // If the result is over the ratelimit specified by the bw variable is updated and processing continues. If more than one ratelimit is applicable
    // only the last is applied. In any case block still means block.
    for (filter = old ? IfDp->oldconf->filters : IfDp->conf->filters; filter; filter = filter->next) {
        if ((filter->dir == IF_STATE_UPSTREAM && dir == IF_STATE_DOWNSTREAM) || (filter->dir == IF_STATE_DOWNSTREAM && dir == IF_STATE_UPSTREAM)) continue;
        if (src == 0 && (group & filter->dst.mask) == filter->dst.ip) {
           if (filter->action > ALLOW) {
               // Set ratelimit for filter. If we are called with a pointer to vifconfig it is for evaluating bwl and we do not do bw control.
               if ((bw = getGroupBw(filter->dst, IfDp)) && bw >= filter->action)
                   LOG(LOG_NOTICE, 0, "BW_CONTROL: Group %s (%lld B/s) ratelimited on %s by filter %s (%lld B/s).", inetFmt(group, 1), bw, IfDp->Name, inetFmts(filter->dst.ip, filter->dst.mask, 2), filter->action);
               else if (bw < filter->action)
                   bw = BLOCK;
           } else if (filter->action == ALLOW) {
               // When joining upstream or evaluating bw lists during config reload the source is not known.
               // Allow the request if the group is valid for any source it is used for joining / leaving and querying groups.
               return bw > ALLOW ? bw : ALLOW;
           }
        } else if ((src & filter->src.mask) == filter->src.ip && (group & filter->dst.mask) == filter->dst.ip && filter->action <= ALLOW) {
           // Process filters top down and apply first match. When action is block return block, otherwise return the set ratelimit (allow by default).
           return filter->action == BLOCK ? BLOCK : bw > ALLOW ? bw : ALLOW;
        }
    }

    return BLOCK;
}

/**
*   Internal function to send join or leave requests for a specified route upstream...
*   When rebuilding interfaces use old IfDesc Table for leaving groups.
*/
static void sendJoinLeaveUpstream(struct routeTable* croute, int join) {
    struct IfDesc *IfDp = NULL;

    // Only join a group if there are listeners downstream. Only leave a group if joined.
    if (join && croute->vifBits == 0) {
        LOG(LOG_DEBUG, 0, "No downstream listeners for group %s. No join sent.", inetFmt(croute->group, 1));
        return;
    }

    for (GETIFL(IfDp)) {
        uint64_t bw = BLOCK;
        // Check if this Request is legit to be forwarded to upstream
        if ((join && !IS_UPSTREAM(IfDp->state)) || (!join && !BIT_TST(croute->upstrState, IfDp->index))) {
            continue;
        } else if (!join && BIT_TST(croute->upstrState, IfDp->index)) {
            LOG(LOG_INFO, 0, "Leaving group %s upstream on interface %s", inetFmt(croute->group, 1), IfDp->Name);
            k_leaveMcGroup(IfDp, croute->group);
            delRoute(croute, IfDp, NULL, 0);
        } else if (CONFIG->bwControlInterval && IfDp->conf->ratelimit > 0 && IfDp->rate > IfDp->conf->ratelimit) {
            LOG(LOG_INFO, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.",
                              IfDp->Name, IfDp->rate, IfDp->conf->ratelimit, inetFmt(croute->group, 1));
        } else if (! (bw = checkFilters(IfDp, 0, IF_STATE_UPSTREAM, 0, croute->group))) {
            LOG(LOG_INFO, 0, "The group address %s may not be forwarded to upstream interface %s.",
                              inetFmt(croute->group, 1), IfDp->Name);
        } else if (bw > ALLOW) {
            LOG(LOG_INFO, 0, "Group %s bandwidth over limit (%lld) on %s. Not joining.",
                              inetFmt(croute->group, 1), bw, IfDp->Name);
        } else if (join) {
            // Build source list for upstream interface.
            // For IN: All active downstream and allowed sources are to be included in the list.
            // For EX: All sources, with timer = 0 on all active interfaces are to be included.
            uint32_t i, nsrcs, *slist;
            struct sources *src;
            if (! (slist = malloc(croute->nsrcs * sizeof(uint32_t))))  // Freed by self
                LOG(LOG_ERR, errno, "sendJoinLeaveUpstream: Out of Memory.");
            for (nsrcs = 0, src = croute->sources; src; src = src->next) {
                if (!croute->mode) {
                    if (!src->vifBits || noHash(src->downstreamHostsHashTable)) {
                        LOG(LOG_INFO, 0, "sendJoinLeaveUpstream: No downstream hosts %s:%s on %s, not adding to source list.",
                                         inetFmt(src->ip, 1), inetFmt(croute->group, 2), IfDp->Name);
                        continue;
                    }
                    if (! checkFilters(IfDp, 0, IF_STATE_UPSTREAM, src->ip, croute->group)) {
                        // Check if source is allowed for group on upstream interface.
                        LOG(LOG_INFO, 0, "sendJoinLeaveUpstream: Source %s not allowed for group %s on interface %s.",
                                         inetFmt(src->ip, 1), inetFmt(croute->group, 2), IfDp->Name);
                        continue;
                    }
                } else {
                    if (src->vifBits != croute->vifBits)
                        continue;
                    else for (i = 0; i < MAXVIFS && ( !((croute->vifBits >> i) & 0x1) || !croute->age[i] ); i++ );
                    if (i >= MAXVIFS)
                        continue;
                }

                LOG(LOG_DEBUG, 0, "sendJoinLeaveUpstream: Adding %s to source list for %s on %s.",
                                   inetFmt(src->ip, 1), inetFmt(croute->group, 2), IfDp->Name);
                slist[nsrcs++] = src->ip;
            }
            // Join the group on interface if necessary.
            if (!BIT_TST(croute->upstrState, IfDp->index) && !(!croute->mode && !nsrcs) && k_joinMcGroup(IfDp, croute->group)) {
                LOG(LOG_INFO, 0, "Joining group %s upstream on interface %s.", inetFmt(croute->group, 1), IfDp->Name);
                addRoute(croute, IfDp, 0);
            }
            // If the group is joined on interface update the source filter. If IN no sources, group is unjoined effectively.
            if (BIT_TST(croute->upstrState, IfDp->index)) {
                k_setSourceFilter(IfDp, croute->group, croute->mode ? MCAST_EXCLUDE : MCAST_INCLUDE, nsrcs, slist);
                if (!croute->mode && !nsrcs)
                    BIT_CLR(croute->upstrState, IfDp->index);
            }
            free(slist);  // Alloced by self
        }
    }
}

/**
*   Clears / Updates all routes and routing table, and sends Joins / Leaves upstream.
*   If called with NULL pointer all routes are removed.
*/
void clearRoutes(void *Dp) {
    struct ifRoutes   *ifr;
    struct routeTable *croute, *proute;
    struct IfDesc     *IfDp     = Dp != CONFIG && Dp != getConfig ? Dp : NULL;
    register uint8_t   oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);

    if (SHUTDOWN || Dp == CONFIG || Dp == getConfig || (!IS_UPSTREAM(oldstate) && IS_UPSTREAM(newstate))) {
        GETMRT(croute) {
            if (SHUTDOWN) {
                proute = croute->prev;
                delRoute(croute, NULL, NULL, 1);
                croute = proute;
            } else if (Dp == CONFIG) {
                struct sources **src;
                // Quickleave was enabled or disabled, or hastable size was changed.
                // Reallocate appriopriate amount of memory and reinitialize downstreahosts tracking.
                for (src = &(croute->sources); *src; src = &(*src)->next) {
                    if (! (*src = realloc(*src, sizeof(struct sources) + CONFIG->downstreamHostsHashTableSize)))
                        LOG(LOG_ERR, errno, "clearRoutes: Out of memory.");
                    if (CONFIG->fastUpstreamLeave)
                        memset((*src)->downstreamHostsHashTable, 0, CONFIG->downstreamHostsHashTableSize);
                }
                if (! (croute = realloc(croute, sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize)))
                    LOG(LOG_ERR, errno, "clearRoutes: Out of memory.");
                if (CONFIG->fastUpstreamLeave)
                    memset(croute->downstreamHostsHashTable, 0, CONFIG->downstreamHostsHashTableSize);
                if (! croute->prev)
                    mrt[iz] = croute;
                else
                    croute->prev->next = croute;
                if (croute->next)
                    croute->next->prev = croute;
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
            } else if (Dp == getConfig) {
                // BW control interval was changed. Reinitialize all bw_upcalls.
                struct uSources *usrc;
                for (usrc = croute->usources; usrc; usrc = usrc->next) {
                    k_deleteUpcalls(usrc->src->ip, croute->group);
                    internUpdateKernelRoute(croute, 1);
                }
#endif
            } else {
                // New upstream interface added, join all relevant groups.
                sendJoinLeaveUpstream(croute, 1);
                LOG(LOG_DEBUG, 0, "clearRoutes: Joining group %s on new upstream interface %s.",
                                   inetFmt(croute->group, 1), IfDp->Name);
            }
        }
        // Check if routing tables are empty.
        for (iz = 0; mrt && iz < CONFIG->routeTables && ! mrt[iz]; iz++);
        if (iz == CONFIG->routeTables) {
            free(mrt);  // Alloced by findRoute()
            mrt = NULL;
            LOG(LOG_INFO, 0, "clearRoutes: Routing table is empty.");
        }
        return;
    }

    // Upstream interface transition.
    for (ifr = IfDp->uRoutes; ifr; ifr = ifr->next) {
        croute = ifr->croute;
        if (IS_UPSTREAM(newstate) || IS_UPSTREAM(oldstate)) {
            if ((CONFRELOAD || SSIGHUP) && IS_UPSTREAM(newstate) && IS_UPSTREAM(oldstate)) {
                if (   checkFilters(IfDp, 0, IF_STATE_UPSTREAM, 0, croute->group) != ALLOW
                    && checkFilters(IfDp, 1, IF_STATE_UPSTREAM, 0, croute->group) == ALLOW) {
                    // Group is no longer allowed. Leave.
                    LOG(LOG_WARNING, 0, "clearRoutes: Leaving group %s on %s, no longer allowed.",
                                         inetFmt(croute->group, 1), IfDp->Name);
                    k_leaveMcGroup(IfDp, croute->group);
                    ifr = delRoute(croute, IfDp, ifr, 0);
                } else if (   checkFilters(IfDp, 0, IF_STATE_UPSTREAM, 0, croute->group) == ALLOW
                           && checkFilters(IfDp, 1, IF_STATE_UPSTREAM, 0, croute->group) != ALLOW) {
                    // Group is now allowed on upstream interface, join.
                     sendJoinLeaveUpstream(croute, 1);
                     LOG(LOG_INFO, 0, "clearRoutes: Joining group %s on %s, it is now allowed.",
                                       inetFmt(croute->group, 1), IfDp->Name);
                }
            } else if (!IS_UPSTREAM(newstate) && BIT_TST(croute->upstrState, IfDp->index)) {
                // Transition from upstream to downstream or disabled. Leave group.
                k_leaveMcGroup(IfDp, croute->group);
                ifr = delRoute(croute, IfDp, ifr, 0);
                LOG(LOG_WARNING, 0, "clearRoutes: Leaving group %s on %s, no longer upstream.",
                                     inetFmt(croute->group, 1), IfDp->Name);
            }
        }
    }

    // Downstream interface transition.
    for (ifr = IfDp->dRoutes; ifr; ifr = ifr ? ifr->next : IfDp->dRoutes) {
        croute = ifr->croute;
        if (!IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate))
            // Transition to disabled / upstream, remove from route.
            LOG(LOG_INFO, 0, "clearRoutes: Vif %d - %s removed, removing from route %s.",
                              IfDp->index, IfDp->Name, inetFmt(croute->group, 1));
            // Check against bl / wl changes on config reload / sighup.
        else if (IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate) && (CONFRELOAD || SSIGHUP)
                                           && checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, 0, croute->group) != ALLOW
                                           && checkFilters(IfDp, 1, IF_STATE_DOWNSTREAM, 0, croute->group) == ALLOW)
            LOG(LOG_INFO, 0, "clearRoutes: Group %s no longer allowed on Vif %d - %s, removing from route.",
                              inetFmt(croute->group, 1), IfDp->index, IfDp->Name);
        else
            continue;

        // Clear query bits and remove route.
        ifr = delRoute(croute, IfDp, ifr, 1);
    }

    logRouteTable("Clear Routes", 1, NULL, 0);
}

/**
*   Creates a new source for route and adds it to list of sources. Doubly linked list
*   with prev of fist pointing to last item in queue. We will be called from updateRoute()
*   which as it evaluates the list in linear order knows exactly where source should be
*   created in list, no dsrc if it should go to end of list.
*/
static inline struct sources *addSrc(struct routeTable *croute, uint32_t ip, struct sources *dsrc) {
    struct sources *nsrc;
    if (croute->nsrcs >= CONFIG->maxOrigins) {
        if ((croute->nsrcs & 0x80000000) == 0) {
            croute->nsrcs |= 0x80000000;
            LOG(LOG_WARNING, 0, "Max origins (%d) exceeded for %s.",
                                 CONFIG->maxOrigins, inetFmt(croute->group, 1), inetFmt(ip, 2));
        }
        return NULL;
    }
    // Check if source was already created, if hosts send reports with duplicate ip's it may break stuff.
    if (! dsrc && croute->sources && croute->sources->prev->ip == ip)
        return croute->sources->prev;
    if (dsrc && dsrc->prev->ip == ip)
        return dsrc->prev;

    LOG(LOG_DEBUG, 0, "addSrc: New source %s for group %s.", inetFmt(ip, 1), inetFmt(croute->group, 2));
    if (! (nsrc = malloc(sizeof(struct sources) + CONFIG->downstreamHostsHashTableSize)))
        LOG(LOG_ERR, errno, "addSrc: Out of memory.");   // Freed by delSrc()
    memset(nsrc, 0, sizeof(struct sources) + CONFIG->downstreamHostsHashTableSize);
    nsrc->ip = ip;
    nsrc->croute = croute;
    if (! croute->sources) {
        croute->sources = nsrc;
        nsrc->prev = nsrc;
    } else if (! dsrc) {
        nsrc->prev = croute->sources->prev;
        nsrc->prev->next = croute->sources->prev = nsrc;
    } else {
        nsrc->prev = dsrc->prev;
        if (croute->sources == dsrc)
            croute->sources = nsrc;
        else
            nsrc->prev->next = nsrc;
        nsrc->next = dsrc;
        dsrc->prev = nsrc;
    }
    croute->nsrcs++;
    return nsrc;
}

/**
*   Removes a source from the list of group sources.
*/
static inline struct sources *delSrc(struct sources *dsrc, struct IfDesc *IfDp, uint32_t srcHash) {
    struct sources *nsrc = dsrc->next;

    LOG(LOG_INFO, 0, "delSrc: Remove source %s from %s.", inetFmt(dsrc->ip, 1), inetFmt(dsrc->croute->group, 2));
    if (srcHash != (uint32_t)-1)
        clearHash(dsrc->downstreamHostsHashTable, srcHash);
    BIT_CLR(dsrc->vifBits, IfDp->index);
    BIT_CLR(dsrc->qryBits, IfDp->index);
    BIT_CLR(dsrc->lmBits, IfDp->index);
    dsrc->age[IfDp->index] = 0;

    if (!dsrc->vifBits && !dsrc->usrc) {
        dsrc->croute->nsrcs &= ~0x80000000;
        dsrc->croute->nsrcs--;
        if (dsrc->next)
            dsrc->next->prev = dsrc->prev;
        if (dsrc == dsrc->croute->sources)
            dsrc->croute->sources = dsrc->next;
        else
            dsrc->prev->next = dsrc->next;
        free(dsrc);  // Alloced by addSrc()
    }

    return nsrc;
}

/**
*   Adds a specified route to the routingtable or updates the route if it exists.
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
void updateRoute(struct IfDesc *IfDp, uint32_t src, struct igmpv3_grec *grec) {
    uint16_t     i = 0, type    = grecType(grec), nsrcs = grecNscrs(grec);
    uint32_t            group   = grec->grec_mca.s_addr,
                        srcHash = CONFIG->fastUpstreamLeave ? murmurhash3(src) % (CONFIG->downstreamHostsHashTableSize) : 0;
    struct qlst        *qlst, *qlst1;
    struct routeTable  *croute;
    struct sources    *dsrc, *tsrc;

    // Return if request is bogus (BLOCK / ALLOW / IS_IN with no sources, or no route when BLOCK or TO_IN with no sources).
    if ((nsrcs == 0 && (type == IGMPV3_ALLOW_NEW_SOURCES || type == IGMPV3_MODE_IS_INCLUDE || type == IGMPV3_BLOCK_OLD_SOURCES))
       || ! (croute = findRoute(group, !((type == IGMPV3_CHANGE_TO_INCLUDE && nsrcs == 0) || type == IGMPV3_BLOCK_OLD_SOURCES))))
        return;

    // Initialze the query list and sort array of sources in group report..
    if (! (qlst = malloc(sizeof(struct qlst))))  // Freed by startQuery() or groupSpecificQuery().
        LOG(LOG_ERR, errno, "updateRoute: Out of Memory.");
    *qlst = (struct qlst){ NULL, NULL, croute, IfDp, 0, 0, IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount, 0, 0 };
    sortArr((uint32_t *)grec->grec_src, nsrcs);
    LOG(LOG_DEBUG, 0, "updateRoute: Processing %s with %d sources for %s on %s.",
                       grecKind(type), nsrcs, inetFmt(group, 1), IfDp->Name);

    // Toggle compatibility modes if older version reports are received.
    if (grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT) {
        LOG(LOG_INFO, 0, "Detected v1 host on %s. Setting compatibility mode for %s.", IfDp->Name, inetFmt(group, 1));
        BIT_SET(croute->v1Bits, IfDp->index);
        croute->v1Age[IfDp->index] = IfDp->querier.qrv;
    } else if (grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT || grec->grec_type == IGMP_V2_LEAVE_GROUP) {
        LOG(LOG_INFO, 0, "Detected v2 host on %s. Setting compatibility mode for %s.", IfDp->Name, inetFmt(group, 1));
        BIT_SET(croute->v2Bits, IfDp->index);
        croute->v2Age[IfDp->index] = IfDp->querier.qrv;
    }

    bool join = true;
    switch (type) {
    case IGMPV3_CHANGE_TO_EXCLUDE:
        if ((BIT_TST(croute->v1Bits, IfDp->index) || BIT_TST(croute->v2Bits, IfDp->index || IfDp->querier.ver < 3)) && nsrcs > 0) {
            LOG(LOG_INFO, 0, "updateRoute: Ignoring %d sources for %s on %s, v1 or v2 host/querier present.",
                               nsrcs, inetFmt(group, 1), IfDp->Name);
            nsrcs = 0;
        } /* FALLTHRU */
    case IGMPV3_MODE_IS_EXCLUDE:
        if (checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, INADDR_ANY, group) < ALLOW) {
            LOG(LOG_NOTICE, 0, "Group %s may not be requested on %s.", inetFmt(group, 1), IfDp->Name);
            return;
        }
        if (!IS_SET(croute, IfDp))
            addRoute(croute, IfDp, 1);
        croute->age[IfDp->index] = IfDp->querier.qrv;  // Group timer = GMI
        BIT_CLR(croute->lmBits, IfDp->index);
        setHash(croute->downstreamHostsHashTable, srcHash);

        qlst->type = 4;
        for (i = 0, dsrc = croute->sources; dsrc || i < nsrcs; i++) {
            if (i >= nsrcs || (dsrc && dsrc->ip < grec->grec_src[i].s_addr)) {
                // IN: Delete (A-B) / EX: Delete (X - A), Delete (Y - A)
                for (;dsrc && (i >= nsrcs || dsrc->ip < grec->grec_src[i].s_addr); dsrc = delSrc(dsrc, IfDp, srcHash));
            } else if ((i < nsrcs && (! (tsrc = dsrc) || tsrc->ip > grec->grec_src[i].s_addr)
                                  && (dsrc = addSrc(croute, grec->grec_src[i].s_addr, tsrc)))
                                  || (tsrc && tsrc->ip == grec->grec_src[i].s_addr)) {
                // IN: Send Q(G, A*B), (B-A) = 0 / EX: Send Q(G, A-Y), (A - X - Y) = Group Timer?
                BIT_SET(dsrc->vifBits, IfDp->index);
                if (type == IGMPV3_CHANGE_TO_EXCLUDE
                          && ( ((! tsrc || tsrc->ip > grec->grec_src[i].s_addr) && IS_EX(croute, IfDp))
                          || (  (tsrc && tsrc->ip == grec->grec_src[i].s_addr) && ((IS_IN(croute, IfDp) && IS_SET(dsrc, IfDp))
                             || (IS_EX(croute, IfDp) && (NOT_SET(dsrc, IfDp) || dsrc->age[IfDp->index] > 0)))) ))
                    qlst = addSrcToQlst(dsrc, IfDp, qlst, srcHash);
                dsrc = dsrc->next;
            }
        }
        BIT_SET(croute->mode, IfDp->index);
        break;

    case IGMPV3_CHANGE_TO_INCLUDE:
        if (BIT_TST(croute->v1Bits, IfDp->index) || IfDp->querier.ver == 1) {
            LOG(LOG_INFO, 0, "updateRoute: Ignoring TO_IN for %s on %s, v1 host/querier present.", inetFmt(group, 1), IfDp->Name);
            return;
        }
        if (nsrcs == 0) {
            clearHash(croute->downstreamHostsHashTable, srcHash);
            if (!(join = !noHash(croute->downstreamHostsHashTable)))
                LOG(LOG_INFO, 0, "updateRoute: Quickleave enabled, %s was the last downstream host, leaving group %s now",
                                  inetFmt(src, 1), inetFmt(group, 2));
        }
        if (IS_EX(croute, IfDp) && !BIT_TST(croute->lmBits, IfDp->index)) {
            if (! (qlst1 = malloc(sizeof(struct qlst))))  // // Freed by startQuery() or groupSpecificQuery().
                LOG(LOG_ERR, errno, "updateRoute: Out of Memory.");
            *qlst1 = (struct qlst){ NULL, NULL, croute, IfDp, 0, 0x2, IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount, 0, 0 };
            startQuery(IfDp, qlst1);
        }  /* FALLTHRU */
    case IGMPV3_ALLOW_NEW_SOURCES:
    case IGMPV3_MODE_IS_INCLUDE:
        if (nsrcs > 0 && !IS_SET(croute, IfDp))
            addRoute(croute, IfDp, 1);

        qlst->type = croute->mode ? 0x8 : 0x4;
        for (i = 0, dsrc = croute->sources; dsrc || i < nsrcs; dsrc = dsrc ? dsrc->next : dsrc) {
            if (dsrc && (i >= nsrcs || dsrc->ip < grec->grec_src[i].s_addr)) {
                if (type == IGMPV3_CHANGE_TO_INCLUDE && IS_SET(dsrc, IfDp) && (IS_IN(croute, IfDp) || dsrc->age[IfDp->index] > 0))
                    // EX: Send Q(G, X-A) IN: Send Q(G, A-B)
                    qlst = addSrcToQlst(dsrc, IfDp, qlst, (uint32_t)-1);
                continue;
            }
            for (;i < nsrcs && checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, grec->grec_src[i].s_addr, group) < ALLOW; i++)
                LOG(LOG_INFO, 0, "updateRoute: Group %s from %s may not be requested on %s.", inetFmt(group, 1),
                                                            inetFmt(grec->grec_src[i].s_addr, 2), IfDp->Name);
            if (i < nsrcs && (! dsrc || dsrc->ip >= grec->grec_src[i].s_addr)) {
                if ((! (tsrc = dsrc) || tsrc->ip >= grec->grec_src[i].s_addr)) do {
                    if ((! tsrc || tsrc->ip > grec->grec_src[i].s_addr))
                        dsrc = addSrc(croute, grec->grec_src[i].s_addr, tsrc);
                    // IN (B) = GMI, (A + B) / EX: (A) = GMI, (X + A) (Y - A)
                    BIT_SET(dsrc->vifBits, IfDp->index);
                    BIT_CLR(dsrc->lmBits, IfDp->index);
                    dsrc->age[IfDp->index] = IfDp->querier.qrv;
                    setHash(dsrc->downstreamHostsHashTable, srcHash);
                    dsrc = ! tsrc ? dsrc->next : dsrc;
                } while (++i < nsrcs && (! tsrc || tsrc->ip >= grec->grec_src[i].s_addr));
            }
        }
        break;

    case IGMPV3_BLOCK_OLD_SOURCES:
        if (BIT_TST(croute->v1Bits, IfDp->index) || BIT_TST(croute->v2Bits, IfDp->index) || IfDp->querier.ver < 3) {
            LOG(LOG_INFO, 0, "updateRoute: Ignoring BLOCK for %s on %s, v1 or v2 host/querier present.",
                              inetFmt(group, 1), IfDp->Name);
            return;
        }

        qlst->type = 4;
        for (i = 0, dsrc = croute->sources; (dsrc || i < nsrcs) && !(IS_IN(croute, IfDp) && ! dsrc); i++) {
            if ((dsrc && dsrc->ip == grec->grec_src[i].s_addr && IS_SET(dsrc, IfDp)
                     && (IS_IN(croute, IfDp) || (IS_EX(croute, IfDp) && dsrc->age[IfDp->index] == 0)))
                     || (IS_EX(croute, IfDp) && i < nsrcs && (! dsrc || dsrc->ip > grec->grec_src[i].s_addr)
                                             && (dsrc = addSrc(croute, grec->grec_src[i].s_addr, dsrc)))) {
                // IN: Send Q(G,A*B) / EX: Send Q(G,A-Y), (A-X-Y) = Group Timer?
                qlst = addSrcToQlst(dsrc, IfDp, qlst, srcHash);
            }
            for (;dsrc && dsrc->ip <= grec->grec_src[i].s_addr; dsrc = dsrc->next);
        }
    }

    // Delete route if it is INCLUDE no sources.
    if (!croute->mode && !croute->nsrcs) {
        delRoute(croute, IfDp, NULL, 1);
        return;
    }

    // Send Query if required.
    startQuery(IfDp, qlst);

    // Send join message upstream.
    sendJoinLeaveUpstream(croute, join);

    // Update route in kernel...
    internUpdateKernelRoute(croute, 1);

    // Log the update in debugmode...
    LOG(LOG_DEBUG, 0, "Updated route entry for %s on VIF #%d", inetFmt(group, 1), IfDp->index);
    logRouteTable("Update Route", 1, NULL, 0);
}

/**
*   Switches a group from exclude to include mode.
*   Returns false if route IS_IN no sources (can be deleted by caller).
*/
static void toInclude(struct routeTable *croute, struct IfDesc *IfDp) {
    struct sources *dsrc = croute->sources;

    LOG(LOG_INFO, 0, "TO_IN: Switching mode for %s to include on %s.", inetFmt(croute->group, 1), IfDp->Name);
    BIT_CLR(croute->mode, IfDp->index);
    BIT_CLR(croute->v2Bits, IfDp->index);
    croute->age[IfDp->index] = croute->v2Age[IfDp->index] = 0;
    while (dsrc) {
         if (IS_SET(dsrc, IfDp) && dsrc->age[IfDp->index] == 0) {
             LOG(LOG_DEBUG, 0, "TO_IN: Removed inactive source %s from group %s.", inetFmt(dsrc->ip, 1), inetFmt(croute->group, 2));
             dsrc = delSrc(dsrc, IfDp, (uint32_t)-1);
         } else
             dsrc = dsrc->next;
    }
}

/**
*   Adds a source to list of sources to query. Toggles appropriate flags and adds to qlst array.
*/
static inline struct qlst *addSrcToQlst(struct sources *dsrc, struct IfDesc *IfDp, struct qlst *qlst, uint32_t srcHash) {
    uint16_t     i, nsrcs = qlst->nsrcs;
    struct qlst       *ql = NULL;

    // Add source to query list if required, prevent duplicates.
    if ((BIT_TST(qlst->type, 5) || IQUERY) && (!nsrcs || qlst->src[qlst->nsrcs - 1]->ip != dsrc->ip)) {
        // In case source is in running query, remove it there and add to current list.
        if (BIT_TST(dsrc->qryBits, IfDp->index)) {
            for (ql = qL; ql && !(ql->croute == dsrc->croute && ql->IfDp == IfDp); ql = ql->next);
            for (i = 0; ql && i < ql->nsrcs && ql->src[i] != dsrc; i++);
            if (ql && i < ql->nsrcs) {
                LOG(LOG_NOTICE, 0, "Existing query for Source %s in group %s on %s.",
                                    inetFmt(ql->src[i]->ip, 1), inetFmt(ql->croute->group, 2), ql->IfDp->Name);
                ql->src[i] = ql->src[--ql->nsrcs];
            }
        }

        // Add to source to the qery list. Allocate memory per 32 sources.
        LOG(LOG_INFO, 0, "addSrcToQlst: Adding source %s to query list for %s (%d).",
                          inetFmt(dsrc->ip, 1), inetFmt(dsrc->croute->group, 2), nsrcs + 1);
        if ((nsrcs & 0x1F) == 0 && ! (qlst = realloc(qlst, sizeof(struct qlst) + ((nsrcs >> 5) + 1) * 0x20 * sizeof(void *))))
            LOG(LOG_ERR, errno, "addSrcToQlst; Out of Memory.");  // Freed by startQuery() or groupSpecificQuery().
        if (srcHash != (uint32_t)-1)
            clearHash(dsrc->downstreamHostsHashTable, srcHash);
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
    struct routeTable *croute = findRoute(query->igmp_group.s_addr, false);
    uint16_t           nsrcs = ver == 2 ? 0 : ntohs(query->igmp_nsrcs);
    struct qlst       *qlst;
    struct sources   *dsrc;

    // If no route found for query, or not active on interface return.
    if (! croute || !IS_SET(croute, IfDp))
        return;

    // Initialize query list and sort array of sources in query.
    if (! (qlst = malloc(sizeof(struct qlst) + nsrcs * sizeof(void *))))  // Freed by startQuery() or groupSpecificQuery().
        LOG(LOG_ERR, errno, "processGroupQuery: Out of Memory.");
    *qlst = (struct qlst){ NULL, NULL, croute, IfDp, 0, 0,
                           query->igmp_code, ver == 3 ? query->igmp_misc & ~0x8 : IfDp->conf->qry.lmCount, 0, 0 };
    sortArr((uint32_t *)query->igmp_src, nsrcs);

    if (nsrcs == 0) {
        LOG(LOG_DEBUG, 0, "processGroupQuery: Group specific query for %s on %s.", inetFmt(croute->group, 1), IfDp->Name);
        qlst->type = 0x10;
    } else {
        LOG(LOG_DEBUG, 0, "processGroupQuery: Group group and source specific query for %s with %d sources on %s.",
                           inetFmt(croute->group, 1), nsrcs, IfDp->Name);
        qlst->type = 0x20;
        uint16_t i;
        for (dsrc = croute->sources, i = 0; dsrc && i < nsrcs; i++, dsrc = dsrc ? dsrc->next : dsrc) {
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
    if (  ( (BIT_TST(qlst->type, 2) || BIT_TST(qlst->type, 3) || BIT_TST(qlst->type, 5)) && qlst->nsrcs == 0)
       || ( !BIT_TST(qlst->type, 4) && !BIT_TST(qlst->type, 5) && !IQUERY)) {
        free(qlst);  // Alloced by updateRoute, addSrcToQlst() or processGroupQuery().
        return;
    }

    // Check if we should take over for a running GSQ.
    if ((BIT_TST(qlst->type, 1) || BIT_TST(qlst->type, 4)) && BIT_TST(qlst->croute->qryBits, IfDp->index)) {
        struct qlst *ql;
        for (ql = qL; ql && !(ql->croute == qlst->croute && ql->IfDp == qlst->IfDp); ql = ql->next);
        if (ql) {
            LOG(LOG_NOTICE, 0, "Removing existing query for %d on %s.", inetFmt(ql->croute->group, 1), ql->IfDp->Name);
            timer_clearTimer(ql->tid);
            if (ql->next)
                ql->next->prev = ql->prev;
            if (ql->prev)
                ql->prev->next = ql->next;
            if (qL == ql)
                qL = ql;
            qC--;
            free(ql);  // Alloced by updateRoute(), addSrcToQlst() or processGroupQuery().
        }
    }

    // Allocate and assign new querier.
    if (qL) {
        qlst->next = qL;
        qL->prev = qlst;
    }
    qL = qlst;
    qC++;

    if (qlst->nsrcs == 0) {
        LOG(LOG_INFO, 0, "startQuery #%d: Querying group %s on %s.", qC, inetFmt(qlst->croute->group, 1), IfDp->Name);
        BIT_SET(qlst->croute->qryBits, IfDp->index);
        BIT_SET(qlst->croute->lmBits, IfDp->index);
        qlst->croute->age[IfDp->index] = qlst->misc;
    } else
        LOG(LOG_INFO, 0, "startQuery #%d: Querying %d sources for %s on %s.",
                         qC, qlst->nsrcs, inetFmt(qlst->croute->group, 1), IfDp->Name);
    groupSpecificQuery(qlst);
}

/**
*   Sends a group specific member report query until the group times out.
*   bit 0 - Router Supress flag
*   bit 1 - Group Specific Query
*   bit 2 - Group and Source Specific query
*   bit 3 - Group and Source Specific query only
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
            if (!BIT_TST(qlst->croute->lmBits, qlst->IfDp->index)) {
                LOG(LOG_INFO, 0, "GSQ: %s no longer in last member state on %s.", inetFmt(qlst->croute->group, 1), qlst->IfDp->Name);
                BIT_SET(qlst->type, 0);  // Suppress router processing flag for next query.
                if (BIT_TST(qlst->type, 4))
                    // If just aging because of other querier, we're done.
                    qlst->cnt = qlst->misc;
            } else if (--qlst->croute->age[qlst->IfDp->index] == 0) {
                // Group in exclude mode has aged, switch to include.
                LOG(LOG_DEBUG, 0, "GSQ: Switch group %s to inlcude on %s after querying.",
                                  inetFmt(qlst->croute->group, 1), qlst->IfDp->Name);
                qlst->cnt = qlst->misc;  // Make sure we're done.
                if (!BIT_TST(qlst->croute->v1Bits, qlst->IfDp->index))
                    // RFC says v2 routes should not switch, but v2 hosts should respond to query, so should be safe
                    toInclude(qlst->croute, qlst->IfDp);
            }

        } else if (BIT_TST(qlst->type, 2) || BIT_TST(qlst->type, 3) || BIT_TST(qlst->type, 5)) {
            // Age sources in case of GSSQ. Create two queries (1 - sources still last member 2 - active source).
            if (! (query1 = malloc(size)) || ! (query2 = malloc(size)))  // Freed by self.
                LOG(LOG_ERR, errno, "GSQ: Out of Memory.");
            *query1 = (struct igmpv3_query){ qlst->type      , qlst->code, 0, {qlst->croute->group}, qlst->misc, 0, 0 };
            *query2 = (struct igmpv3_query){ qlst->type | 0x1, qlst->code, 0, {qlst->croute->group}, qlst->misc, 0, 0 };
            while (i < qlst->nsrcs) {
                if (!BIT_SET(qlst->src[i]->lmBits, qlst->IfDp->index) || NOT_SET(qlst->src[i], qlst->IfDp)) {
                    // Source no longer in last member state.
                    LOG(LOG_INFO, 0, "GSQ: Source %s for group %s no longer in last member state on %s.",
                                      inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->croute->group, 2), qlst->IfDp->Name);
                    query2->igmp_src[query2->igmp_nsrcs++].s_addr = qlst->src[i++]->ip;
                } else if (--qlst->src[i]->age[qlst->IfDp->index] == 0) {
                    // Source expired. Remove from query list.
                    BIT_CLR(qlst->src[i]->qryBits, qlst->IfDp->index);
                    BIT_CLR(qlst->src[i]->lmBits, qlst->IfDp->index);
                    if (IS_IN(qlst->croute, qlst->IfDp)) {
                        // Aged source in include mode should be removed.
                        LOG(LOG_INFO, 0, "GSQ: Removed inactive source %s from group %s on %s.",
                                          inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->croute->group, 2), qlst->IfDp->Name);
                        delSrc(qlst->src[i], qlst->IfDp, (uint32_t)-1);
                    } else
                        // In exclude mode sources should be kept.
                        LOG(LOG_INFO, 0, "GSQ: Source %s from group %s on %s expired.",
                                          inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->croute->group, 2), qlst->IfDp->Name);
                    qlst->src[i] = qlst->src[--qlst->nsrcs];
                } else
                    // Source still in last member state, add to  query.
                    query1->igmp_src[query1->igmp_nsrcs++].s_addr = qlst->src[i++]->ip;
            }
        }
    }

    if (qlst->cnt++ < qlst->misc) {
        // Send a query if not aging for other querier.
        if (!BIT_TST(qlst->type, 4) && !BIT_TST(qlst->type, 5)) {
            if (qlst->cnt == 1 || BIT_TST(qlst->type, 1)) {
                // Use qlst in case of group query, or first group and source query.
                if (! (query = malloc(sizeof(struct igmpv3_query) + qlst->nsrcs * sizeof(struct in_addr))))
                    LOG(LOG_ERR, errno, "GSQ: Out of Memory.");
                *query = (struct igmpv3_query){ qlst->type, qlst->code, 0, {qlst->croute->group}, qlst->misc, 0, qlst->nsrcs };
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
        // Set timer for next round.
        sprintf(msg, "GSQ (%s): %15s/%u", qlst->IfDp->Name, inetFmt(qlst->croute->group, 1), qlst->nsrcs);
        uint32_t timeout = BIT_TST(qlst->type, 4) || BIT_TST(qlst->type, 5) ? qlst->code
                         : qlst->IfDp->querier.ver == 3 ? getIgmpExp(qlst->IfDp->conf->qry.lmInterval, 0)
                         : qlst->IfDp->conf->qry.lmInterval;
        qlst->tid = timer_setTimer(TDELAY(timeout), msg, (timer_f)groupSpecificQuery, qlst);

    } else if (qlst->cnt >= qlst->misc) {
        // Done querying. Remove current querier from list and free.
        LOG(LOG_INFO, 0, "GSQ: done querying %d sources for %s on %s.",
                          nsrcs, inetFmt(qlst->croute->group, 1), qlst->IfDp->Name);
        // Clear last member and query bits.
        if (BIT_TST(qlst->type, 1) || BIT_TST(qlst->type, 4)) {
            BIT_CLR(qlst->croute->lmBits, qlst->IfDp->index);
            BIT_CLR(qlst->croute->qryBits, qlst->IfDp->index);
        } else
            for (uint16_t i = 0; i < qlst->nsrcs; BIT_CLR(qlst->src[i]->lmBits, qlst->IfDp->index),
                                                  BIT_CLR(qlst->src[i]->qryBits, qlst->IfDp->index), i++);
        // Delete the route if IS_IN no sources, or update upstream status.
        if (!qlst->croute->mode && !qlst->croute->nsrcs)
            delRoute(qlst->croute, qlst->IfDp, NULL, 1);
        else {
            sendJoinLeaveUpstream(qlst->croute, 1);
            internUpdateKernelRoute(qlst->croute, 1);
        }
        // Unlink from query list and free qlst.
        if (qlst->next)
            qlst->next->prev = qlst->prev;
        if (qlst->prev)
            qlst->prev->next = qlst->next;
        if (qL == qlst)
            qL = qlst->next;
        qC--;
        free(qlst);  // Alloced by updateRoute(), addSrcToQlst() or processGroupQueryt()
    }

    free(query1);  // Alloced by self.
    free(query2);  // Alloced by self.
}

/**
*   Removes all active queriers on an interface.
*/
void delQry(struct IfDesc *IfDp) {
    struct qlst *ql = qL;
    while (ql) {
        struct qlst *nql = ql->next;
        // Find all queriers for interface.
        if (ql->IfDp == IfDp) {
            // In case of GSSQ clear last member and query bits.
            if (ql->nsrcs) for (uint16_t i = 0; i < ql->nsrcs; BIT_CLR(ql->src[i]->lmBits, IfDp->index),
                                                               BIT_CLR(ql->src[i]->qryBits, IfDp->index), i++);
            // Unlink from query list and free qlst.
            timer_clearTimer(ql->tid);
            if (ql->next)
                ql->next->prev = ql->prev;
            if (ql->prev)
                ql->prev->next = ql->next;
            if (qL == ql)
                qL = ql->next;
            qC--;
            free(ql);  // Alloced by updateRoute(), addSrcToQlst() or processGroupQuery()
        }
        ql = nql;
    }
}

/**
*   Activates a passive group. If the group is already activated, it's reinstalled in the kernel.
*   If the route is activated, no originAddr is needed.
*/
inline void activateRoute(struct IfDesc *IfDp, register uint32_t src, register uint32_t group) {
    struct routeTable *croute = findRoute(group, false);
    struct uSources   *nusrc;
    struct sources    *dsrc;
    if (! croute || croute->nsrcs >= CONFIG->maxOrigins) {
        if (croute && croute->nsrcs >= CONFIG->maxOrigins) {
            LOG(LOG_WARNING, 0, "Max origins exceeded for %s.", inetFmt(croute->group, 1));
            if ((croute->nsrcs & 0x80000000) == 0)
                croute->nsrcs |= 0x80000000;
        }
        return;
    }
    LOG(LOG_INFO, 0, "Route activation for group: %s from src: %s on VIF[%d - %s]",
                      inetFmt(group, 1), inetFmt(src, 2), IfDp->index, IfDp->Name);

    // find or create source in route.
    for (dsrc = croute->sources; dsrc && !(dsrc->ip >= src); dsrc = dsrc->next);
    if ((! dsrc || dsrc->ip > src) && ! (dsrc = addSrc(croute, src, dsrc))) {
        LOG(LOG_WARNING, 0, "Unable to activate route %s to %s on %s. Cannot create source.",
                            inetFmt(src, 1), inetFmt(group, 2), IfDp->Name);
        return;
    }
    // Create and initialize a new upstream source.
    if (! dsrc->usrc) {
        if (! (dsrc->usrc = nusrc = malloc(sizeof(struct uSources))))
            LOG(LOG_ERR, errno, "activateRoute: Out of Memory!");  // Freed by internUpdateKernelRoute().
        *nusrc = (struct uSources){ NULL, NULL, dsrc, IfDp->index, 0, 0 };
        if (croute->usources) {
            nusrc->next = croute->usources;
            croute->usources->prev = nusrc;
        }
        croute->usources = nusrc;
    }

    // Update kernel route table.
    internUpdateKernelRoute(croute, 1);

    logRouteTable("Activate Route", 1, NULL, 0);
}

/**
*   Ages active routes in tables.
*/
void ageRoutes(struct IfDesc *IfDp) {
    struct ifRoutes *ifr;
    LOG(LOG_INFO, 0, "ageRoutes: Aging active routes on %s.", IfDp->Name);

    for (ifr = IfDp->dRoutes; ifr; ifr = ifr ? ifr->next : IfDp->dRoutes) {
        struct routeTable *croute = ifr->croute;
        if (BIT_TST(croute->lmBits, IfDp->index))
            continue;

        // Age v1 and v2 compatibility mode.
        if (croute->v1Age[IfDp->index] == 0)
            BIT_CLR(croute->v1Bits, IfDp->index);
        else if (croute->v1Age[IfDp->index] > 0)
            croute->v1Age[IfDp->index]--;
        if (croute->v2Age[IfDp->index] == 0)
            BIT_CLR(croute->v2Bits, IfDp->index);
        else if (croute->v2Age[IfDp->index] > 0)
            croute->v2Age[IfDp->index]--;

        // Age sources in group.
        bool             keep = false;
        struct sources *dsrc = croute->sources;
        while (dsrc) {
            if (NOT_SET(dsrc, IfDp) || (IS_EX(croute, IfDp) && dsrc->age[IfDp->index] == 0)) {
                dsrc = dsrc->next;
            } else if (!BIT_TST(dsrc->lmBits, IfDp->index) && IS_IN(croute, IfDp) && dsrc->age[IfDp->index] == 0) {
                LOG(LOG_INFO, 0, "ageRoutes: Removed source %s from %s on %s after aging.",
                                  inetFmt(dsrc->ip, 1), inetFmt(croute->group, 2), IfDp->Name);
                dsrc = delSrc(dsrc, IfDp, (uint32_t)-1);
            } else if (BIT_TST(dsrc->lmBits, IfDp->index) || dsrc->age[IfDp->index]-- > 0) {
                dsrc = dsrc->next;
                keep = true;
            }
        }

        // Next age group.
        if (IS_EX(croute, IfDp) && croute->age[IfDp->index] == 0 && !BIT_TST(croute->v1Bits, IfDp->index))
            toInclude(croute, IfDp);
        if (IS_IN(croute, IfDp) && (!keep || !croute->nsrcs)) {
            LOG(LOG_INFO, 0, "ageRoutes: Removed group %s from %s after aging.", inetFmt(croute->group, 2), IfDp->Name);
            ifr = delRoute(croute, IfDp, ifr, 1);
            continue;
        } else if (IS_IN(croute, IfDp)) {
            sendJoinLeaveUpstream(croute, 1);
        } else if (croute->age[IfDp->index] > 0)
            croute->age[IfDp->index]--;

        internUpdateKernelRoute(croute, 1);
    }

    logRouteTable("Age routes", 1, NULL, 0);
}

/**
*   Updates the Kernel routing table. If activate is 1, the route is (re-)activated. If activate is 0, the route is removed.
*/
static void internUpdateKernelRoute(struct routeTable *croute, int activate) {
    struct  IfDesc   *IfDp = NULL;
    struct  uSources *usrc = croute->usources;
    uint8_t           ttlVc[MAXVIFS] = {0};
    uint16_t          i = 1;

    while (usrc) {
        struct  uSources *fusrc = NULL;
        LOG(LOG_DEBUG, 0, "Vif bits %d: 0x%08x", i, croute->vifBits);

        if (activate) {
            // Set the TTL's for the route descriptor...
            for (GETIFL(IfDp)) {
                if (IS_DOWNSTREAM(IfDp->state) && IS_SET(croute, IfDp)) {
                    LOG(LOG_DEBUG, 0, "Setting TTL for Vif %d to %d", IfDp->index, IfDp->conf->threshold);
                    ttlVc[IfDp->index] = IfDp->conf->threshold;
                }
            }
        } else {
            // The origin should be freed if route is removed.
            fusrc = usrc;
        }

        // Do the actual Kernel route update. Update return state, accordingly. add/delmroute returns 1 if failed.
        if (activate)
            k_addMRoute(usrc->src->ip, croute->group, usrc->vif, ttlVc);
        else
            k_delMRoute(usrc->src->ip, croute->group, usrc->vif);
        usrc = usrc->next;
        // Remove route from active routes list.
        if (fusrc) {
            if (fusrc->next)
                fusrc->next->prev = fusrc->prev;
            if (fusrc->prev)
                fusrc->prev->next = fusrc->next;
            if (croute->usources == fusrc)
                croute->usources = fusrc->next;
            free(fusrc);   // Alloced by activateRoute()
        }
        i++;
    }
}

/**
*   Debug function that writes the routing table entries to the log or sends them to the cli socket specified in arguments.
*/
void logRouteTable(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd) {
    struct routeTable *croute;
    struct uSources   *usrc;
    struct IfDesc      *IfDp = NULL;
    char                msg[CLI_CMD_BUF] = "", buf[CLI_CMD_BUF] = "";
    unsigned int        rcount = 1;
    uint64_t            totalb = 0, totalr = 0;

    if (! cliSockAddr) {
        LOG(LOG_DEBUG, 0, "Current routing table (%s):", header);
        LOG(LOG_DEBUG, 0, "_____|______SRC______|______DST______|_______In_______|_____Out____|____dHost____|_______Data_______|______Rate_____");
    } else if (h) {
        sprintf(buf, "Current Routing Table:\n_____|______SRC______|______DST______|_______In_______|_____Out____|____dHost____|_______Data_______|______Rate_____\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
    GETMRT(croute) {
        usrc = croute->usources;
        do {
            if (usrc) {
                IfDp = getIfByIx(usrc->vif);
                totalb += usrc->bytes;
                totalr += usrc->rate;
            }
            if (h) {
                strcpy(msg, "%4d |%15s|%15s|%16s| 0x%08x | %11s | %14lld B | %10lld B/s");
            } else {
                strcpy(msg, "%d %s %s %s %08x %s %ld %ld");
            }
            if (! cliSockAddr) {
                LOG(LOG_DEBUG, 0, msg, rcount, usrc ? inetFmt(usrc->src->ip, 1) : "-", inetFmt(croute->group, 2), usrc ? IfDp->Name : "", croute->vifBits, ! CONFIG->fastUpstreamLeave || !croute->mode ? "not tracked" : noHash(croute->downstreamHostsHashTable) ? "no" : "yes", usrc ? usrc->bytes : 0, usrc ? usrc->rate : 0);
            } else {
                sprintf(buf, strcat(msg, "\n"), rcount, usrc ? inetFmt(usrc->src->ip, 1) : "-", inetFmt(croute->group, 2), usrc ? IfDp->Name : "", croute->vifBits, ! CONFIG->fastUpstreamLeave || !croute->mode ? "not tracked" : noHash(croute->downstreamHostsHashTable) ? "no" : "yes", usrc ? usrc->bytes : 0, usrc ? usrc->rate : 0);
                sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
            }
            usrc = usrc ? usrc->next : NULL;
            rcount++;
        } while (usrc);
    }

    if (! cliSockAddr) {
        LOG(LOG_DEBUG, 0, "Total|---------------|---------------|----------------|------------|-------------| %14lld B | %10lld B/s", totalb, totalr);
    } else if (h) {
        strcpy(msg, "Total|---------------|---------------|----------------|------------|-------------| %14lld B | %10lld B/s\n");
        sprintf(buf, msg, totalb, totalr);
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
