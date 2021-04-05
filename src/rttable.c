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
/**
*   rttable.c
*
*   Updates the routingtable according to
*     received request.
*/

#include "igmpproxy.h"
#include "igmpv3.h"

/**
*   Routing table structure definitions.
*/
struct originAddrs {
    struct originAddrs *next;
    uint32_t            src;                      // Stream source IP
    uint8_t             vif;                      // Incoming vif index
    uint64_t            bytes, rate;              // Bwcontrol counters
};

struct dSources {
    struct dSources    *next;
    uint32_t            ip;                         // Source IP adress
    uint32_t            lmBits;                     // Per vif last member state
    uint32_t            vifBits;                    // Active vifs for source
    uint32_t            queryBits;                  // Active query interfaces
    uint8_t             age[MAXVIFS];               // Age value for source
    uint8_t             downstreamHostsHashTable[]; // Host tracking table
};

struct uSources {
    struct uSources    *next;
    uint32_t            ip;                       // Source IP adress
};

struct routeTable {
    // Keeps group and source information.
    struct routeTable  *prev;                     // Pointer to the next group in line.
    struct routeTable  *next;                     // Pointer to the next group in line.
    uint32_t            group;                    // The group to route
    struct uSources    *uSources;                 // Upstream source list for group
    struct dSources    *dSources;                 // Downstream source list for group
    struct originAddrs *origins;                  // The origin adresses (only set on activated routes)

    // Keeps the group states. Per vif flags.
    uint32_t            mode;                     // Mode (include/exclude) for group
    uint32_t            upstrState;               // Upstream membership state
    uint32_t            lmBits;                   // Last member flag
    uint32_t            queryBits;                // Active query interfaces
    uint32_t            v1Bits;                   // v1 compatibility flags
    uint8_t             v1Age[MAXVIFS];           // v1 compatibility timer
    uint32_t            v2Bits;                   // v2 compatibility flags
    uint8_t             v2Age[MAXVIFS];           // v2 compitibility timer
    uint8_t             age[MAXVIFS];             // Downcounter for death.
    uint32_t            vifBits;                  // Bits representing recieving VIFs

    // Keeps downstream hosts information
    uint8_t             downstreamHostsHashTable[];
};

// Keeper for the routing table.
static struct routeTable  *routing_table = NULL;
static char                msg[TMNAMESZ];

// Prototypes
static inline struct routeTable *findRoute(register uint32_t group, bool create);
static uint64_t      checkFilters(struct IfDesc *IfDp, register int old, register int dir, register uint32_t src, register uint32_t group);
static void          sendJoinLeaveUpstream(struct routeTable* croute, struct IfDesc * IfDp, int join);
static void          sendGroupSpecificQuery(struct igmpv3_grec *grec);
static bool          internUpdateKernelRoute(struct routeTable *route, int activate);
static void          removeRoute(struct routeTable *croute);

static inline void setDownstreamHost(uint8_t *table, uint32_t src) {
    if (CONFIG->fastUpstreamLeave) {
        uint32_t hash = murmurhash3(src ^ CONFIG->downstreamHostsHashSeed) % (CONFIG->downstreamHostsHashTableSize*8);
        BIT_SET(table[hash/8], hash%8);
    }
}

static inline void clearDownstreamHost(uint8_t *table, uint32_t src) {
    if (CONFIG->fastUpstreamLeave) {
        uint32_t hash = murmurhash3(src ^ CONFIG->downstreamHostsHashSeed) % (CONFIG->downstreamHostsHashTableSize*8);
        BIT_CLR(table[hash/8], hash%8);
    }
}

static inline bool testNoDownstreamHost(uint8_t *table) {
    if (CONFIG->fastUpstreamLeave) {
        size_t i;
        for (i = 0; i < CONFIG->downstreamHostsHashTableSize && !table[i]; i++)
        return i < CONFIG->downstreamHostsHashTableSize ? false : true;
    }
    return false;
}

/**
*   Private access function to find a route from a given group, creates new if required.
*/
static inline struct routeTable *findRoute(register uint32_t group, bool create) {
    struct routeTable*  croute;
    for (croute = routing_table; croute && croute->group != group; croute = croute->next);
    if (create && ! croute) {
        // Create and initialize the new route table entry. Freed by clearRoutes() or removeRoute()
        LOG(LOG_INFO, 0, "No existing route for %s. Create new.", inetFmt(group, 1));
        if (! (croute = (struct routeTable *)malloc(sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize)))
            LOG(LOG_ERR, errno, "insertRoute: Out of memory.");
        memset(croute, 0, sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize);
        croute->group = group;
        if (routing_table)
            routing_table->prev = croute;
        croute->next  = routing_table;
        routing_table = croute;
    }
    return croute;
}

/**
*   Calculates bandwidth fo group/subnet filter.
*/
uint64_t getGroupBw(struct subnet group, struct IfDesc *IfDp) {
    struct routeTable  *croute;
    struct originAddrs *oAddr;
    register uint64_t   bw = 0;

    for (croute = routing_table; croute; croute = croute->next) {
        if (IS_UPSTREAM(IfDp->state) && (croute->group & group.mask) == group.ip) {
            for (oAddr = croute->origins; oAddr; oAddr = oAddr->next)
                bw = oAddr->vif == (IfDp->index) ? bw + oAddr->rate : bw;
        } else if (IS_DOWNSTREAM(IfDp->state) && (croute->group & group.mask) == group.ip && BIT_TST(croute->vifBits, IfDp->index)) {
            for (oAddr = croute->origins; oAddr; oAddr = oAddr->next)
                bw += oAddr->rate;
        }
    }

    return bw;
}

#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
/**
*   Bandwith control processing for BSD systems.
*/
void processBwUpcall(struct bw_upcall *bwUpc, int nr) {
    struct IfDesc      *IfDp;
    struct originAddrs *oAddr;

    // Process all pending BW_UPCALLS.
    for (int i = 0; i < nr; i++, bwUpc++) {
        struct routeTable  *croute = findRoute(bwUpc->bu_dst.s_addr, false);
        if (! croute)
            LOG(LOG_ERR, 0, "BW_UPCALL: Src %s, Dst %s, but no route found.", inetFmt(bwUpc->bu_dst.s_addr, 1), inetFmt(bwUpc->bu_dst.s_addr, 2));

        // Find the source for the upcall and add to counter.
        for (oAddr = croute->origins; oAddr && oAddr->src != bwUpc->bu_src.s_addr; oAddr = oAddr->next);
        if (oAddr) {
            oAddr->bytes += bwUpc->bu_measured.b_bytes;
            oAddr->rate = bwUpc->bu_measured.b_bytes / CONFIG->bwControlInterval;
            LOG(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to Src %s Dst %s, total %lldB (%lld B/s)", bwUpc->bu_measured.b_bytes, inetFmt(oAddr->src, 1), inetFmt(croute->group, 2), oAddr->bytes, oAddr->rate);
            for (GETIFL(IfDp)) {
                // Find the incoming and outgoing interfaces and add to counter.
                if (IfDp->index == oAddr->vif || BIT_TST(croute->vifBits, IfDp->index)) {
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
    struct IfDesc      *IfDp = NULL;
    struct routeTable  *croute;
    struct originAddrs *oAddr;

    // Reset all interface rate counters.
    for (GETIFL(IfDp)) IfDp->rate = 0;

    // Go over all routes.
    for (croute = routing_table; croute; croute = croute->next) {
        // Go over all sources.
        for (oAddr = croute->origins; oAddr; oAddr = oAddr->next) {
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
            // On Linux get the S,G statistics via ioct. On BSD they are processed by processBwUpcall().
            struct sioc_sg_req siocReq = { {oAddr->src}, {croute->group}, 0, 0, 0 };
            if (ioctl(MROUTERFD, SIOCGETSGCNT, (void *)&siocReq, sizeof(siocReq))) {
                LOG(LOG_WARNING, errno, "BW_CONTROL: ioctl failed.");
                continue;
            }
            uint64_t bytes = siocReq.bytecnt - oAddr->bytes;
            oAddr->bytes += bytes;
            oAddr->rate = bytes / CONFIG->bwControlInterval;
            LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to Src %s Dst %s (%lld B/s), total %lld.", bytes, inetFmt(oAddr->src, 1), inetFmt(croute->group, 2), oAddr->rate, oAddr->bytes);
#else
            // On BSD systems go over all interfaces.
            for (GETIFL(IfDp)) {
                if (IfDp->index == oAddr->vif || BIT_TST(croute->vifBits, IfDp->index)) {
                    IfDp->rate += oAddr->rate;
                    LOG(LOG_DEBUG, 0, "BW_CONTROL: Added %lld B/s to interface %s (%lld B/s), total %lld.", oAddr->rate, IfDp->Name, IfDp->rate, IfDp->bytes);
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
static void sendJoinLeaveUpstream(struct routeTable* croute, struct IfDesc *IfDp, int join) {
    struct IfDesc   *checkVIF = NULL;

    // Only join a group if there are listeners downstream. Only leave a group if joined.
    if (join && croute->vifBits == 0) {
        LOG(LOG_DEBUG, 0, "No downstream listeners for group %s. No join sent.", inetFmt(croute->group, 1));
        return;
    }

    for (GETIFL(checkVIF)) {
        uint64_t bw = BLOCK;
        // Check if this Request is legit to be forwarded to upstream
        if (!IS_UPSTREAM(checkVIF->state) || (join && BIT_TST(croute->upstrState, checkVIF->index)) || (! join && ! BIT_TST(croute->upstrState, checkVIF->index))) {
            continue;
        } else if (! join) {
            LOG(LOG_INFO, 0, "Leaving group %s upstream on IF address %s", inetFmt(croute->group, 1), inetFmt(checkVIF->InAdr.s_addr, 2));
            if (k_leaveMcGroup(checkVIF, croute->group)) {
                BIT_CLR(croute->upstrState, checkVIF->index);
            }
        } else if (checkVIF == IfDp) {
            LOG(LOG_DEBUG, 0, "Not joining group %s on interface that received request (%s)", inetFmt(croute->group, 1), IfDp->Name);
        } else if (! (bw = checkFilters(checkVIF, 0, IF_STATE_UPSTREAM, 0, croute->group))) {
            LOG(LOG_INFO, 0, "The group address %s may not be forwarded to upstream if %s.", inetFmt(croute->group, 1), checkVIF->Name);
        } else if (CONFIG->bwControlInterval && checkVIF->conf->ratelimit > 0 && checkVIF->rate > checkVIF->conf->ratelimit) {
            LOG(LOG_WARNING, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.", checkVIF->Name, checkVIF->rate, checkVIF->conf->ratelimit, inetFmt(croute->group, 1));
        } else if (bw > ALLOW) {
            LOG(LOG_WARNING, 0, "Group %s bandwidth over limit (%lld) on %s. Not joining.", inetFmt(croute->group, 1), bw, checkVIF->Name);
        } else {
            LOG(LOG_INFO, 0, "Joining group %s upstream on IF address %s", inetFmt(croute->group, 1), inetFmt(checkVIF->InAdr.s_addr, 2));
            if (k_joinMcGroup(checkVIF, croute->group)) BIT_SET(croute->upstrState, checkVIF->index);
        }
    }
}

/**
*   Clears / Updates all routes and routing table, and sends Joins / Leaves upstream. If called with NULL pointer all routes are removed.
*/
void clearRoutes(void *Dp) {
    struct routeTable *croute, *nextroute;
    struct IfDesc     *IfDp = Dp != CONFIG && Dp != getConfig ? Dp : NULL;
    register uint8_t   oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);

    // Loop through all routes...
    for (croute = routing_table; croute; croute = nextroute) {
        struct originAddrs *oAddr, *pAddr;
        register bool       keep = false;
        nextroute = croute->next;

        if (!NOSIG && Dp == CONFIG) {
            struct dSources **src;
            // Quickleave was enabled or disabled, or hastable size was changed. Reallocate appriopriate amount of memory and reinitialize downstreahosts tracking.
            for (src = &(croute->dSources); *src; src = &(*src)->next) {
                if (! (*src = (struct dSources *)realloc(*src, sizeof(struct dSources) + CONFIG->downstreamHostsHashTableSize)))
                    LOG(LOG_ERR, errno, "clearRoutes: Out of memory.");
                if (CONFIG->fastUpstreamLeave)
                    memset((*src)->downstreamHostsHashTable, 0, CONFIG->downstreamHostsHashTableSize);
            if (! (croute = (struct routeTable *)realloc(croute, sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize)))
                LOG(LOG_ERR, errno, "clearRoutes: Out of memory.");
            if (CONFIG->fastUpstreamLeave)
                memset(croute->downstreamHostsHashTable, 0, CONFIG->downstreamHostsHashTableSize);
            if (! croute->prev)
                routing_table = croute;
            else
                croute->prev->next = croute;
            if (croute->next)
                croute->next->prev = croute;
            }
            continue;

#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        } else if (!NOSIG && Dp == getConfig) {
            // BW control interval was changed. Reinitialize all bw_upcalls.
            for (oAddr = croute->origins; oAddr; oAddr = oAddr->next) {
                k_deleteUpcalls(oAddr->src, croute->group);
                internUpdateKernelRoute(croute, 1);
            }
            continue;
#endif
        } else if (!NOSIG && !IS_UPSTREAM(oldstate) && IS_UPSTREAM(newstate)) {
            // New upstream interface added, join all relevant groups.
            if (checkFilters(IfDp, 0, IF_STATE_UPSTREAM, 0, croute->group) == ALLOW && k_joinMcGroup(IfDp, croute->group)) {
                BIT_SET(croute->upstrState, IfDp->index);
                LOG(LOG_INFO, 0, "clearRoutes: Joined %s on new upstream interface %s.", inetFmt(croute->group, 1), IfDp->Name);
            }
            continue;

        } else if (!NOSIG && IS_UPSTREAM(oldstate)) {
            if ((CONFRELOAD || SSIGHUP) && IS_UPSTREAM(newstate)) {
                // Upstream to upstream during config reload, check route sources against wl / bl changes.
                for (oAddr = croute->origins, pAddr = NULL; oAddr; ) {
                    if (checkFilters(IfDp, 0, IF_STATE_UPSTREAM, oAddr->src, croute->group) != ALLOW && checkFilters(IfDp, 1, IF_STATE_UPSTREAM, oAddr->src, croute->group) == ALLOW) {
                        LOG(LOG_WARNING, 0, "clearRoutes: Removing source %s on %s from route %s, no longer allowed.",inetFmt (oAddr->src, 1), IfDp->Name, inetFmt(croute->group, 2));
                        k_delMRoute(oAddr->src, croute->group, oAddr->vif);
                        if (pAddr)
                            pAddr->next = oAddr->next;
                        else
                            croute->origins = oAddr->next;
                        free(oAddr);  // Alloced by activateRoute()
                        oAddr = pAddr ? pAddr->next : croute->origins;
                    } else {
                        pAddr = oAddr;
                        oAddr = oAddr->next;
                    }
                }
                keep = croute->origins ? true : false;

                // Continue check bl / wl if route still valid on interfacei and join or leave group accordingly.
                if (keep) {
                    if (checkFilters(IfDp, 0, IF_STATE_UPSTREAM, 0, croute->group) != ALLOW && checkFilters(IfDp, 1, IF_STATE_UPSTREAM, 0, croute->group) == ALLOW) {
                        // Group is no longer allowed. Leave if not active on interface set to last member. If active on interface, remove.
                        LOG(LOG_WARNING, 0, "clearRoutes: Leaving group %s on %s, no longer allowed.", inetFmt(croute->group, 1), IfDp->Name);
                        if (k_leaveMcGroup(IfDp, croute->group))
                            BIT_CLR(croute->upstrState, IfDp->index);
                    } else if (checkFilters(IfDp, 0, IF_STATE_UPSTREAM, 0, croute->group) == ALLOW && checkFilters(IfDp, 1, IF_STATE_UPSTREAM, 0, croute->group) != ALLOW) {
                        // Group is now allowed on upstream interface, join.
                        if (k_joinMcGroup(IfDp, croute->group) == ALLOW) {
                            LOG(LOG_INFO, 0, "clearRoutes: Joining group %s on %s, it is now allowed.", inetFmt(croute->group, 1), IfDp->Name);
                            BIT_SET(croute->upstrState, IfDp->index);
                        }
                    }
                }

            // Transition from upstream to downstream or disabled. Leave group, set to last member and query.
            } else if (!IS_UPSTREAM(newstate) && BIT_TST(croute->upstrState, IfDp->index)) {
                LOG(LOG_WARNING, 0, "clearRoutes: Leaving group %s on %s, no longer upstream.", inetFmt(croute->group, 1), IfDp->Name);
                if (k_leaveMcGroup(IfDp, croute->group))
                    BIT_CLR(croute->upstrState, IfDp->index);
                for (oAddr = croute->origins, pAddr = NULL; oAddr; ) {
                    if (BIT_TST(oAddr->vif, IfDp->index)) {
                        k_delMRoute(oAddr->src, croute->group, oAddr->vif);
                        if (pAddr)
                            pAddr->next = oAddr->next;
                        else
                            croute->origins = oAddr->next;
                        free(oAddr);   // Alloced by activateRoute()
                        oAddr = pAddr ? pAddr->next : croute->origins;
                    } else {
                        pAddr = oAddr;
                        oAddr = oAddr->next;
                    }
                }
                keep = croute->origins ? true : false;
            } else
                keep = true;                           // Upstream to upstream during interface rebuild, or group not valid for interface.
        } else if (IS_DOWNSTREAM(oldstate))
            keep = true;  // If interface was downstream only, continue checking.

        // Downstream interface transition. No need to check if route is already to be removed because of upstream interface transition.
        if (!NOSIG && keep && IS_DOWNSTREAM(oldstate) && BIT_TST(croute->vifBits, IfDp->index)) {
            if ((CONFRELOAD || SSIGHUP) && IS_DOWNSTREAM(newstate) && checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, 0, croute->group) == ALLOW && checkFilters(IfDp, 1, IF_STATE_DOWNSTREAM, 0, croute->group) != ALLOW) {
                LOG(LOG_DEBUG, 0, "clearRoutes: Group %s now allowed on Vif %d - %s", inetFmt(croute->group, 1), IfDp->index, IfDp->Name);
            } else {
                // Check against bl / wl changes on config reload / sighup.
                if ((CONFRELOAD || SSIGHUP) && checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, 0, croute->group) != ALLOW && checkFilters(IfDp, 1, IF_STATE_DOWNSTREAM, 0, croute->group) == ALLOW) {
                    LOG(LOG_INFO, 0, "clearRoutes: Group %s no longer allowed on Vif %d - %s, removing from route.", inetFmt(croute->group, 1), IfDp->index, IfDp->Name);
                    keep = false;
                // Transition to disabled / upstream, remove from route and query.
                } else if (!IS_DOWNSTREAM(newstate)) {
                    LOG(LOG_INFO, 0, "clearRoutes: Vif %d - %s removed, removing from route %s.", IfDp->index, IfDp->Name, inetFmt(croute->group, 1));
                    keep = false;
                }
                if (!keep) {
                    BIT_CLR(croute->vifBits, IfDp->index);
                    // If there are still listeners keep and update kernel route to remove Vif. If no more listeners remove the route.
                    if (croute->vifBits > 0) {
                        internUpdateKernelRoute(croute, 1);
                        keep = true;
                    }
                }
            }
        }

        if (!keep) {
            // Route will be removed, send a leave message upstream on current interfaces.
            sendJoinLeaveUpstream(croute, NULL, 0);

            // Log the cleanup in debugmode...
            LOG(LOG_DEBUG, 0, "clearRoutes: Removing route entry for %s", inetFmt(croute->group, 1));

            // Remove the route from routing table.
            removeRoute(croute);
        }
    }

    if (! routing_table)
        LOG(LOG_INFO, 0, "clearRoutes: Routing table is empty.");
    else
        logRouteTable("Clear Routes", 1, NULL, 0);
}

/**
*   Adds a specified route to the routingtable or updates the route if it exists.
*   Function will implement group table and proces group reports per RFC.
*   See paragraph 6.4 of RFC3376 for more information.
*/
void updateRoute(struct IfDesc *IfDp, register uint32_t src, void *rec) {
    struct igmpv3_grec *grec   = (struct igmpv3_grec *)rec,
                       *query  = NULL , *query1 = NULL;
    struct routeTable  *croute = findRoute(grec->grec_mca.s_addr, true);
    uint16_t type   = grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT
                 || grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT ? IGMPV3_MODE_IS_EXCLUDE
                  : grec->grec_type == IGMP_V2_LEAVE_GROUP       ? IGMPV3_CHANGE_TO_INCLUDE
                  : grec->grec_type,
           nsrcs  = grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT
                 || grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT
                 || grec->grec_type == IGMP_V2_LEAVE_GROUP       ? 0
                  : ntohs(grec->grec_nsrcs),
          i, a, q = 0;
    struct dSources *dsrc, *psrc;

    // Toggle compatibility modes if older version reports are received.
    if (grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT) {
        LOG(LOG_INFO, 0, "Detected v1 host on %s. Setting compatibility mode for %s.", IfDp->Name, inetFmt(croute->group, 1));
        BIT_SET(croute->v1Bits, IfDp->index);
        croute->v1Age[IfDp->index] = IfDp->querier.qrv;
    } else if (grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT || grec->grec_type == IGMP_V2_LEAVE_GROUP) {
        LOG(LOG_INFO, 0, "Detected v2 host on %s. Setting compatibility mode for %s.", IfDp->Name, inetFmt(croute->group, 2));
        BIT_SET(croute->v2Bits, IfDp->index);
        croute->v2Age[IfDp->index] = IfDp->querier.qrv;
    }

    switch (type) {
    case IGMPV3_CHANGE_TO_EXCLUDE:
        if ((BIT_TST(croute->v1Bits, IfDp->index) || BIT_TST(croute->v2Bits, IfDp->index || IfDp->querier.ver < 3)) && nsrcs > 0) {
            LOG(LOG_INFO, 0, "updateRoute: Ignoring %d sources for %s on %s, v1 or v2 host/querier present.", nsrcs, inetFmt(croute->group, 1), IfDp->Name);
            nsrcs = 0;
        }
        /* FALLTHRU */
    case IGMPV3_MODE_IS_EXCLUDE:
        if (checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, INADDR_ANY, grec->grec_mca.s_addr) < ALLOW) {
            LOG(LOG_NOTICE, 0, "Group %s may not be requested on %s.", inetFmt(croute->group, 1), IfDp->Name);
            return;
        }

        LOG(LOG_DEBUG, 0, "updateRoute: Processing %s with %d sources for %s (%s) on %s.", type == IGMPV3_MODE_IS_EXCLUDE ? "IS_EX" : "TO_EX", nsrcs, inetFmt(croute->group, 1), BIT_TST(croute->mode, IfDp->index) ? "EX" : "IN", IfDp->Name);
        croute->age[IfDp->index] = IfDp->querier.qrv;  // Group timer = GMI
        BIT_SET(croute->vifBits, IfDp->index);
        BIT_CLR(croute->lmBits, IfDp->index);
        setDownstreamHost(croute->downstreamHostsHashTable, src);

        if (nsrcs == 0) {
            // Remove all sources from source list for interface if group report has no sources.
            for (dsrc = croute->dSources; dsrc; BIT_CLR(dsrc->vifBits, IfDp->index), clearDownstreamHost(dsrc->downstreamHostsHashTable, src), dsrc = dsrc->next);
            LOG(LOG_INFO, 0, "updateRoute: Removing all sources for %s on %s (Ex{}).", inetFmt(croute->group, 1), IfDp->Name);
        } else for (dsrc = croute->dSources; dsrc; dsrc = dsrc->next) {
            if (!BIT_TST(dsrc->vifBits, IfDp->index))
                continue;
            clearDownstreamHost(dsrc->downstreamHostsHashTable, src);
            for (i = 0; i < nsrcs && dsrc->ip != grec->grec_src[i].s_addr; i++);
            if (i >= nsrcs)
                // EX: Delete (X-A) & Delete (Y-A), IN: Delete (A-B)
                BIT_CLR(dsrc->vifBits, IfDp->index);
            else if (type == IGMPV3_CHANGE_TO_EXCLUDE && (!BIT_TST(croute->mode, IfDp->index) || dsrc->age[IfDp->index] > 0)) {
                // IN: Send Q(G, A*B), EX: Send Q(G, A-Y)
                BIT_SET(dsrc->lmBits, IfDp->index);
                q++;
            }
        }

        for (i = 0; i < nsrcs; i++) {
            for (dsrc = croute->dSources; dsrc && dsrc->ip != grec->grec_src[i].s_addr; dsrc = dsrc->next);
            if (! dsrc) {
                if (! (dsrc = (struct dSources *)malloc(sizeof(struct dSources) + CONFIG->downstreamHostsHashTableSize)))   // Freed by self removeRoute() or ageRoutes()
                    LOG(LOG_ERR, errno, "updateRoute: Out of memory.");
                memset(dsrc, 0, sizeof(struct dSources) + CONFIG->downstreamHostsHashTableSize);
                *dsrc = (struct dSources){ croute->dSources, grec->grec_src[i].s_addr, 0, 0, 0, {0} };
                croute->dSources = dsrc;
            }
            if (! BIT_TST(dsrc->vifBits, IfDp->index)) {
                BIT_SET(dsrc->vifBits, IfDp->index);
                if (type == IGMPV3_CHANGE_TO_EXCLUDE && BIT_TST(croute->mode, IfDp->index)) {
                    // EX: (A-X-Y) = GMI, Send Q(G, A-Y)
                    BIT_SET(dsrc->lmBits, IfDp->index);
                    dsrc->age[IfDp->index] = IfDp->conf->qry.lmCount;
                    q++;
                } else if (BIT_TST(croute->mode, IfDp->index))
                    dsrc->age[IfDp->index] = IfDp->querier.qrv;
                else {
                    // IN: (B-A) = 0
                    dsrc->age[IfDp->index] = 0;
                }
            }
        }

        BIT_SET(croute->mode, IfDp->index);
        break;

    case IGMPV3_CHANGE_TO_INCLUDE:
        if (BIT_TST(croute->v1Bits, IfDp->index) || IfDp->querier.ver == 1) {
            LOG(LOG_INFO, 0, "updateRoute: Ignoring TO_IN for %s on %s, v1 host/querier present.", inetFmt(croute->group, 1), IfDp->Name);
            return;
        } else if (nsrcs == 0) {
            clearDownstreamHost(croute->downstreamHostsHashTable, src);
            for (dsrc = croute->dSources; dsrc; dsrc = dsrc->next) 
                if (BIT_TST(dsrc->vifBits, IfDp->index))
                    clearDownstreamHost(dsrc->downstreamHostsHashTable, src);
            if (testNoDownstreamHost(croute->downstreamHostsHashTable)) {
                LOG(LOG_INFO, 0, "Quickleave enabled, %s was the last downstream host, leaving group %s now", inetFmt(src, 1), inetFmt(croute->group, 2));
                removeRoute(croute);
                return;
            } else {
                BIT_SET(croute->lmBits, IfDp->index);
                croute->age[IfDp->index] = IfDp->conf->qry.lmCount;
            }
        }
        /* FALLTHRU */
    case IGMPV3_ALLOW_NEW_SOURCES:
    case IGMPV3_MODE_IS_INCLUDE:
        if ((type == IGMPV3_MODE_IS_INCLUDE || type == IGMPV3_ALLOW_NEW_SOURCES) && nsrcs == 0) {
            LOG(LOG_NOTICE, 0, "Received %s without sources for group %s, ignoring.", type == IGMPV3_MODE_IS_INCLUDE ? "IS_IN" : "ALLOW", inetFmt(croute->group, 1));
            return;
        } else if (nsrcs > 0)
            BIT_SET(croute->vifBits, IfDp->index);

        LOG(LOG_DEBUG, 0, "updateRoute: Processing %s with %d sources for %s (%s) on %s.", type == IGMPV3_MODE_IS_INCLUDE ? "IS_IN" : type == IGMPV3_ALLOW_NEW_SOURCES ? "ALLOW" : "TO_IN", nsrcs, inetFmt(croute->group, 1), BIT_TST(croute->mode, IfDp->index) ? "EX" : "IN", IfDp->Name);
        for (i = 0; i < nsrcs; i++) {
            if (checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, grec->grec_src[i].s_addr, grec->grec_mca.s_addr) < ALLOW) {
                LOG(LOG_NOTICE, 0, "Group %s from %s may not be requested on %s.", inetFmt(croute->group, 1), inetFmt(grec->grec_src[i].s_addr, 2), IfDp->Name);
                continue;
            }
            for (dsrc = croute->dSources; dsrc && dsrc->ip != grec->grec_src[i].s_addr; dsrc = dsrc->next);
            if (! dsrc) {
                if (! (dsrc = (struct dSources *)malloc(sizeof(struct dSources) + CONFIG->downstreamHostsHashTableSize)))   // Freed by self removeRoute() or ageRoutes()
                    LOG(LOG_ERR, errno, "updateRoute: Out of memory.");
                memset(dsrc, 0, sizeof(struct dSources) + CONFIG->downstreamHostsHashTableSize);
                *dsrc = (struct dSources){ croute->dSources, grec->grec_src[i].s_addr, 0, 0, 0, {0} };
                croute->dSources = dsrc;
            }
            // IN (B) = GMI, (A + B) / EX: (A) = GMI, (X + A) (Y - A)
            if (!BIT_TST(dsrc->vifBits, IfDp->index) || dsrc->age[IfDp->index] > 0) {
                BIT_SET(dsrc->vifBits, IfDp->index);
                BIT_CLR(dsrc->lmBits, IfDp->index);
                dsrc->age[IfDp->index] = IfDp->querier.qrv;
                setDownstreamHost(dsrc->downstreamHostsHashTable, src);
            } else if (dsrc->age[IfDp->index] == 0) {
                BIT_CLR(dsrc->vifBits, IfDp->index);
                dsrc->age[IfDp->index] = 0;
                clearDownstreamHost(dsrc->downstreamHostsHashTable, src);
            }
        }

        if (type == IGMPV3_CHANGE_TO_INCLUDE) {
            // EX: Send Q(G, X-A) IN: Send Q(G, A-B)
            for (dsrc = croute->dSources; dsrc; dsrc = dsrc->next) {
                if (!BIT_TST(dsrc->vifBits, IfDp->index) || dsrc->age[IfDp->index] == 0)
                    continue;
                for (i = 0; i < nsrcs && dsrc->ip != grec->grec_src[i].s_addr; i++);
                if (i >= nsrcs) {
                    BIT_SET(dsrc->lmBits, IfDp->index);
                    q++;
                }
            }
        }

        break;

    case IGMPV3_BLOCK_OLD_SOURCES:
        if (BIT_TST(croute->v1Bits, IfDp->index) || BIT_TST(croute->v2Bits, IfDp->index) || IfDp->querier.ver < 3) {
            LOG(LOG_INFO, 0, "updateRoute: Ignoring BLOCK for %s on %s, v1 or v2 host/querier present.", inetFmt(croute->group, 1), IfDp->Name);
            return;
        } else if (checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, INADDR_ANY, grec->grec_mca.s_addr) < ALLOW) {
            LOG(LOG_NOTICE, 0, "Group %s may not be requested on %s.", inetFmt(croute->group, 1), IfDp->Name);
            return;
        }

        LOG(LOG_DEBUG, 0, "updateRoute: Processing BLOCK with %d sources for %s (%s) on %s.", nsrcs, inetFmt(croute->group, 1), BIT_TST(croute->mode, IfDp->index) ? "EX" : "IN", IfDp->Name);
        for (i = 0; i < nsrcs; i++) {
            if (BIT_TST(croute->mode, IfDp->index)) {
                for (dsrc = croute->dSources; dsrc && dsrc->ip != grec->grec_src[i].s_addr; dsrc = dsrc->next);
                if (! dsrc) {
                    if (! (dsrc = (struct dSources *)malloc(sizeof(struct dSources) + CONFIG->downstreamHostsHashTableSize)))   // Freed by self removeRoute() or ageRoutes()
                        LOG(LOG_ERR, errno, "updateRoute: Out of memory.");
                    memset(dsrc, 0, sizeof(struct dSources) + CONFIG->downstreamHostsHashTableSize);
                    *dsrc = (struct dSources){ croute->dSources, grec->grec_src[i].s_addr, 0, 0, 0, {0} };
                    croute->dSources = dsrc;
                }
                clearDownstreamHost(dsrc->downstreamHostsHashTable, src);
                // (A-X-Y) = GMI, Send Q(G,A-Y)
                if (!BIT_TST(dsrc->vifBits, IfDp->index)) {
                    BIT_SET(dsrc->lmBits, IfDp->index);
                    dsrc->age[IfDp->index] = IfDp->conf->qry.lmCount;
                } else if (dsrc->age[IfDp->index] > 0)
                    BIT_SET(dsrc->lmBits, IfDp->index);
                q++;
            } else {
                for (dsrc = croute->dSources; dsrc && (!BIT_TST(dsrc->vifBits, IfDp->index) || dsrc->ip != grec->grec_src[i].s_addr); dsrc = dsrc->next);
                if (dsrc) {
                    // Send Q(G,A*B)
                    clearDownstreamHost(dsrc->downstreamHostsHashTable, grec->grec_src[i].s_addr);
                    BIT_SET(dsrc->lmBits, IfDp->index);
                    q++;
                }
            }
        }

        break;
    }

    // Remove excess sources and enforce maxorigins.
    for (i = a = 0, psrc = NULL, dsrc = croute->dSources; dsrc; dsrc = psrc ? psrc->next : croute->dSources) {
        if (i >= CONFIG->maxOrigins) {
            psrc->next = NULL;
            for (psrc = dsrc; dsrc; dsrc = psrc->next, free(psrc), psrc = dsrc);
            break;
        } else if (dsrc->vifBits == 0) {
            if (! psrc)
                croute->dSources = dsrc->next;
            else
                psrc->next = dsrc->next;
            free(dsrc);
        } else {
            psrc = dsrc;
            i++;
            if (BIT_TST(dsrc->vifBits, IfDp->index) && !BIT_TST(dsrc->lmBits, IfDp->index) && !BIT_TST(dsrc->queryBits, IfDp->index)) {
                a++;
                BIT_SET(dsrc->queryBits, IfDp->index);
            }
        }
    }

    // Check if route can be removed or cleared on interface.
    if (croute->mode == 0 && ! croute->dSources) {
        LOG(LOG_DEBUG, 0, "updateRoute: Removed group %s (IN{}).", inetFmt(croute->group, 1));
        sendJoinLeaveUpstream(croute, IfDp, 0);
        removeRoute(croute);
        return;
    } else if (!BIT_TST(croute->mode, IfDp->index)) {
        for (dsrc = croute->dSources; dsrc && !BIT_TST(dsrc->vifBits, IfDp->index); dsrc = dsrc->next);
        if (! dsrc) {
            LOG(LOG_DEBUG, 0, "updateRoute: Removed group %s from %s (IN{}).", inetFmt(croute->group, 1), IfDp->Name);
            BIT_CLR(croute->vifBits, IfDp->index);
        }
    }

    // Send queries if necessary.
    if (q > 0) {
        LOG(LOG_DEBUG, 0, "updateRoute: Querying %d/%d sources for %s on %s.", q, a, inetFmt(croute->group, 1), IfDp->Name);     // Freed by sendGroupSpecificQuery()
        if (  ! (query  = (struct igmpv3_grec *)malloc(sizeof(struct igmpv3_grec) + q * sizeof(struct in_addr) + IF_NAMESIZE))   // Freed by sendGroupSpecificQuery()
           || (a > 0 && ! (query1 = (struct igmpv3_grec *)malloc(sizeof(struct igmpv3_grec) + a * sizeof(struct in_addr) + IF_NAMESIZE))))
            LOG(LOG_ERR, errno, "updateRoute: Out of memory.");
        query->grec_nsrcs = q;
        query->grec_type = query->grec_auxwords = 0;
        query->grec_mca.s_addr = croute->group;
        memcpy(&query->grec_src[q], IfDp->Name, IF_NAMESIZE);
        for (q = 0, dsrc = croute->dSources; dsrc; dsrc = dsrc->next) {
            if (!BIT_TST(dsrc->vifBits, IfDp->index) || !BIT_TST(dsrc->lmBits, IfDp->index))
                continue;
            query->grec_src[q++].s_addr = dsrc->ip;
        }
        if (a > 0) {
            memcpy(&query1->grec_src[i], IfDp->Name, IF_NAMESIZE);
            query1->grec_mca.s_addr = croute->group;
            query1->grec_type = 1;
            query1->grec_auxwords = 0;
            query1->grec_nsrcs = i;
            for (i = 0, dsrc = croute->dSources; dsrc; dsrc = dsrc->next) {
                if (!BIT_TST(dsrc->vifBits, IfDp->index) || BIT_TST(dsrc->lmBits, IfDp->index))
                    continue;
                query1->grec_src[i++].s_addr = dsrc->ip;
            }
            sendGroupSpecificQuery(query1);
        }
        sendGroupSpecificQuery(query);
    }
    // EX TO_IN: Send Q(G)
    if (type == IGMPV3_CHANGE_TO_INCLUDE && BIT_TST(croute->mode, IfDp->index)) {
        LOG(LOG_DEBUG, 0, "updateRoute: Querying group %s on %s.", inetFmt(croute->group, 1), IfDp->Name);
        if (! (query = (struct igmpv3_grec *)malloc(sizeof(struct igmpv3_grec) + IF_NAMESIZE)))   // Freed by sendGroupSpecificQuery()
            LOG(LOG_ERR, errno, "updateRoute: Out of memory.");
        query->grec_mca.s_addr = croute->group;
        query->grec_nsrcs = query->grec_type = query->grec_auxwords = 0;
        memcpy(&query->grec_src[0], IfDp->Name, IF_NAMESIZE);
        sendGroupSpecificQuery(query);
    }

    // Send join message upstream.
    sendJoinLeaveUpstream(croute, IfDp, 1);

    // Update route in kernel...
    if (! internUpdateKernelRoute(croute, 1))
        LOG(LOG_WARNING, 0, "The insertion of route %s into Kernel failed.", inetFmt(croute->group, 1));

    // Log the update in debugmode...
    LOG(LOG_DEBUG, 0, "Updated route entry for %s on VIF #%d", inetFmt(croute->group, 1), IfDp->index);
    logRouteTable("Update Route", 1, NULL, 0);
}

/**
*   Sends a group specific member report query until the group times out.
*/
static void sendGroupSpecificQuery(struct igmpv3_grec *grec) {
    struct IfDesc      *IfDp = getIfByName((char *)&grec->grec_src[grec->grec_nsrcs]);
    struct routeTable  *croute;
    struct dSources    *src;
    uint16_t            i,j;
    if (! IfDp) {
        LOG(LOG_WARNING, 0, "Requested to send GSQ for %s with %d sources, but interface %s not found.", inetFmt(grec->grec_mca.s_addr, 1), grec->grec_nsrcs, &grec->grec_src[grec->grec_nsrcs]);
        free(grec);  // Alloced by updateRoute()
        return;
    }

    // Send GSQ for all active sources and return.
    if (grec->grec_type == 1) {
        if (grec->grec_auxwords++ >= IfDp->conf->qry.lmCount) {
            if ((croute = findRoute(grec->grec_mca.s_addr, false)))
                for (i = 0; i < grec->grec_nsrcs; i++)
                    for (src = croute->dSources; src; src = src->next)
                        if (grec->grec_src[i].s_addr == src->ip)
                            BIT_CLR(src->queryBits, IfDp->index);
            free(grec);   // Alloced by updateRoute()
        } else {
            sendIgmp(IfDp, grec);
            sprintf(msg, "GSQ (%s): %15s/%u", IfDp->Name, inetFmt(grec->grec_mca.s_addr, 1), grec->grec_nsrcs);
            timer_setTimer(TDELAY(IfDp->querier.ver == 3 ? getIgmpExp(IfDp->conf->qry.lmInterval, 0) : IfDp->conf->qry.lmInterval), msg, (timer_f)sendGroupSpecificQuery, grec);
        }
        return;
    }

    // Do aging upon reentry.
    if (grec->grec_auxwords > 0) {
        ageRoutes(IfDp, 0);

        // Check group and sources we still need to query.
        if (grec->grec_nsrcs == 0 && ((croute = findRoute(grec->grec_mca.s_addr, false)) || ! croute || !BIT_TST(croute->lmBits, IfDp->index))) {
            LOG(LOG_DEBUG, 0, "sendGSQ: %s not longer in last member state on %s.", inetFmt(grec->grec_mca.s_addr, 1), IfDp->Name);
            free(grec);   // Alloced by updateRoute()
            return;
        } else if (grec->grec_nsrcs > 0) {
            grec->grec_nsrcs = 0;
            if ((croute = findRoute(grec->grec_mca.s_addr, false))) {
                for (i = 0, j = 1; i < grec->grec_nsrcs; j++) {
                    for (src = croute->dSources; src && (!BIT_TST(src->vifBits, IfDp->index) || !BIT_TST(src->lmBits, IfDp->index)); src = src->next);
                    if (! src) {
                        LOG(LOG_DEBUG, 0, "sendGSQ: %s / %s not longer in last member state on %s.", inetFmt(grec->grec_src[i].s_addr, 1), inetFmt(grec->grec_mca.s_addr, 1), IfDp->Name);
                        grec->grec_src[i] = grec->grec_src[j];
                    } else {
                        grec->grec_nsrcs++;
                        i++;
                    }
                }
            }
            if (grec->grec_nsrcs == 0) {
                LOG(LOG_DEBUG, 0, "sendGSQ: No more sources to query for %s on %s.", inetFmt(grec->grec_mca.s_addr, 1), IfDp->Name);
                free(grec);   // Alloced by updateRoute()
                return;
            }
        }
    }

    // Send query and set timeout for next round...
    if (grec->grec_auxwords++ < IfDp->conf->qry.lmCount) {
        sendIgmp(IfDp, grec);
        sprintf(msg, "GSQ (%s): %15s/%u", IfDp->Name, inetFmt(grec->grec_mca.s_addr, 1), grec->grec_nsrcs);
        timer_setTimer(TDELAY(IfDp->querier.ver == 3 ? getIgmpExp(IfDp->conf->qry.lmInterval, 0) : IfDp->conf->qry.lmInterval), msg, (timer_f)sendGroupSpecificQuery, grec);
    } else {
        LOG(LOG_DEBUG, 0, "sendGSQ: Done querying %d sources for %s on %s.", grec->grec_nsrcs, inetFmt(grec->grec_mca.s_addr, 1), IfDp->Name);
        free(grec);   // Alloced by updateRoute()
    }
}

/**
*   Activates a passive group. If the group is already activated, it's reinstalled in the kernel.
*   If the route is activated, no originAddr is needed.
*/
void activateRoute(struct IfDesc *IfDp, register uint32_t src, register uint32_t group) {
    struct routeTable  *croute;

    // Find the requested route.
    if (src == 0 || src == (uint32_t)-1 || ! checkFilters(IfDp, 0, IF_STATE_UPSTREAM, src, group))
        LOG(LOG_DEBUG, 0, "Route activation request for group: %s from src: %s not valid. Ignoring", inetFmt(group, 1), inetFmt(src, 2));
    else if (! (croute = findRoute(group, true)))
        LOG(LOG_ERR, 0, "No table entry for %s [From: %s].", inetFmt(group, 1),inetFmt(src, 2));
    else {
        struct originAddrs *nAddr;
        LOG(LOG_INFO, 0, "Route activation for group: %s from src: %s on VIF[%d - %s]", inetFmt(group, 1), inetFmt(src, 2), IfDp->index, IfDp->Name);

        // Allocate a new originAddr struct for the source.
        for (nAddr = croute->origins; nAddr && nAddr->src != src; nAddr = nAddr->next);
        if (! nAddr) {
            if (! (nAddr = (struct originAddrs *)malloc(sizeof(struct originAddrs))))
                LOG(LOG_ERR, errno, "activateRoute: Out of Memory!");  // Freed by clearRoutes() or internUpdateKernelRoute().
            *nAddr = (struct originAddrs){ croute->origins, src, IfDp->index, 0, 0 };
            croute->origins = nAddr;
        }

        // Update kernel route table.
        if (! internUpdateKernelRoute(croute, 1))
            LOG(LOG_WARNING, 0, "Route activation for group %s failed for one or more source.", inetFmt(croute->group, 1));

        logRouteTable("Activate Route", 1, NULL, 0);
    }
}

/**
*   Remove a specified route. Returns 1 on success, nd 0 if route was not found.
*/
static void removeRoute(struct routeTable* croute) {
    // Log the cleanup in debugmode...
    LOG(LOG_DEBUG, 0, "Removed route entry for %s from table.", inetFmt(croute->group, 1));

    // Uninstall current route from kernel
    if (! internUpdateKernelRoute(croute, 0))
        LOG(LOG_WARNING, 0, "The removal of route %s from Kernel failed.", inetFmt(croute->group, 1));

    // Send Leave request upstream.
    sendJoinLeaveUpstream(croute, NULL, 0);

    // Update pointers.
    if (croute == routing_table)
        routing_table = croute->next;
    else
        croute->prev->next = croute->next;
    if (croute->next)
        croute->next->prev = croute->prev;

    // Free the memory, and return.
    for (struct dSources *src; croute->dSources; src = croute->dSources->next, free(croute->dSources), croute->dSources = src);   // Alloced by updateRoute()
    for (struct uSources *src; croute->uSources; src = croute->uSources->next, free(croute->uSources), croute->uSources = src);
    free(croute);   // Alloced by findRoute()
    logRouteTable("Remove route", 1, NULL, 0);
}

/**
*   Ages a specific route
*/
void ageRoutes(struct IfDesc *IfDp, uint64_t tid) {
    struct routeTable *croute = routing_table;
    struct dSources   *dsrc, *psrc;
    LOG(LOG_DEBUG, 0, "ageRoutes: Aging %s routes on %s.", tid ? "active" : "last member", IfDp->Name);
    while (croute) {
        if (!BIT_TST(croute->vifBits, IfDp->index)) {
            croute = croute->next;
            continue;
        }
        if (tid != 0 && croute->v1Age[IfDp->index] > 0 && --croute->v1Age[IfDp->index] == 0)
            BIT_CLR(croute->v1Bits, IfDp->index);
        if (tid != 0 && croute->v2Age[IfDp->index] > 0 && --croute->v2Age[IfDp->index] == 0)
            BIT_CLR(croute->v2Bits, IfDp->index);
        for (psrc = NULL, dsrc = croute->dSources; dsrc; dsrc = dsrc ? dsrc->next : croute->dSources) {
            if (!BIT_TST(dsrc->vifBits, IfDp->index) || (tid == 0 && !BIT_TST(dsrc->lmBits, IfDp->index)) || (tid != 0 && BIT_TST(dsrc->lmBits, IfDp->index))
               || (dsrc->age[IfDp->index] > 0 && --dsrc->age[IfDp->index] > 0) || BIT_TST(croute->mode, IfDp->index))
                psrc = dsrc;
            else {
                LOG(LOG_DEBUG, 0, "ageRoutes: Removed source %s from %s on %s after aging.", inetFmt(dsrc->ip, 1), inetFmt(croute->group, 2), IfDp->Name);
                if (! psrc)
                    croute->dSources = dsrc->next;
                else
                    psrc->next = dsrc->next;
                free(dsrc);   // Alloced by updateRoute()
                dsrc = psrc ? psrc : NULL;
            }
        }
        if ( ((tid == 0 && BIT_TST(croute->lmBits, IfDp->index)) || (tid != 0 && !BIT_TST(croute->lmBits, IfDp->index)))
           && (croute->age[IfDp->index] > 0 && --croute->age[IfDp->index] == 0 && !BIT_TST(croute->mode, IfDp->index))) {
            LOG(LOG_DEBUG, 0, "ageRoutes: Switching mode for %s to include on %s.", inetFmt(croute->group, 1), IfDp->Name);
            BIT_CLR(croute->mode, IfDp->index);
            for (psrc = NULL, dsrc = croute->dSources; dsrc; dsrc = dsrc ? dsrc->next : croute->dSources) {
                if (BIT_TST(dsrc->vifBits, IfDp->index) && dsrc->age[IfDp->index] == 0) {
                    if (! psrc)
                        croute->dSources = dsrc->next;
                    else
                        psrc->next = dsrc->next;
                    free(dsrc);   // Alloced by updateRoute()
                    dsrc = psrc ? psrc : NULL;
                }
            }
        }
        if (croute->mode == 0 && ! croute->dSources) {
            LOG(LOG_DEBUG, 0, "ageRoutes: Removed group %s after aging.", inetFmt(croute->group, 2), IfDp->Name);
            croute = croute->prev;
            removeRoute(croute ? croute->next : routing_table);
            croute = ! croute ? routing_table : croute->next;
        } else {
            if (!BIT_TST(croute->mode, IfDp->index)) {
                for (dsrc = croute->dSources; dsrc && !BIT_TST(dsrc->vifBits, IfDp->index); dsrc = dsrc->next);
                if (! dsrc) {
                    LOG(LOG_DEBUG, 0, "ageRoutes: Removed group %s from %s after aging.", inetFmt(croute->group, 2), IfDp->Name);
                    BIT_CLR(croute->vifBits, IfDp->index);
                }
            }
            croute = croute->next;
        }
    }

    logRouteTable("Age routes", 1, NULL, 0);
}

/**
*   Updates the Kernel routing table. If activate is 1, the route is (re-)activated. If activate is false, the route is removed.
*/
static bool internUpdateKernelRoute(struct routeTable *croute, int activate) {
    struct  IfDesc      *IfDp = NULL;
    struct  originAddrs *oAddr = croute->origins;
    uint8_t              ttlVc[MAXVIFS] = {0};
    unsigned int         i = 0;
    bool                 result = true;

    while (oAddr) {
        struct  originAddrs *fAddr = NULL;

        LOG(LOG_DEBUG, 0, "Vif bits %d: 0x%08x", i + 1, croute->vifBits);

        if (activate) {
            // Enforce maxorigins. New entries are inserted in front of list, so find and remove the excess sources.
            if (i >= CONFIG->maxOrigins) {
                for (fAddr = croute->origins; fAddr->next != oAddr; fAddr = fAddr->next);
                fAddr->next = NULL;
                while (oAddr) {
                    LOG(LOG_INFO, 0, "Removing source %s from route %s, too many sources.", inetFmt(oAddr->src, 1), inetFmt(croute->group, 2));
                    fAddr = oAddr;
                    oAddr = oAddr->next;
                    k_delMRoute(fAddr->src, croute->group, fAddr->vif);
                    free(fAddr);   // Alloced by activateRoute()
                }
                break;
            }

            // Set the TTL's for the route descriptor...
            for (GETIFL(IfDp)) {
                if (IS_DOWNSTREAM(IfDp->state) && BIT_TST(croute->vifBits, IfDp->index)) {
                    LOG(LOG_DEBUG, 0, "Setting TTL for Vif %d to %d", IfDp->index, IfDp->conf->threshold);
                    ttlVc[IfDp->index] = IfDp->conf->threshold;
                }
            }
        } else {
            // The origin should be freed if route is removed.
            fAddr = oAddr;
        }

        // Do the actual Kernel route update. Update return state, accordingly. add/delmroute returns 1 if failed.
        result &= (activate && ! k_addMRoute(oAddr->src, croute->group, oAddr->vif, ttlVc)) || (! activate && ! k_delMRoute(oAddr->src, croute->group, oAddr->vif)) ? true : false;
        oAddr = oAddr->next;
        free(fAddr);   // Alloced by activateRoute()
        i++;
    }

    // Return the accumulated result of adding / removing routes.
    return result;
}

/**
*   Debug function that writes the routing table entries to the log or sends them to the cli socket specified in arguments.
*/
void logRouteTable(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd) {
    struct routeTable  *croute = routing_table;
    struct originAddrs *oAddr;
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
    if (! croute) {
        LOG(LOG_DEBUG, 0, "No routes in table...");
    } else do {
        oAddr = croute->origins;
        do {
            if (oAddr) {
                IfDp = getIfByIx(oAddr->vif);
                totalb += oAddr->bytes;
                totalr += oAddr->rate;
            }
            if (h) {
                strcpy(msg, "%4d |%15s|%15s|%16s| 0x%08x | %11s | %14lld B | %10lld B/s");
            } else {
                strcpy(msg, "%d %s %s %s %08x %s %ld %ld");
            }
            if (! cliSockAddr) {
                LOG(LOG_DEBUG, 0, msg, rcount, oAddr ? inetFmt(oAddr->src, 1) : "-", inetFmt(croute->group, 2), oAddr ? IfDp->Name : "",
                    croute->vifBits, ! CONFIG->fastUpstreamLeave ? "not tracked" : testNoDownstreamHost(croute->downstreamHostsHashTable) ? "no" : "yes", oAddr ? oAddr->bytes : 0, oAddr ? oAddr->rate : 0);
            } else {
                sprintf(buf, strcat(msg, "\n"), rcount, oAddr ? inetFmt(oAddr->src, 1) : "-", inetFmt(croute->group, 2), oAddr ? IfDp->Name : "",
                    croute->vifBits, ! CONFIG->fastUpstreamLeave ? "not tracked" : testNoDownstreamHost(croute->downstreamHostsHashTable) ? "no" : "yes", oAddr ? oAddr->bytes : 0, oAddr ? oAddr->rate : 0);
                sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
            }
            oAddr = oAddr ? oAddr->next : NULL;
            rcount++;
        } while (oAddr);

        croute = croute->next;
    } while (croute);

    if (! cliSockAddr) {
        LOG(LOG_DEBUG, 0, "Total|---------------|---------------|----------------|------------|-------------| %14lld B | %10lld B/s", totalb, totalr);
    } else if (h) {
        strcpy(msg, "Total|---------------|---------------|----------------|------------|-------------| %14lld B | %10lld B/s\n");
        sprintf(buf, msg, totalb, totalr);
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
