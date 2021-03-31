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
    uint32_t            src;                      // Stream source IP
    uint8_t             vif;                      // Incoming vif index
    uint64_t            bytes, rate;              // Bwcontrol counters
    struct originAddrs *next;
};

struct dSources {
    struct dsources    *next;
    uint32_t            ip;                         // Source IP adress
    uint32_t            lastMember;                 // Per vif last member state
    uint32_t            ageBits;                    // Active vifs for source
    uint8_t             age[MAXVIFS];               // Age value for source
    uint32_t            downstreamHostsHashSeed;    // Host tracking table
    uint8_t             downstreamHostsHashTable[]; 
};

struct uSources {
    uint32_t            ip;                       // Source IP adress
    struct uSources    *next;
};

struct routeTable {
    // Keeps group and source information.
    struct routeTable  *next;                     // Pointer to the next group in line.
    uint32_t            group;                    // The group to route
    struct uSources    *uSources;                 // Upstream source list for group
    struct dSources    *dSources;                 // Downstream source list for group
    struct originAddrs *origins;                  // The origin adresses (only set on activated routes)

    // Keeps the group states. Per vif flags.
    uint32_t            mode;                     // Mode (include/exclude) for group
    uint32_t            upstrState;               // Upstream membership state
    uint32_t            lastMember;               // Last member flag
    uint32_t            v1Bits;                   // v1 compatibility flags
    uint8_t             v1Age[MAXVIFS]            // v1 compatibility timer
    uint32_t            v2Bits;                   // v2 compatibility flags
    uint8_t             v2Age[MAXVIFS]            // v2 compitibility timer
    uint8_t             ageValue[MAXVIFS];        // Downcounter for death.
    uint32_t            vifBits;                  // Bits representing recieving VIFs
    uint32_t            ageVifBits;               // Bits representing aging VIFs.

    // Keeps downstream hosts information
    uint32_t            downstreamHostsHashSeed;
    uint8_t             downstreamHostsHashTable[];
};

// Keeper for the routing table.
static struct routeTable   *routing_table = NULL;
static char msg[TMNAMESZ];

// Prototypes
static inline struct routeTable *findRoute(register uint32_t group);
static uint64_t      checkFilters(struct IfDesc *IfDp, register int old, register int dir, register uint32_t src, register uint32_t group);
static uint64_t      checkGrpRec(struct IfDesc *IfDp, register uint32_t src, register uint32_t group, register uint8_t ifstate);
static void          sendJoinLeaveUpstream(struct routeTable* croute, struct IfDesc * IfDp, int join);
static bool          internAgeRoute(struct routeTable *croute, struct IfDesc *IfDp);
static bool          internUpdateKernelRoute(struct routeTable *route, int activate);
static void          removeRoute(struct routeTable *croute);

static inline void setDownstreamHost(struct routeTable *croute, uint32_t src) {
    uint32_t hash = murmurhash3(src ^ croute->downstreamHostsHashSeed) % (CONFIG->downstreamHostsHashTableSize*8);
    BIT_SET(croute->downstreamHostsHashTable[hash/8], hash%8);
}

static inline void clearDownstreamHost(struct routeTable *croute, uint32_t src) {
    uint32_t hash = murmurhash3(src ^ croute->downstreamHostsHashSeed) % (CONFIG->downstreamHostsHashTableSize*8);
    BIT_CLR(croute->downstreamHostsHashTable[hash/8], hash%8);
}

static inline void zeroDownstreamHosts(struct routeTable *croute) {
    croute->downstreamHostsHashSeed = ((uint32_t)rand() << 16) | (uint32_t)rand();
    memset(croute->downstreamHostsHashTable, 0, CONFIG->downstreamHostsHashTableSize);
}

static inline bool testNoDownstreamHost(struct routeTable *croute) {
    for (size_t i = 0; i < CONFIG->downstreamHostsHashTableSize; i++)
        if (croute->downstreamHostsHashTable[i]) return false;
    return true;
}

/**
*   Private access function to find a route from a given group, creates new if not exists.
*/
static inline struct routeTable *findRoute(register uint32_t group) {
    struct routeTable*  croute;
    for (croute = routing_table; croute && croute->group != group; croute = croute->next);
    if (! croute) {
        // Create and initialize the new route table entry. Freed by clearRoutes() or removeRoute()
        myLog(LOG_INFO, 0, "No existing route for %s. Create new.", inetFmt(group, 1));
        if (! (croute = (struct routeTable*)malloc(sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize)))
            myLog(LOG_ERR, errno, "insertRoute: Out of memory.");
        memset(croute, 0, sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize);
        croute->group = group;
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
        struct routeTable  *croute = findRoute(bwUpc->bu_dst.s_addr);
        if (! croute)
            myLog(LOG_ERR, 0, "BW_UPCALL: Src %s, Dst %s, but no route found.", inetFmt(bwUpc->bu_dst.s_addr, 1), inetFmt(bwUpc->bu_dst.s_addr, 2));

        // Find the source for the upcall and add to counter.
        for (oAddr = croute->origins; oAddr && oAddr->src != bwUpc->bu_src.s_addr; oAddr = oAddr->next);
        if (oAddr) {
            oAddr->bytes += bwUpc->bu_measured.b_bytes;
            oAddr->rate = bwUpc->bu_measured.b_bytes / CONFIG->bwControlInterval;
            myLog(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to Src %s Dst %s, total %lldB (%lld B/s)", bwUpc->bu_measured.b_bytes, inetFmt(oAddr->src, 1), inetFmt(croute->group, 2), oAddr->bytes, oAddr->rate);
            for (GETIFL(IfDp)) {
                // Find the incoming and outgoing interfaces and add to counter.
                if (IfDp->index == oAddr->vif || BIT_TST(croute->vifBits, IfDp->index)) {
                    IfDp->bytes += bwUpc->bu_measured.b_bytes;
                    myLog(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to interface %s (%lld B/s), total %lld.", bwUpc->bu_measured.b_bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
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
                myLog(LOG_WARNING, errno, "BW_CONTROL: ioctl failed.");
                continue;
            }
            uint64_t bytes = siocReq.bytecnt - oAddr->bytes;
            oAddr->bytes += bytes;
            oAddr->rate = bytes / CONFIG->bwControlInterval;
            myLog(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to Src %s Dst %s (%lld B/s), total %lld.", bytes, inetFmt(oAddr->src, 1), inetFmt(croute->group, 2), oAddr->rate, oAddr->bytes);
#else
            // On BSD systems go over all interfaces.
            for (GETIFL(IfDp)) {
                if (IfDp->index == oAddr->vif || BIT_TST(croute->vifBits, IfDp->index)) {
                    IfDp->rate += oAddr->rate;
                    myLog(LOG_DEBUG, 0, "BW_CONTROL: Added %lld B/s to interface %s (%lld B/s), total %lld.", oAddr->rate, IfDp->Name, IfDp->rate, IfDp->bytes);
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
                myLog(LOG_WARNING, errno, "BW_CONTROL: ioctl failed.");
                continue;
            }
            uint64_t bytes = (IS_UPSTREAM(IfDp->state) ? siocVReq.ibytes : siocVReq.obytes) - IfDp->bytes;
            IfDp->bytes += bytes;
            IfDp->rate = bytes / CONFIG->bwControlInterval;
            myLog(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to interface %s (%lld B/s), total %lld.", bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
        }
    }
#endif

    // Set next timer;
    *tid = timer_setTimer(0, TDELAY(CONFIG->bwControlInterval * 10), "Bandwidth Control", (timer_f)bwControl, tid);
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
                   myLog(LOG_NOTICE, 0, "BW_CONTROL: Group %s (%lld B/s) ratelimited on %s by filter %s (%lld B/s).", inetFmt(group, 1), bw, IfDp->Name, inetFmts(filter->dst.ip, filter->dst.mask, 2), filter->action);
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
*  Checks if group record is valid and returns access control status.
*/
static uint64_t checkGrpRec(struct IfDesc *IfDp, register uint32_t src, register uint32_t group, register uint8_t ifstate) {
    uint64_t       bw = BLOCK;

    // Check if this Request is legit or ratelimited on this interface.
    if (! (bw = checkFilters(IfDp, 0, ifstate, src, group)))
        myLog(LOG_INFO, 0, "checkGrpRec: The group address %s may not be requested from %s on interface %s. Ignoring.", inetFmt(group, 1), inetFmt(src, 2), IfDp->Name);

    // Return BLOCK, or the outcome of checkFilters(), which may be a ratelimited group.
    return bw;
}

/**
*   Internal function to send join or leave requests for a specified route upstream...
*   When rebuilding interfaces use old IfDesc Table for leaving groups.
*/
static void sendJoinLeaveUpstream(struct routeTable* croute, struct IfDesc *IfDp, int join) {
    struct IfDesc   *checkVIF = NULL;

    // Only join a group if there are listeners downstream. Only leave a group if joined.
    if (join && croute->vifBits == 0) {
        myLog(LOG_DEBUG, 0, "No downstream listeners for group %s. No join sent.", inetFmt(croute->group, 1));
        return;
    }

    for (GETIFL(checkVIF)) {
        uint64_t bw = BLOCK;
        // Check if this Request is legit to be forwarded to upstream
        if (!IS_UPSTREAM(checkVIF->state) || (join && BIT_TST(croute->upstrState, checkVIF->index)) || (! join && ! BIT_TST(croute->upstrState, checkVIF->index))) {
            continue;
        } else if (! join) {
            myLog(LOG_INFO, 0, "Leaving group %s upstream on IF address %s", inetFmt(croute->group, 1), inetFmt(checkVIF->InAdr.s_addr, 2));
            if (k_leaveMcGroup(checkVIF, croute->group)) {
                BIT_CLR(croute->upstrState, checkVIF->index);
            }
        } else if (checkVIF == IfDp) {
            myLog(LOG_DEBUG, 0, "Not joining group %s on interface that received request (%s)", inetFmt(croute->group, 1), IfDp->Name);
        } else if (! (bw = checkFilters(checkVIF, 0, IF_STATE_UPSTREAM, 0, croute->group))) {
            myLog(LOG_INFO, 0, "The group address %s may not be forwarded to upstream if %s.", inetFmt(croute->group, 1), checkVIF->Name);
        } else if (CONFIG->bwControlInterval && checkVIF->conf->ratelimit > 0 && checkVIF->rate > checkVIF->conf->ratelimit) {
            myLog(LOG_WARNING, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.", checkVIF->Name, checkVIF->rate, checkVIF->conf->ratelimit, inetFmt(croute->group, 1));
        } else if (bw > ALLOW) {
            myLog(LOG_WARNING, 0, "Group %s bandwidth over limit (%lld) on %s. Not joining.", inetFmt(croute->group, 1), bw, checkVIF->Name);
        } else {
            myLog(LOG_INFO, 0, "Joining group %s upstream on IF address %s", inetFmt(croute->group, 1), inetFmt(checkVIF->InAdr.s_addr, 2));
            if (k_joinMcGroup(checkVIF, croute->group)) BIT_SET(croute->upstrState, checkVIF->index);
        }
    }
}

/**
*   Clears / Updates all routes and routing table, and sends Joins / Leaves upstream. If called with NULL pointer all routes are removed.
*/
void clearRoutes(void *Dp) {
    struct routeTable    *croute, *nextroute, *prevroute;
    struct IfDesc        *IfDp = Dp != CONFIG && Dp != getConfig ? Dp : NULL;
    register uint8_t      oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);
    if (!routing_table) return;

    // Loop through all routes...
    for (prevroute = NULL, croute = routing_table; croute; croute = nextroute) {
        struct originAddrs *oAddr, *pAddr;
        register bool       keep = false;
        nextroute = croute->next;

        if (!NOSIG && Dp == CONFIG) {
            // Quickleave was enabled or disabled, or hastable size was changed. Reallocate appriopriate amount of memory and reinitialize downstreahosts tracking.
            if (! (croute = (struct routeTable *)realloc(croute, sizeof(struct routeTable) + CONFIG->downstreamHostsHashTableSize))) myLog(LOG_ERR, errno, "clearRoutes: Out of memory.");
            if (! prevroute) routing_table = croute;
            else prevroute->next = croute;
            if (CONFIG->fastUpstreamLeave) zeroDownstreamHosts(croute);
            prevroute = croute;
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
                myLog(LOG_INFO, 0, "clearRoutes: Joined %s on new upstream interface %s.", inetFmt(croute->group, 1), IfDp->Name);
            }
            keep = true;

        } else if (!NOSIG && IS_UPSTREAM(oldstate)) {
            if ((CONFRELOAD || SSIGHUP) && IS_UPSTREAM(newstate)) {
                // Upstream to upstream during config reload, check route sources against wl / bl changes.
                for (oAddr = croute->origins, pAddr = NULL; oAddr; ) {
                    if (checkFilters(IfDp, 0, IF_STATE_UPSTREAM, oAddr->src, croute->group) != ALLOW && checkFilters(IfDp, 1, IF_STATE_UPSTREAM, oAddr->src, croute->group) == ALLOW) {
                        myLog(LOG_WARNING, 0, "clearRoutes: Removing source %s on %s from route %s, no longer allowed.",inetFmt (oAddr->src, 1), IfDp->Name, inetFmt(croute->group, 2));
                        k_delMRoute(oAddr->src, croute->group, oAddr->vif);
                        if (pAddr) pAddr->next = oAddr->next;
                        else croute->origins = oAddr->next;
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
                        myLog(LOG_WARNING, 0, "clearRoutes: Leaving group %s on %s, no longer allowed.", inetFmt(croute->group, 1), IfDp->Name);
                        if (k_leaveMcGroup(IfDp, croute->group)) BIT_CLR(croute->upstrState, IfDp->index);
                    } else if (checkFilters(IfDp, 0, IF_STATE_UPSTREAM, 0, croute->group) == ALLOW && checkFilters(IfDp, 1, IF_STATE_UPSTREAM, 0, croute->group) != ALLOW) {
                        // Group is now allowed on upstream interface, join.
                        if (k_joinMcGroup(IfDp, croute->group) == ALLOW) {
                            myLog(LOG_INFO, 0, "clearRoutes: Joining group %s on %s, it is now allowed.", inetFmt(croute->group, 1), IfDp->Name);
                            BIT_SET(croute->upstrState, IfDp->index);
                        }
                    }
                }

            // Transition from upstream to downstream or disabled. Leave group, set to last member and query.
            } else if (!IS_UPSTREAM(newstate) && BIT_TST(croute->upstrState, IfDp->index)) {
                myLog(LOG_WARNING, 0, "clearRoutes: Leaving group %s on %s, no longer upstream.", inetFmt(croute->group, 1), IfDp->Name);
                if (k_leaveMcGroup(IfDp, croute->group)) BIT_CLR(croute->upstrState, IfDp->index);
                for (oAddr = croute->origins, pAddr = NULL; oAddr; ) {
                    if (BIT_TST(oAddr->vif, IfDp->index)) {
                        k_delMRoute(oAddr->src, croute->group, oAddr->vif);
                        if (pAddr) pAddr->next = oAddr->next;
                        else croute->origins = oAddr->next;
                        free(oAddr);   // Alloced by activateRoute()
                        oAddr = pAddr ? pAddr->next : croute->origins;
                    } else {
                        pAddr = oAddr;
                        oAddr = oAddr->next;
                    }
                }
                keep = croute->origins ? true : false;
            } else keep = true;                           // Upstream to upstream during interface rebuild, or group not valid for interface.
        } else if (IS_DOWNSTREAM(oldstate)) keep = true;  // If interface was downstream only, continue checking.

        // Downstream interface transition. No need to check if route is already to be removed because of upstream interface transition.
        if (!NOSIG && keep && IS_DOWNSTREAM(oldstate) && BIT_TST(croute->vifBits, IfDp->index)) {
            if ((CONFRELOAD || SSIGHUP) && IS_DOWNSTREAM(newstate) && checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, 0, croute->group) == ALLOW && checkFilters(IfDp, 1, IF_STATE_DOWNSTREAM, 0, croute->group) != ALLOW) {
                myLog(LOG_DEBUG, 0, "clearRoutes: Group %s now allowed on Vif %d - %s", inetFmt(croute->group, 1), IfDp->index, IfDp->Name);
            } else {
                // Check against bl / wl changes on config reload / sighup.
                if ((CONFRELOAD || SSIGHUP) && checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, 0, croute->group) != ALLOW && checkFilters(IfDp, 1, IF_STATE_DOWNSTREAM, 0, croute->group) == ALLOW) {
                    myLog(LOG_INFO, 0, "clearRoutes: Group %s no longer allowed on Vif %d - %s, removing from route.", inetFmt(croute->group, 1), IfDp->index, IfDp->Name);
                    keep = false;
                // Transition to disabled / upstream, remove from route and query.
                } else if (!IS_DOWNSTREAM(newstate)) {
                    myLog(LOG_INFO, 0, "clearRoutes: Vif %d - %s removed, removing from route %s.", IfDp->index, IfDp->Name, inetFmt(croute->group, 1));
                    keep = false;
                }
                if (!keep) {
                    BIT_CLR(croute->vifBits, IfDp->index);
                    BIT_CLR(croute->ageVifBits, IfDp->index);
                    // If there are still listeners keep and update kernel route to remove Vif. If no more listeners remove the route.
                    if (croute->vifBits > 0 || croute->ageVifBits > 0) {
                        internUpdateKernelRoute(croute, 1);
                        keep = true;
                    }
                }
            }
        }

        // If the current route is not to be removed, continue.
        if (keep) {
            prevroute = croute;
            continue;
        }

        // Route will be removed, send a leave message upstream on current interfaces.
        sendJoinLeaveUpstream(croute, NULL, 0);

        // Remove the route from routing table.
        if (croute == routing_table) routing_table = croute->next;
        else prevroute->next = croute->next;

        // Log the cleanup in debugmode...
        myLog(LOG_DEBUG, 0, "clearRoutes: Removing route entry for %s", inetFmt(croute->group, 1));

        // Uninstall current route
        if (! internUpdateKernelRoute(croute, 0)) myLog(LOG_WARNING, 0, "clearRoutes: The removal from Kernel failed.");

        // Clear memory, and set pointer to next route...
        free(croute);   // Alloced by findRoute()
    }

    if (! routing_table) myLog(LOG_NOTICE, 0, "clearRoutes: Routing table is empty.");
}

/**
*   Returns the active vifbits for a route.
*/
inline uint32_t getRouteVifbits(register uint32_t group) {
    struct routeTable*  croute;
    for (croute = routing_table; croute && croute->group != group; croute = croute->next);
    return croute ? croute->vifBits : 0;
}

/**
*   Adds a specified route to the routingtable. Update the route if it exists.
*   Function will implement group table and proces group reports per RFC.
*   See paragraph 6.4 of RFC3376 for more information.
*/
void updateRoute(struct IfDesc *IfDp, register uint32_t src, void *rec) {
    struct igmpv3_grec *grec   = (struct igmpv3_grec *)rec;
    struct routeTable  *croute = findRoute(grec->grec_mca.s_addr);
    int i, type   = grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT
                 || grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT ? IGMPV3_MODE_IS_EXCLUDE
                  : grec->grec_type == IGMP_V2_LEAVE_GROUP       ? IGMPV3_CHANGE_TO_INCLUDE
                  : grec->grec_type,
           nsrcs  = grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT
                 || grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT
                 || grec->grec_type == IGMP_V2_LEAVE_GROUP       ? 0
                  : grec->grec_nsrcs;
    struct dSources *src, *psrc;

    // Toggle compatibility modes if older version reports are received.
    if (grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT) {
        BIT_SET(croute->v1Bits, IfDp->index);
        croute->v1Age[IfDp->index] = IfDp->querier.qrv;
    } else if (grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT || grec->grec_type == IGMP_V2_LEAVE_GROUP) {
        BIT_SET(croute->v2Bits, IfDp->index);
        croute->v2Age[IfDp->index] = IfDp->querier.qrv;
    }

    switch (type) {
    case IGMPV3_CHANGE_TO_EXCLUDE:
        if ((BIT_TST(croute->v1Bits, IfDp->index) || BIT_TST(croute->v2Bits, IfDp->index)) && nsrcs > 0) {
            myLog(LOG_INFO, 0, "updateRoute: Ignoring %d sources for %s on %s, v1 or v2 host present.", nsrcs, inetFmt(croute->group, 1), IfDp->Name);
            nsrcs = 0;
        } // And Fall Through.
    case IGMPV3_MODE_IS_EXCLUDE:
        if (checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, INADDR_ANY, grec->grec_mca.s_addr) < ALLOW) {
            myLog(LOG_NOTICE, 0, "Group %s may not be requested on %s.", inetFmt(croute->group, 1), IfDp->Name);
            return;
        }

        myLog(LOG_DEBUG, 0, "updateRoute: Processing %s with %d sources for %s (%s) on %s.", type == IGMPV3_MODE_IS_EXCLUDE ? "IS_EX" : "TO_EX", nsrcs, inetFmt(croute->group, 1), BIT_TST(croute->mode, IfDp->index) ? "EX" : "IN", IfDp->Name);
        croute->ageValue[IfDp->index] = IfDp->querier.qrv;  // Group timer = GMI
        BIT_SET(croute->vifBits, IfDp->index);
        BIT_SET(croute->ageVifBits, IfDp->index);
        if (CONFIG->fastUpstreamLeave)
            setDownstreamHost(croute, src);

        if (nsrcs == 0) {
            // Remove all sources from source list for interface if group report has no sources.
            for (src = croute->dSrouces; src; BIT_CLR(src->vifBits, IfDp->index), src = src->next);
            myLog(LOG_INFO, 0, "updateRoute: Removing all sources for %s on %s (Ex{}).", inetFmt(croute->group, 1), IfDp-Name);
        }
        for (src = croute->dSources, src, src = src->next) {
            // EX: Delete (X-A) & Delete (Y-A), IN: Delete (A-B)
            if (!BIT_TST(src.vifBits, IfDp->index))
                continue;
            for (i = 0; i < nsrcs && src.ip != grec->grec_src[i].s_addr; i++);
            if (i >= nsrcs)
                BIT_CLR(src->vifBits, IfDp->index);
        }
        for (i = 0; i < nsrcs; i++) {
            for (src = croute->dSources, src && src.ip != grec->grec_src[i].s_addr; src = src->next);
            if (! src) {
                if (! (src = (struct dSources *)malloc(sizeOf(struct dSources))))   // Freed by self
                    myLog(LOG_ERR, errno, "updateRoute: Out of memory.");
                *src = (struct dSources){ grec->grec_src[i].s_addr, 0, 0, {0}, croute->dSources };
                croute->dSouces = src;
            }
            if (! BIT_TST(src->vifBits, IfDp->index)) {
                BIT_SET(src->vifBits, IfDp->index);
                if (BIT_TST(croute->mode, IfDp->index))
                    // EX: (A-X-Y) = GMI
                    src->ageValue[IfDp->index] = IfDp->querier.qrv;
                else {
                    // IN: (B-A) = 0, Send Q(G,A*B)
                    src->ageValue[IfDp->index] = 0;
                    grec->grec_src[i].s_addr = 0;
                }
            else if (BIT_TST(croute->mode, IfDp->index) && src->ageValue[IfDp->index] == 0)
                // EX: Send Q(G,A-Y)
                grec->grec_src[i].s_addr = 0;
            }
        }

        BIT_SET(croute->mode, IfDp->index);
        if (type == IGMPV3_CHANGE_TO_EXCLUDE)
            sendGroupQuery(IfDp, grec);
        break;

    case IGMPV3_CHANGE_TO_INCLUDE:
        if (BIT_TST(croute->v1Bits, IfDp->index)) {
            my_log(LOG_INFO, 0, "updateRoute: Ignoring TO_IN for %s on %s, v1 host present.", inetFmt(croute->group, 1), IfDp->Name);
            return;
        }  // Else Fall Through
    case IGMPV3_ALLOW_NEW_SOURCES:
    case IGMPV3_MODE_IS_INCLUDE:
        if ((type == IGMPV3_MODE_IS_INCLUDE || type == IGMPV3_ALLOW_NEW_SOURCES) && nsrcs == 0) {
            myLog(LOG_NOTICE, 0, "Received %s without sources for group %s, ignoring.", type == IGMPV3_MODE_IS_INCLUDE ? "IS_IN" : "ALLOW", inetFmt(croute->group, 1));
            return;
        }

        myLog(LOG_DEBUG, 0, "updateRoute: Processing %s with %d sources for %s (%s) on %s.", type == IGMPV3_MODE_IS_INCLUDE ? "IS_IN" : type == IGMPV3_ALLOW_NEW_SOURCES ? "ALLOW" : "TO_IN", nsrcs, inetFmt(croute->group, 1), BIT_TST(croute->mode, IfDp->index) ? "EX" : "IN", IfDp->Name);
        BIT_SET(croute->vifBits, IfDp->index);
        BIT_SET(croute->ageVifBits, IfDp->index);
        if (CONFIG->fastUpstreamLeave)
            setDownstreamHost(croute, src);

        for (i = 0; i < nsrcs; i++) {
            if (checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, grec->grec_src[i].s_addr, grec->grec_mca.s_addr) < ALLOW) {
                myLog(LOG_NOTICE, 0, "Group %s from %s may not be requested on %s.", inetFmt(croute->group, 1), inetFmt(grec->grec_src[i].s_addr, 2), IfDp->Name);
                continue;
            }
            for (src = croute->dSources, src && src.ip != grec->grec_src[i].s_addr; src = src->next);
            if (! src) {
                if (! (src = (struct dSources *)malloc(sizeOf(struct dSources))))  // Freed by self
                    myLog(LOG_ERR, errno, "updateRoute: Out of memory.");
                *src = (struct dSources){ grec->grec_src[i].s_addr, 0, 0, {0}, croute->dSources };
                croute-dSrouces = src;
            }
            // (A) / (B) = GMI, (X + A) (Y - A)
            if (!BIT_TST(src->vifBits, IfDp->index) || src->ageValue[IfDp->index] > 0) {
                BIT_SET(src->vifBits, IfDp->index);
                src->ageValue[IfDp->index] = IfDp->querier.qrv;
            } else if (src->ageValue[IfDp->index] == 0)
                BIT_CLR(src->vifBits, IfDp->index);
        }

        if (type == IGMPV3_CHANGE_TO_INCLUDE) {
            for (src = croute->dSources; src; src = src->next) {
                if (!BIT_TST(src.vifBits, IfDp->index) || src->ageValue[IfDp->index] == 0)
                    continue;
                for (i = 0; i < nsrcs && src.ip != grec->grec_src[i].s_addr; i++);
                if (i >= nsrcs)
                    queryG,S;
            }
            // Send Q(G)
            if (BIT_TST(croute->mode, IfDp->index))
                croutesendGroupQuery(IfDp, croute->group);
        }

        break;

    case IGMPV3_BLOCK_OLD_SOURCES:
        if (BIT_TST(croute->v1Bits, IfDp->index) || BIT_TST(croute->v2Bits, IfDp->index)) {
            myLog(LOG_INFO, 0, "updateRoute: Ignoring BLOCK for %s on %s, v1 or v2 host present.", inetFmt(croute->group, 1), IfDp->Name);
            return;
        } else if (checkFilters(IfDp, 0, IF_STATE_DOWNSTREAM, INADDR_ANY, grec->grec_mca.s_addr) < ALLOW) {
            myLog(LOG_NOTICE, 0, "Group %s may not be requested on %s.", inetFmt(croute->group, 1), IfDp->Name);
            return;
        }

        myLog(LOG_DEBUG, 0, "updateRoute: Processing BLOCK with %d sources for %s (%s) on %s.", nsrcs, BIT_TST(croute->mode, IfDp->index) ? "EX" : "IN", IfDp->Name);
        if (BIT_TST(croute->mode, IfDp->index)) {
            bla;
        } else {
            for (src = croute->dSources; src; src = src->next) {
                if (!BIT_TST(src.vifBits, IfDp->index))
                    continue;
    }

    // Remove excess sources and enforce maxorigins.
    for (i = 0, psrc = NULL, src = croute->dSources; src; src = psrc ? psrc->next : src) {
        if (i >= CONFIG->maxOrigins) {
            psrc->next = NULL;
            for (psrc = src; src; src = psrc->next, free(psrc), psrc = src);
            break;
        if (src->vifBits == 0) {
            if (! psrc)
                croute->dsources = src = src->next;
            else
                psrc->next = src->next;
            free(src);
        } else {
            psrc = src;
            i++;
        }
    }

    // Send join message upstream.
    sendJoinLeaveUpstream(croute, IfDp, 1);

    // Update route in kernel...
    if (! internUpdateKernelRoute(croute, 1))
        myLog(LOG_WARNING, 0, "The insertion of route %s into Kernel failed.", inetFmt(croute->group, 1));

    // Log the update in debugmode...
    myLog(LOG_DEBUG, 0, "Updated route entry for %s on VIF #%d", inetFmt(croute->group, 1), IfDp->index);
    logRouteTable("Insert Route", 1, NULL, 0);
}

/**
*   Activates a passive group. If the group is already activated, it's reinstalled in the kernel.
*   If the route is activated, no originAddr is needed.
*/
void activateRoute(struct IfDesc *IfDp, register uint32_t src, register uint32_t group) {
    struct routeTable  *croute;

    // Find the requested route.
    if (src == 0 || src == (uint32_t)-1 || ! checkGrpRec(IfDp, src, group, IF_STATE_UPSTREAM))
        myLog(LOG_DEBUG, 0, "Route activation request for group: %s from src: %s not valid. Ignoring", inetFmt(group, 1), inetFmt(src, 2));
    else if (! (croute = findRoute(group)))
        myLog(LOG_ERR, 0, "No table entry for %s [From: %s].", inetFmt(group, 1),inetFmt(src, 2));
    else {
        struct originAddrs *nAddr;
        myLog(LOG_INFO, 0, "Route activation for group: %s from src: %s on VIF[%d - %s]", inetFmt(group, 1), inetFmt(src, 2), IfDp->index, IfDp->Name);

        // Allocate a new originAddr struct for the source.
        for (nAddr = croute->origins; nAddr && nAddr->src != src; nAddr = nAddr->next);
        if (! nAddr) {
            if (! (nAddr = (struct originAddrs *)malloc(sizeof(struct originAddrs))))
                myLog(LOG_ERR, errno, "activateRoute: Out of Memory!");  // Freed by clearRoutes() or internUpdateKernelRoute().
            *nAddr = (struct originAddrs){ src, IfDp->index, 0, 0, croute->origins };
            croute->origins = nAddr;
        }

        // Update kernel route table.
        if (! internUpdateKernelRoute(croute, 1))
            myLog(LOG_WARNING, 0, "Route activation for group %s failed for one or more source.", inetFmt(croute->group, 1));

        logRouteTable("Activate Route", 1, NULL, 0);
    }
}

/**
*   This function loops through all routes, and updates the age of any active routes.
*/
void ageActiveRoutes(struct IfDesc *IfDp) {
    struct routeTable   *croute, *nroute;
    IfDp->querier.ageTimer = 0;

    myLog(LOG_DEBUG, 0, "Aging routes in table for %s.", IfDp->Name);
    // Scan all routes...
    for (croute = routing_table; croute; croute = nroute) {
        // Run the aging round algorithm.
        nroute = croute->next;
        // Only age routes if Last member probe is not active...
        if (! BIT_TST(croute->lastMember, IfDp->index)) internAgeRoute(croute, IfDp);
    }
    logRouteTable("Age active routes", 1, NULL, 0);
}

/**
*   Should be called when a leave message is received, to mark a route for the last member probe state.
*/
bool setRouteLastMemberMode(uint32_t group, uint32_t src, struct IfDesc *IfDp) {
    struct routeTable  *croute;
    uint32_t            vifBits = 0;

    // Find route and clear agevifbits on interface the leave request was received on.
    if (! (croute = findRoute(group)) || BIT_TST(croute->lastMember, IfDp->index)) return false;
    else if (CONFIG->fastUpstreamLeave && croute->upstrState) {
        // Do not actually reset the route's vifbits here, it may cause interupted streams. Use temp copy.
        BIT_SET(vifBits, IfDp->index);
        vifBits = croute->vifBits & ~vifBits;

        // Remove downstream host from route
        if (src == 0) zeroDownstreamHosts(croute);
        else clearDownstreamHost(croute, src);

        // Send a leave message right away but only when the route is not active anymore on any downstream host
        // It is possible that there are still some interfaces active but no downstream host in hash table due to hash collision
        // Also possible is still downstream hosts but no active interfaces, due to leave messages not being sent/recieved.
        if (testNoDownstreamHost(croute) && vifBits == 0) {
            myLog(LOG_DEBUG, 0, "quickleave is enabled and this was the last downstream host, leaving group %s now", inetFmt(croute->group, 1));
            removeRoute(croute);
            return false;
        } else myLog(LOG_DEBUG, 0, "quickleave is enabled but there are still some downstream hosts left, not leaving group %s", inetFmt(croute->group, 1));
    }

    // Set the state for interface to last member check.
    BIT_CLR(croute->ageVifBits, IfDp->index);
    BIT_SET(croute->lastMember, IfDp->index);
    croute->ageValue[IfDp->index] = IfDp->querier.ip == IfDp->InAdr.s_addr || IfDp->querier.ver < 3 ? IfDp->conf->qry.lmCount : IfDp->querier.qrv;

    return true;
}

/**
*   Ages groups in the last member check state. If the route is not found, or not in this state, 0 is returned.
*/
inline bool lastMemberGroupAge(uint32_t group, struct IfDesc *IfDp) {
    struct routeTable   *croute;
    return ((croute = findRoute(group)) && BIT_TST(croute->lastMember, IfDp->index)) ? internAgeRoute(croute, IfDp) : true;
}

/**
*   Remove a specified route. Returns 1 on success, nd 0 if route was not found.
*/
static void removeRoute(struct routeTable* croute) {
    struct routeTable *rt;

    // Log the cleanup in debugmode...
    myLog(LOG_DEBUG, 0, "Removed route entry for %s from table.", inetFmt(croute->group, 1));

    // Uninstall current route from kernel
    if (! internUpdateKernelRoute(croute, 0)) myLog(LOG_WARNING, 0, "The removal of route %s from Kernel failed.", inetFmt(croute->group, 1));

    // Send Leave request upstream.
    sendJoinLeaveUpstream(croute, NULL, 0);

    // Update pointers...
    if (croute == routing_table) routing_table = croute->next;
    else {
        for (rt = routing_table; rt->next && rt->next != croute; rt = rt->next);
        rt->next = croute->next;
    }

    // Free the memory, and return.
    free(croute);   // Alloced by findRoute()
    logRouteTable("Remove route", 1, NULL, 0);
}

/**
*   Ages a specific route
*/
static bool internAgeRoute(struct routeTable*  croute, struct IfDesc *IfDp) {
    bool                result = false;

    // Drop age by 1.
    croute->ageValue[IfDp->index]--;

    // Check if there has been any activity.
    if (BIT_TST(croute->ageVifBits, IfDp->index)) {
        // Everything is in perfect order, so we just update the route age and vifBits and reset last member state.
        croute->ageValue[IfDp->index] = IfDp->querier.ip == IfDp->InAdr.s_addr || IfDp->querier.ver < 3 ? IfDp->conf->qry.robustness : IfDp->querier.qrv;
        BIT_CLR(croute->lastMember, IfDp->index);
        result = true;
    } else if (croute->ageValue[IfDp->index] == 0) {
        // VIF has not gotten any response. Remove from route.
        BIT_CLR(croute->ageVifBits, IfDp->index);
        BIT_CLR(croute->vifBits, IfDp->index);
        BIT_CLR(croute->lastMember, IfDp->index);
        if (croute->vifBits == 0) {
            // No activity was registered for any interfaces within the timelimit, so remove the route.
            myLog(LOG_DEBUG, 0, "Removing group %s. Died of old age.", inetFmt(croute->group, 1));
            removeRoute(croute);
        } else {
            // There are still active vifs, update the kernel routing table.
            myLog(LOG_DEBUG, 0, "Removing interface %s from group %s after aging.", IfDp->Name, inetFmt(croute->group, 1));
            if (! internUpdateKernelRoute(croute, 1))
                myLog(LOG_WARNING, 0, "Update of group %s after aging failed.", inetFmt(croute->group, 1));
        }
        result = true;
    }

    // The aging vif bit must be reset for each round.
    BIT_CLR(croute->ageVifBits, IfDp->index);

    return result;
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

        myLog(LOG_DEBUG, 0, "Vif bits %d: 0x%08x", i + 1, croute->vifBits);

        if (activate) {
            // Enforce maxorigins. New entries are inserted in front of list, so find and remove the excess sources.
            if (i >= CONFIG->maxOrigins) {
                for (fAddr = croute->origins; fAddr->next != oAddr; fAddr = fAddr->next);
                fAddr->next = NULL;
                while (oAddr) {
                    myLog(LOG_INFO, 0, "Removing source %s from route %s, too many sources.", inetFmt(oAddr->src, 1), inetFmt(croute->group, 2));
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
                    myLog(LOG_DEBUG, 0, "Setting TTL for Vif %d to %d", IfDp->index, IfDp->conf->threshold);
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
        myLog(LOG_DEBUG, 0, "Current routing table (%s):", header);
        myLog(LOG_DEBUG, 0, "_____|______SRC______|______DST______|_______In_______|_____Out____|____dHost____|_______Data_______|______Rate_____");
    } else if (h) {
        sprintf(buf, "Current Routing Table:\n_____|______SRC______|______DST______|_______In_______|_____Out____|____dHost____|_______Data_______|______Rate_____\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
    if (! croute) {
        myLog(LOG_DEBUG, 0, "No routes in table...");
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
                myLog(LOG_DEBUG, 0, msg, rcount, oAddr ? inetFmt(oAddr->src, 1) : "-", inetFmt(croute->group, 2), oAddr ? IfDp->Name : "",
                    croute->vifBits, ! CONFIG->fastUpstreamLeave ? "not tracked" : testNoDownstreamHost(croute) ? "no" : "yes", oAddr ? oAddr->bytes : 0, oAddr ? oAddr->rate : 0);
            } else {
                sprintf(buf, strcat(msg, "\n"), rcount, oAddr ? inetFmt(oAddr->src, 1) : "-", inetFmt(croute->group, 2), oAddr ? IfDp->Name : "",
                    croute->vifBits, ! CONFIG->fastUpstreamLeave ? "not tracked" : testNoDownstreamHost(croute) ? "no" : "yes", oAddr ? oAddr->bytes : 0, oAddr ? oAddr->rate : 0);
                sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
            }
            oAddr = oAddr ? oAddr->next : NULL;
            rcount++;
        } while (oAddr);

        croute = croute->next;
    } while (croute);

    if (! cliSockAddr) {
        myLog(LOG_DEBUG, 0, "Total|---------------|---------------|----------------|------------|-------------| %14lld B | %10lld B/s", totalb, totalr);
    } else if (h) {
        strcpy(msg, "Total|---------------|---------------|----------------|------------|-------------| %14lld B | %10lld B/s\n");
        sprintf(buf, msg, totalb, totalr);
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
