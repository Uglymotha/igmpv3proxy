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

/**
*   Routing table structure definition.
*/
struct RouteTable {
    struct RouteTable              *next;                     // Pointer to the next group in line.
    uint32_t                        group;                    // The group to route
    uint32_t                        vifBits;                  // Bits representing recieving VIFs.
    struct originAddrs {                                      // The origin adresses (only set on activated routes)
        uint32_t            src;                              // Stream source IP
        unsigned int        vif;                              // Incoming vif index
        uint64_t            bytes, ageBytes, rate;            // Bwcontrol counters
        uint8_t             ageValue;                         // Aging Value for source
        struct originAddrs *next;
    }                              *origins;

    // Keeps the upstream membership state. Per vif flag.
    uint32_t                        upstrState;               // Upstream membership state
    uint32_t                        lastMember;               // Last member flag

    // These parameters contain aging details.
    uint8_t                         ageValue[MAXVIFS];        // Downcounter for death.
    uint32_t                        ageVifBits;               // Bits representing aging VIFs.

    // Keeps downstream hosts information
    uint32_t                        downstreamHostsHashSeed;
    uint8_t                         downstreamHostsHashTable[];
};

// Keeper for the routing table...
static struct RouteTable   *routing_table = NULL;

// Prototypes
static struct RouteTable *findRoute(register uint32_t group);
static bool internAgeRoute(struct RouteTable *croute, struct IfDesc *IfDp);
static bool internUpdateKernelRoute(struct RouteTable *route, int activate);
static void removeRoute(struct RouteTable *croute);

/**
*   Functions for downstream hosts hash table
*/

/**
*   MurmurHash3 32bit hash function by Austin Appleby, public domain
*/
static uint32_t murmurhash3(uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6b;
    x ^= x >> 13;
    x *= 0xc2b2ae35;
    x ^= x >> 16;
    return x;
}

static inline void setDownstreamHost(struct RouteTable *croute, uint32_t src) {
    uint32_t hash = murmurhash3(src ^ croute->downstreamHostsHashSeed) % (CONFIG->downstreamHostsHashTableSize*8);
    BIT_SET(croute->downstreamHostsHashTable[hash/8], hash%8);
}

static inline void clearDownstreamHost(struct RouteTable *croute, uint32_t src) {
    uint32_t hash = murmurhash3(src ^ croute->downstreamHostsHashSeed) % (CONFIG->downstreamHostsHashTableSize*8);
    BIT_CLR(croute->downstreamHostsHashTable[hash/8], hash%8);
}

static inline void zeroDownstreamHosts(struct RouteTable *croute) {
    croute->downstreamHostsHashSeed = ((uint32_t)rand() << 16) | (uint32_t)rand();
    memset(croute->downstreamHostsHashTable, 0, CONFIG->downstreamHostsHashTableSize);
}

static inline bool testNoDownstreamHost(struct RouteTable *croute) {
    for (size_t i = 0; i < CONFIG->downstreamHostsHashTableSize; i++) {
        if (croute->downstreamHostsHashTable[i])
            return false;
    }
    return true;
}

/**
*   Private access function to find a route from a given
*   Route Descriptor.
*/
static struct RouteTable *findRoute(register uint32_t group) {
    struct RouteTable*  croute;
    for (croute = routing_table; croute && croute->group != group; croute = croute->next);
    return croute;
}

/**
*   Calculates bandwidth fo group/subnet filter.
*/
uint64_t getGroupBw(struct subnet group, void *Dp, register int ifdesc) {
    struct RouteTable  *croute;
    struct originAddrs *oAddr;
    register uint64_t   bw = 0;
    struct IfDesc      *IfDp = Dp;
    struct vifconfig   *vifDp = Dp;

    for (croute = routing_table; croute; croute = croute->next) {
        if ((ifdesc ? IfDp->state : vifDp->state) == IF_STATE_UPSTREAM && (croute->group & group.mask) == group.ip) {
            for (oAddr = croute->origins; oAddr; oAddr = oAddr->next) {
                bw = oAddr->vif == (ifdesc ? IfDp->index : *vifDp->index) ? bw + oAddr->rate : bw;
            }
        } else if ((ifdesc ? IfDp->state : vifDp->state) == IF_STATE_DOWNSTREAM && (croute->group & group.mask) == group.ip && BIT_TST(croute->vifBits, ifdesc ? IfDp->index : *vifDp->index)) {
            for (oAddr = croute->origins; oAddr; oAddr = oAddr->next) {
                bw += oAddr->rate;
            }
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
        struct RouteTable  *croute = findRoute(bwUpc->bu_dst.s_addr);
        if (! croute) {
            my_log(LOG_WARNING, 0, "BW_UPCALL: Src %s, Dst %s, but no route found.", inetFmt(bwUpc->bu_dst.s_addr, 1), inetFmt(bwUpc->bu_dst.s_addr, 2));
            continue;
        }

        // Find the source for the upcall and add to counter.
        for (oAddr = croute->origins; oAddr && oAddr->src != bwUpc->bu_src.s_addr; oAddr = oAddr->next);
        if (oAddr) {
            oAddr->bytes += bwUpc->bu_measured.b_bytes;
            oAddr->ageBytes += bwUpc->bu_measured.b_bytes;
            oAddr->rate = bwUpc->bu_measured.b_bytes / CONFIG->bwControlInterval;
            my_log(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to Src %s Dst %s, total %lldB / age %lldB (%lld B/s)", bwUpc->bu_measured.b_bytes, inetFmt(oAddr->src, 1), inetFmt(croute->group, 2), oAddr->bytes, oAddr->ageBytes, oAddr->rate);
            for (IfDp = NULL, getNextIf(&IfDp); IfDp; getNextIf(&IfDp)) {
                // Find the incoming and outgoing interfaces and add to counter.
                if (IfDp->index == oAddr->vif || BIT_TST(croute->vifBits, IfDp->index)) {
                    IfDp->bytes += bwUpc->bu_measured.b_bytes;
                    my_log(LOG_DEBUG, 0, "BW_UPCALL: Added %lld bytes to interface %s (%lld B/s), total %lld.", bwUpc->bu_measured.b_bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
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
    struct RouteTable  *croute;
    struct originAddrs *oAddr;

    // Reset all interface rate counters.
    for (getNextIf(&IfDp); IfDp; IfDp->rate = 0, getNextIf(&IfDp));

    // Go over all routes.
    for (croute = routing_table; croute; croute = croute->next) {
        // Go over all sources.
        for (oAddr = croute->origins; oAddr; oAddr = oAddr->next) {
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
            // On Linux get the S,G statistics via ioct. On BSD they are processed by processBwUpcall().
            struct sioc_sg_req siocReq = { {oAddr->src}, {croute->group}, 0, 0, 0 };
            if (ioctl(getMrouterFD(), SIOCGETSGCNT, (void *)&siocReq, sizeof(siocReq))) {
                my_log(LOG_WARNING, errno, "BW_CONTROL: ioctl failed.");
                continue;
            }
            uint64_t bytes = siocReq.bytecnt - oAddr->bytes;
            oAddr->bytes += bytes;
            oAddr->ageBytes += bytes;
            oAddr->rate = bytes / CONFIG->bwControlInterval;
            my_log(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to Src %s Dst %s (%lld B/s), total %lld.", bytes, inetFmt(oAddr->src, 1), inetFmt(croute->group, 2), oAddr->rate, oAddr->bytes);
#else
            // On BSD systems go over all interfaces.
            for (IfDp = NULL, getNextIf(&IfDp); IfDp; getNextIf(&IfDp)) {
                if (IfDp->index == oAddr->vif || BIT_TST(croute->vifBits, IfDp->index)) {
                    IfDp->rate += oAddr->rate;
                    my_log(LOG_DEBUG, 0, "BW_CONTROL: Added %lld B/s to interface %s (%lld B/s), total %lld.", oAddr->rate, IfDp->Name, IfDp->rate, IfDp->bytes);
                }
            }
#endif
        }
    }

    // On Linux get the interface stats via ioctl.
#ifndef HAVE_STRUCT_BW_UPCALL_BU_SRC
    for (IfDp = NULL, getNextIf(&IfDp); IfDp; getNextIf(&IfDp)) {
        if (IfDp->index != (unsigned int)-1) {
            struct sioc_vif_req siocVReq = { IfDp->index, 0, 0, 0, 0 };
            if (ioctl(getMrouterFD(), SIOCGETVIFCNT, (void *)&siocVReq, sizeof(siocVReq))) {
                my_log(LOG_WARNING, errno, "BW_CONTROL: ioctl failed.");
                continue;
            }
            uint64_t bytes = (IfDp->state == IF_STATE_UPSTREAM ? siocVReq.ibytes : siocVReq.obytes) - IfDp->bytes;
            IfDp->bytes += bytes;
            IfDp->rate = bytes / CONFIG->bwControlInterval;
            my_log(LOG_DEBUG, 0, "BW_CONTROL: Added %lld bytes to interface %s (%lld B/s), total %lld.", bytes, IfDp->Name, IfDp->rate, IfDp->bytes);
        }
    }
#endif

    // Set next timer;
    *tid = timer_setTimer(0, CONFIG->bwControlInterval * 10, "Bandwidth Control", (timer_f)bwControl, tid);
}

/**
*   Internal function to send join or leave requests for a specified route upstream...
*   When rebuilding interfaces use old IfDesc Table for leaving groups.
*/
static void sendJoinLeaveUpstream(struct RouteTable* croute, int join) {
    struct IfDesc   *checkVIF = NULL;

    // Only join a group if there are listeners downstream. Only leave a group if joined.
    if (join && croute->vifBits == 0) {
        my_log(LOG_DEBUG, 0, "No downstream listeners for group %s. No join sent.", inetFmt(croute->group, 1));
        return;
    }

    for (getNextIf(&checkVIF); checkVIF; getNextIf(&checkVIF)) {
        uint64_t bw = BLOCK;
        // Check if this Request is legit to be forwarded to upstream
        if (checkVIF->state != IF_STATE_UPSTREAM || (join && BIT_TST(croute->upstrState, checkVIF->index)) || (! join && ! BIT_TST(croute->upstrState, checkVIF->index))) {
            continue;
        } else if (! join) {
            my_log(LOG_INFO, 0, "Leaving group %s upstream on IF address %s", inetFmt(croute->group, 1), inetFmt(checkVIF->InAdr.s_addr, 2));
            if (k_leaveMcGroup(checkVIF, croute->group)) {
                BIT_CLR(croute->upstrState, checkVIF->index);
            }
        } else if (join && ! (bw = isAddressValidForIf(checkVIF, 1, 0, croute->group))) {
            my_log(LOG_INFO, 0, "The group address %s may not be forwarded to upstream if %s.", inetFmt(croute->group, 1), checkVIF->Name);
        } else if (join && CONFIG->bwControlInterval && checkVIF->ratelimit > 0 && checkVIF->rate > checkVIF->ratelimit) {
            my_log(LOG_WARNING, 0, "Interface %s over bandwidth limit (%d > %d). Not joining %s.", checkVIF->Name, checkVIF->rate, checkVIF->ratelimit, inetFmt(croute->group, 1));
        } else if (join && bw > ALLOW) {
            my_log(LOG_WARNING, 0, "Group %s bandwidth over limit (%lld) on %s. Not joining.", inetFmt(croute->group, 1), bw, checkVIF->Name);
        } else {
            my_log(LOG_INFO, 0, "Joining group %s upstream on IF address %s", inetFmt(croute->group, 1), inetFmt(checkVIF->InAdr.s_addr, 2));
            if (k_joinMcGroup(checkVIF, croute->group)) {
                BIT_SET(croute->upstrState, checkVIF->index);
            }
        }
    }
}

/**
*   Adds a group to list of groups to query.
*/
static void addGvDescL(struct IfDesc *IfDp, u_int32_t group, struct gvDescL **gvDescL) {
    // Allocate memory for groupvifdesc and set.
    struct gvDescL *tmp = *gvDescL;
    *gvDescL = (struct gvDescL *)malloc(sizeof(struct gvDescL));          // Freed by createVifs()
    GroupVifDesc *gvDesc = (GroupVifDesc *)malloc(sizeof(GroupVifDesc));  // Freed by sendGroupSpecificMembershipQuery(), timer_ageQueue() or timer_clearTimer()
    if (! *gvDescL || ! gvDesc) {
        my_log(LOG_ERR, 0, "addGvDescL: Out of Memory");
    }

    // Set the gvdesc for group specific query and add to list.
    gvDesc->group = group;
    strcpy(gvDesc->sourceVif, IfDp->Name);
    gvDesc->started = false;
    gvDesc->aging = false;
    (**gvDescL).gvDesc = gvDesc;
    (**gvDescL).next = tmp;
}

/**
*   Clears / Updates all routes and routing table, and sends Joins / Leaves upstream.
*   Function will return pointer to list of groups to query if states have changed.
*   ----------------------------------------------------------------------------------------
*   State table for calling arguments:
*   NULL, NULL:          Used to remove all routes during shutdown
*   NULL, CONFIG:  Used when quickleave mode was enabled or hashtable sized changed due to config change to reallocate appropriate memory size for routes.
*   CONFIG, NULL:  Used when bwcontrol interval changed during config reload to reinitialize all bw upcalls on BSD systems.
*   IfDesc, NULL:        Used when rebuilding interfaces or SIGHUP (1, 3, 5) if interface has disappeared. Clears routes for IfDesc.
*   IfDesc, IfDesc (==): Used when a new upstream interfaces is detected to join all relevant groups on the interface.
*   IfDesc, void:        Used in 2 ways, depending on process signal status. See below.
*   ----------------------------------------------------------------------------------------
*       When rebuilding interfaces or SIGHUP (status 1, 3, 5):
*         old IfDesc,     new IfDesc    - Used to clear routes for the old IfDesc.
*                                         In this case the new IfDesc is used for comparing interface state and to evaluate black and whitelist changes.
*       When reloading configuration (status 2 or 4):
*         current IfDesc, old vifconfig - Used to clear routes when interfaces transistion to different state because of config change.
*                                         Also used to evaluate black & whitelist changes when interface does not transition.
*                                         In this cases the pointers are reversed (new, old vs old, new) and status and bwl pointers need to be swapped accordingly.
*/
struct gvDescL *clearRoutes(void *Dp1, void *Dp2) {
    struct RouteTable    *croute, *nextroute, *prevroute;
    struct gvDescL       *gvDescL = NULL;
    struct IfDesc        *oIfDp = Dp1, *nIfDp = CONFRELOAD ? Dp1 : Dp2;
    struct vifconfig     *ovcDp = Dp2;
    register unsigned int newstate = nIfDp ? nIfDp->state : IF_STATE_DISABLED,
                          oldstate = (CONFRELOAD && ovcDp) ? ovcDp->state : (CONFRELOAD && ! ovcDp) ? IF_STATE_DOWNSTREAM : (!CONFRELOAD && oIfDp) ? oIfDp->state : IF_STATE_DISABLED,
                          oldindex = oIfDp ? oIfDp->index : (unsigned int)-1,
                          ifdesc   = CONFRELOAD ? 0 : 1;
    void                 *obwDp    = CONFRELOAD ? Dp2 : Dp1, *nbwDp = CONFRELOAD ? Dp1 : Dp2;

    // Loop through all routes...
    for (prevroute = NULL, croute = routing_table; croute; croute = nextroute) {
        register bool query = false, keep = false;
        nextroute = croute->next;

        if (!STARTUP && Dp1 == Dp2) {
            // New upstream interface added, join all relevant groups.
            if (isAddressValidForIf(nIfDp, 1, 0, croute->group) == ALLOW && k_joinMcGroup(nIfDp, croute->group)) {
                my_log(LOG_INFO, 0, "clearRoutes: Joining %s on new upstream interface %s.", inetFmt(croute->group, 1), nIfDp->Name);
            }
            continue;

         } else if (!STARTUP && ! Dp1 && Dp2 == CONFIG) {
             // Quickleave was enabled or disabled, or hastable size was changed. Reallocate appriopriate amount of memory and reinitialize downstreahosts tracking.
             if (! (croute = (struct RouteTable *)realloc(croute, sizeof(struct RouteTable) + (CONFIG->fastUpstreamLeave ? CONFIG->downstreamHostsHashTableSize : 0)))) {
                 my_log(LOG_ERR, 0, "clearRoutes: Out of memory.");
             }
             if (! prevroute) {
                 routing_table = croute;
             } else {
                 prevroute->next = croute;
             }
             if (CONFIG->fastUpstreamLeave) {
                 zeroDownstreamHosts(croute);
             }
             keep = true;

#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
         } else if (!STARTUP && Dp1 == CONFIG && Dp2 == NULL) {
             // BW control interval was changed. Reinitialize all bw_upcalls.
             struct originAddrs *oAddr;
             for (oAddr = croute->origins; oAddr; oAddr = oAddr->next) {
                 deleteUpcalls(oAddr->src, croute->group);
                 internUpdateKernelRoute(croute, 1);
             }
             keep = true;
#endif
         } else if (!STARTUP && oldstate == IF_STATE_UPSTREAM) {
            if ((CONFRELOAD || SSIGHUP) && newstate == IF_STATE_UPSTREAM) {
                // Upstream to upstream during config reload, check route against wl / bl changes.
                if (croute->origins) {
                    struct originAddrs *oAddr = croute->origins, *pAddr = NULL;
                    while (oAddr) {
                        if (isAddressValidForIf(nbwDp, 1, oAddr->src, croute->group) != ALLOW && isAddressValidForIf(obwDp, ifdesc, oAddr->src, croute->group) == ALLOW) {
                            my_log(LOG_WARNING, 0, "clearRoutes: Removing source %s on %s from route %s, no longer allowed.",inetFmt (oAddr->src, 1), oIfDp->Name, inetFmt(croute->group, 2));
                            query = true;
                            delMRoute(oAddr->src, croute->group, oAddr->vif);
                            if (pAddr) {
                                pAddr->next = oAddr->next;
                            } else {
                                croute->origins = oAddr->next;
                            }
                            free(oAddr);
                            oAddr = pAddr ? pAddr->next : croute->origins;
                        } else {
                            pAddr = oAddr;
                            oAddr = oAddr->next;
                        }
                    }
                    keep = croute->origins ? true : false;
                } else keep = true;  // If route has no origins, just keep it.

                // Continue check bl / wl if route still valid or not active on interface.
                if (keep) {
                    if (isAddressValidForIf(nbwDp, 1, 0, croute->group) != ALLOW && isAddressValidForIf(obwDp, ifdesc, 0, croute->group) == ALLOW) {
                        // Group is no longer allowed. Leave if not active on interface set to last member. If active on interface, remove.
                        my_log(LOG_WARNING, 0, "clearRoutes: Leaving group %s on %s, no longer allowed.", inetFmt(croute->group, 1), oIfDp->Name);
                        if (k_leaveMcGroup(oIfDp, croute->group)) {
                            BIT_CLR(croute->upstrState, oIfDp->index);
                        }
                        query = true;
                    } else if (isAddressValidForIf(nbwDp, 1, 0, croute->group) == ALLOW && isAddressValidForIf(obwDp, ifdesc, 0, croute->group) != ALLOW) {
                        // Group is now allowed on upstream interface, join.
                        if (k_joinMcGroup(oIfDp, croute->group) == ALLOW) {
                            my_log(LOG_INFO, 0, "clearRoutes: Joining group %s on %s, it is now allowed.", inetFmt(croute->group, 1), nIfDp->Name);
                            BIT_SET(croute->upstrState, nIfDp->index);
                        }
                    }
                }

            // Transition from upstream to downstream or disabled. Leave group, set to last member and query.
            } else if (newstate != IF_STATE_UPSTREAM && BIT_TST(croute->upstrState, oIfDp->index)) {
                my_log(LOG_WARNING, 0, "clearRoutes: Leaving group %s on %s, no longer upstream.", inetFmt(croute->group, 1), oIfDp->Name);
                if (k_leaveMcGroup(oIfDp, croute->group)) {
                    BIT_CLR(croute->upstrState, oIfDp->index);
                }
                query = true;
                keep = true;
            } else keep = true;   // Upstream to upstream during interface rebuild, or group not valid for interface.

        // Downstream interface transition.
        } else if (!STARTUP && oldstate == IF_STATE_DOWNSTREAM) {
            // If group has become available on downstream vif, send a query.
            if ((CONFRELOAD || SSIGHUP) && newstate == IF_STATE_DOWNSTREAM && isAddressValidForIf(nbwDp, 1, 0, croute->group) == ALLOW && isAddressValidForIf(obwDp, ifdesc, 0, croute->group) != ALLOW) {
                my_log(LOG_INFO, 0, "clearRoutes: Group %s now allowed on Vif %d - %s", inetFmt(croute->group, 1), oldindex, oIfDp->Name);
                addGvDescL(ifdesc ? nIfDp : oIfDp, croute->group, &gvDescL);
            } else if (! BIT_TST(croute->vifBits, oldindex)) {
                // If vif is not part of route, just continue.
                keep = true;
            } else {
                // Check against bl / wl changes on config reload / sighup.
                if ((CONFRELOAD || SSIGHUP) && isAddressValidForIf(nbwDp, 1, 0, croute->group) != ALLOW && isAddressValidForIf(obwDp, ifdesc, 0, croute->group) == ALLOW) {
                    my_log(LOG_WARNING, 0, "clearRoutes: Group %s no longer allowed on Vif %d - %s, removing from route.", inetFmt(croute->group, 1), oldindex, oIfDp->Name);
                    query = true;
                // Transition to disabled / upstream, remove from route and query.
                } else if (newstate != IF_STATE_DOWNSTREAM) {
                    my_log(LOG_WARNING, 0, "clearRoutes: Vif %d - %s removed, removing from route %s.", oldindex, oIfDp->Name, inetFmt(croute->group, 1));
                    query = true;
                }
                keep = !query;   // If above leads to querying the route we assume it should be removed.
                if (query) {
                    BIT_CLR(croute->vifBits, oldindex);
                    BIT_CLR(croute->ageVifBits, oldindex);
                    setRouteLastMemberMode(croute->group, 0, oIfDp);
                    // If there are still listeners, set route to last member mode and keep. If no more listeners remove the route.
                    if (croute->vifBits > 0 || croute->ageVifBits > 0) {
                        keep = true;
                    }
                }
            }
        }

        // We are interested in any route which is valid for an added upstream interface, so that it may be joined again.
        // Also any route that was set to last memeber state or will actually be removed. Build a list of downstream interfaces to query for the group.
        // In this case all vifs that may be part of the route since the vif table is in incosistent state (being run from inside createVifs().
        if (query) {
            struct IfDesc* IfDp;
            for (IfDp = NULL, getNextIf(&IfDp); IfDp; getNextIf(&IfDp)) {
                if (IfDp->state == IF_STATE_DOWNSTREAM && isAddressValidForIf(IfDp, 0, 0, croute->group) == ALLOW) {
                    addGvDescL(IfDp, croute->group, &gvDescL);
                }
            }
        }

        // If the current route is not to be removed, continue.
        if (keep) {
            prevroute = croute;
            continue;
        }

        // Route will be removed, send a leave message upstream on current interfaces.
        sendJoinLeaveUpstream(croute, 0);

        // Remove the route from routing table.
        if (croute == routing_table) {
            routing_table = croute->next;
        } else {
            prevroute->next = croute->next;
        } 

        // Log the cleanup in debugmode...
        my_log(LOG_DEBUG, 0, "clearRoutes: Removing route entry for %s", inetFmt(croute->group, 1));

        // Uninstall current route
        if (! internUpdateKernelRoute(croute, 0)) {
            my_log(LOG_WARNING, 0, "clearRoutes: The removal from Kernel failed.");
        }

        // Clear memory, and set pointer to next route...
        free(croute);   // Alloced by insertRoute()
    }

    if (! routing_table) {
        // Send a notice that the routing table is empty...
        my_log(LOG_NOTICE, 0, "clearRoutes: Routing table is empty.");
    }

    return gvDescL;
}

/**
*   Returns the active vifbits for a route.
*/
uint32_t getRouteVifbits(register uint32_t group) {
    struct RouteTable*  croute;
    for (croute = routing_table; croute && croute->group != group; croute = croute->next);
    return croute ? croute->vifBits : 0;
}

/**
*   Adds a specified route to the routingtable. If the route already exists, the existing route id updated.
*/
struct RouteTable *insertRoute(register uint32_t src, register uint32_t group, struct IfDesc *IfDp) {
    struct RouteTable  *croute;
    unsigned int        ifx = IfDp ? IfDp->index : (unsigned int)-1;

    // Santiycheck the VIF index...
    if (ifx != (unsigned int)-1 && ifx >= MAXVIFS) {
        my_log(LOG_WARNING, 0, "The VIF Ix %d is out of range (0-%d). Table insert failed.", ifx, MAXVIFS-1);
        return NULL;
    } else if (! (croute = findRoute(group))) {
        struct RouteTable*  newroute;

        my_log(LOG_DEBUG, 0, "No existing route for %s. Create new.", inetFmt(group, 1));

        // Create and initialize the new route table entry. Freed by clearRoutes() or removeRoute()
        if (! (newroute = (struct RouteTable*)malloc(sizeof(struct RouteTable) + (CONFIG->fastUpstreamLeave ? CONFIG->downstreamHostsHashTableSize : 0)))) {
            my_log(LOG_ERR, 0, "insertRoute: Out of memory.");
        }

        // Insert the route desc and clear all pointers...
        newroute->group      = group;
        newroute->origins    = NULL;
        newroute->next       = NULL;

        // Init downstream hosts bit hash table
        if (CONFIG->fastUpstreamLeave) {
            zeroDownstreamHosts(newroute);
        }
        // Add downstream host
        if (src != 0) {
            setDownstreamHost(newroute, src);
        }

        // The group is not joined initially.
        newroute->upstrState = newroute->lastMember = newroute->ageVifBits = newroute->vifBits = 0;

        // The route is not active yet, so the age is unimportant.
        memset(newroute->ageValue, 0, sizeof(newroute->ageValue));
        if (IfDp->state == IF_STATE_DOWNSTREAM) {
            BIT_SET(newroute->vifBits, ifx);
            newroute->ageValue[ifx] = IfDp->querier.ip == IfDp->InAdr.s_addr || IfDp->querier.ver < 3 ? IfDp->qry->robustness : IfDp->querier.qrv;
        }

        // Check if there is a table already....
        if (! routing_table) {
            // No location set, so insert in on the table top.
            routing_table = newroute;
            my_log(LOG_DEBUG, 0, "No routes in table. Insert at beginning.");
        } else {
            my_log(LOG_DEBUG, 0, "Found existing routes. Find insert location.");
            for (croute = routing_table; croute->next && croute->next->group < group; croute = croute->next);

            // Check if the route could be inserted at the beginning or other position.
            if (croute == routing_table && croute->group > group) {
                my_log(LOG_DEBUG, 0, "Inserting at beginning, before route %s", inetFmt(croute->group, 1));
                newroute->next = croute;
                routing_table = newroute;
            } else {
                my_log(LOG_DEBUG, 0, "Inserting after route %s", inetFmt(croute->group, 1));
                newroute->next = croute->next;
                croute->next = newroute;
            }
        }

        // Set the new route as the current...
        croute = newroute;
    } else {
        // The route exists already, so just update it.
        BIT_SET(croute->vifBits, ifx);

        // Register the VIF activity for the aging routine
        BIT_SET(croute->ageVifBits, ifx);

        // Register dwnstrHosts for host tracking if fastleave is enabled
        if (CONFIG->fastUpstreamLeave && src != 0) {
            setDownstreamHost(croute, src);
        }

        // Log the update in debugmode...
        my_log(LOG_INFO, 0, "Updated route entry for %s on VIF #%d", inetFmt(croute->group, 1), ifx);

        // Update route in kernel...
        if (! internUpdateKernelRoute(croute, 1)) {
            my_log(LOG_WARNING, 0, "The insertion of route %s into Kernel failed.", inetFmt(croute->group, 1));
        }
    }

    // Send join message upstream.
    sendJoinLeaveUpstream(croute, 1);

    logRouteTable("Insert Route", 1, NULL, 0);

    return croute;
}

/**
*   Activates a passive group. If the group is already activated, it's reinstalled in the kernel.
*   If the route is activated, no originAddr is needed.
*/
void activateRoute(register uint32_t src, register uint32_t group, struct IfDesc *IfDp) {
    struct RouteTable  *croute;
    struct originAddrs *nAddr;

    // Find the requested route.
    if (! (croute = findRoute(group))) {
        my_log(LOG_DEBUG, 0, "No table entry for %s [From: %s]. Inserting route.", inetFmt(group, 1),inetFmt(src, 2));

        // Insert route, but no interfaces have yet requested it downstream.
        if (! (croute = insertRoute(0, group, IfDp))) return;
    }

    // Allocate a new originAddr struct for the source.
    for (nAddr = croute->origins; nAddr && nAddr->src != src; nAddr = nAddr->next);
    if (! nAddr) {
        nAddr = (struct originAddrs *)malloc(sizeof(struct originAddrs));    // Freed by clearRoutes() or internUpdateKernelRoute().
        if (! nAddr) {
            my_log(LOG_ERR, ENOMEM, "activateRoute: Out of Memory!");
        }
        *nAddr = (struct originAddrs){ src, IfDp->index, 0, 0, 0, IfDp->qry->robustness, croute->origins };
        croute->origins = nAddr;
    }

    // Update kernel route table.
    if (! internUpdateKernelRoute(croute, 1)) {
        my_log(LOG_WARNING, 0, "Route activation for group %s failed for one or more source.", inetFmt(croute->group, 1));
    }

    logRouteTable("Activate Route", 1, NULL, 0);
    return;
}

/**
*   This function loops through all routes, and updates the age of any active routes.
*/
void ageActiveRoutes(struct IfDesc *IfDp) {
    struct RouteTable   *croute, *nroute;
    IfDp->querier.ageTimer = 0;

    my_log(LOG_DEBUG, 0, "Aging routes in table for %s.", IfDp->Name);
    // Scan all routes...
    for (croute = routing_table; croute; croute = nroute) {
        // Run the aging round algorithm.
        nroute = croute->next;
        if (! BIT_TST(croute->lastMember, IfDp->index)) {
            // Only age routes if Last member probe is not active...
            internAgeRoute(croute, IfDp);
        }
    }
    logRouteTable("Age active routes", 1, NULL, 0);
}

/**
*   Should be called when a leave message is received, to mark a route for the last member probe state.
*/
bool setRouteLastMemberMode(uint32_t group, uint32_t src, struct IfDesc *IfDp) {
    struct RouteTable  *croute;
    uint32_t            vifBits = 0;

    // Find route and clear agevifbits on interface the leave request was received on.
    if (! (croute = findRoute(group)) || BIT_TST(croute->lastMember, IfDp->index)) {
        return false;
    } else if (CONFIG->fastUpstreamLeave && croute->upstrState) {
        // Do not actually reset the route's vifbits here, it may cause interupted streams. Use temp copy.
        BIT_SET(vifBits, IfDp->index);
        vifBits = croute->vifBits & ~vifBits;

        // Remove downstream host from route
        if (src == 0) {
            zeroDownstreamHosts(croute);
        } else {
            clearDownstreamHost(croute, src);
        }

        // Send a leave message right away but only when the route is not active anymore on any downstream host
        // It is possible that there are still some interfaces active but no downstream host in hash table due to hash collision
        // Also possible is still downstream hosts but no active interfaces, due to leave messages not being sent/recieved.
        if (testNoDownstreamHost(croute) && vifBits == 0) {
            my_log(LOG_DEBUG, 0, "quickleave is enabled and this was the last downstream host, leaving group %s now", inetFmt(croute->group, 1));
            removeRoute(croute);
            return false;
        } else {
            my_log(LOG_DEBUG, 0, "quickleave is enabled but there are still some downstream hosts left, not leaving group %s", inetFmt(croute->group, 1));
        }
    }

    // Set the state for interface to last member check.
    BIT_CLR(croute->ageVifBits, IfDp->index);
    BIT_SET(croute->lastMember, IfDp->index);
    croute->ageValue[IfDp->index] = IfDp->querier.ip == IfDp->InAdr.s_addr || IfDp->querier.ver < 3 ? IfDp->qry->lmCount : IfDp->querier.qrv;

    return true;
}

/**
*   Ages groups in the last member check state. If the route is not found, or not in this state, 0 is returned.
*/
bool lastMemberGroupAge(uint32_t group, struct IfDesc *IfDp) {
    struct RouteTable   *croute;
    return ((croute = findRoute(group)) && BIT_TST(croute->lastMember, IfDp->index)) ? internAgeRoute(croute, IfDp) : true;
}

/**
*   Remove a specified route. Returns 1 on success, nd 0 if route was not found.
*/
static void removeRoute(struct RouteTable* croute) {
    struct RouteTable *rt;

    // Log the cleanup in debugmode...
    my_log(LOG_DEBUG, 0, "Removed route entry for %s from table.", inetFmt(croute->group, 1));

    // Uninstall current route from kernel
    if (! internUpdateKernelRoute(croute, 0)) {
        my_log(LOG_WARNING, 0, "The removal of route %s from Kernel failed.", inetFmt(croute->group, 1));
    }

    // Send Leave request upstream.
    sendJoinLeaveUpstream(croute, 0);

    // Update pointers...
    if (croute == routing_table) {
        routing_table = croute->next;
    } else {
        for (rt = routing_table; rt->next && rt->next != croute; rt = rt->next);
        rt->next = croute->next;
    }

    // Free the memory, and return.
    free(croute);   // Alloced by insertRoute()
    logRouteTable("Remove route", 1, NULL, 0);
}

/**
*   Ages a specific route
*/
static bool internAgeRoute(struct RouteTable*  croute, struct IfDesc *IfDp) {
    struct originAddrs *oAddr = croute->origins, *pAddr = NULL;
    bool                result = false;

    // First Age sources if bw control is enabled.
    if (CONFIG->bwControlInterval && BIT_TST(croute->vifBits, IfDp->index)) {
        while (oAddr) {
            oAddr->ageValue = oAddr->ageValue > (unsigned int)0 && oAddr->ageBytes > (unsigned int)0 ? CONFIG->robustnessValue : oAddr->ageValue - (unsigned int)1;
            if (oAddr->ageValue == 0 && oAddr->ageBytes == 0) {
                my_log(LOG_DEBUG, 0, "Removing route Src %s, Dst %s, no traffic for %ds.", inetFmt(oAddr->src, 1), inetFmt(croute->group, 2), ((CONFIG->robustnessValue) * CONFIG->queryInterval));
                delMRoute(oAddr->src, croute->group, oAddr->vif);
                if (pAddr) {
                    pAddr->next = oAddr->next;
                } else {
                    croute->origins = oAddr->next;
                }
                free(oAddr);
                oAddr = pAddr ? pAddr->next : croute->origins;
            } else if (oAddr->ageValue == IfDp->qry->robustness) {
                oAddr->ageBytes = 0;
                pAddr = oAddr;
                oAddr = oAddr->next;
            }
        }
    }

    // Drop age by 1.
    croute->ageValue[IfDp->index]--;

    // Check if there has been any activity.
    if (BIT_TST(croute->ageVifBits, IfDp->index)) {
        // Everything is in perfect order, so we just update the route age and vifBits and reset last member state.
        croute->ageValue[IfDp->index] = IfDp->querier.ip == IfDp->InAdr.s_addr || IfDp->querier.ver < 3 ? IfDp->qry->robustness : IfDp->querier.qrv;
        BIT_CLR(croute->lastMember, IfDp->index);
        result = true;
    } else if (croute->ageValue[IfDp->index] == 0) {
        // VIF has not gotten any response. Remove from route.
        BIT_CLR(croute->ageVifBits, IfDp->index);
        BIT_CLR(croute->vifBits, IfDp->index);
        BIT_CLR(croute->lastMember, IfDp->index);
        if (croute->vifBits == 0) {
            // No activity was registered for any interfaces within the timelimit, so remove the route.
            my_log(LOG_DEBUG, 0, "Removing group %s. Died of old age.", inetFmt(croute->group, 1));
            removeRoute(croute);
        } else {
            // There are still active vifs, update the kernel routing table.
            my_log(LOG_DEBUG, 0, "Removing interface %s from group %s after aging.", IfDp->Name, inetFmt(croute->group, 1));
            if (! internUpdateKernelRoute(croute, 1)) {
                my_log(LOG_WARNING, 0, "Update of group %s after aging failed.", inetFmt(croute->group, 1));
            }
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
static bool internUpdateKernelRoute(struct RouteTable *croute, int activate) {
    struct  IfDesc      *Dp = NULL;
    struct  originAddrs *oAddr = croute->origins;
    uint8_t              ttlVc[MAXVIFS] = {0};
    unsigned int         i = 0;
    bool                 result = true;

    while (oAddr) {
        struct  originAddrs *fAddr = NULL;

        my_log(LOG_DEBUG, 0, "Vif bits %d: 0x%08x", i + 1, croute->vifBits);

        if (activate) {
            // When BW control is disabled, enforce maxorigins. New entries are inserted in front of list, so find and remove the excess sources.
            if (! CONFIG->bwControlInterval && i >= CONFIG->maxOrigins) {
                for (fAddr = croute->origins; fAddr->next != oAddr; fAddr = fAddr->next);
                fAddr->next = NULL;
                while (oAddr) {
                    my_log(LOG_INFO, 0, "Removing source %s from route %s, too many sources.", inetFmt(oAddr->src, 1), inetFmt(croute->group, 2));
                    fAddr = oAddr;
                    oAddr = oAddr->next;
                    delMRoute(fAddr->src, croute->group, fAddr->vif);
                    free(fAddr);
                }
                break;
            }

            // Set the TTL's for the route descriptor...
            for (getNextIf(&Dp); Dp; getNextIf(&Dp)) {
                if (Dp->state == IF_STATE_DOWNSTREAM && BIT_TST(croute->vifBits, Dp->index)) {
                    my_log(LOG_DEBUG, 0, "Setting TTL for Vif %d to %d", Dp->index, Dp->threshold);
                    ttlVc[Dp->index] = Dp->threshold;
                }
            }
        } else {
            // The origin should be freed if route is removed.
            fAddr = oAddr;
        }

        // Do the actual Kernel route update. Update return state, accordingly. add/delmroute returns 1 if failed.
        result &= (activate && ! addMRoute(oAddr->src, croute->group, oAddr->vif, ttlVc)) || (! activate && ! delMRoute(oAddr->src, croute->group, oAddr->vif)) ? true : false;
        oAddr = oAddr->next;
        free(fAddr);
        i++;
    }

    // Return the accumulated result of adding / removing routes.
    return result;
}

/**
*   Debug function that writes the routing table entries to the log or sends them to the cli socket specified in arguments.
*/
void logRouteTable(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd) {
    struct RouteTable  *croute = routing_table;
    struct originAddrs *oAddr;
    struct IfDesc      *Dp = NULL;
    char                msg[CLI_CMD_BUF] = "", buf[CLI_CMD_BUF] = "";
    unsigned int        rcount = 1;

    if (! cliSockAddr) {
        my_log(LOG_DEBUG, 0, "Current routing table (%s):", header);
        my_log(LOG_DEBUG, 0, "_____|______SRC______|______DST______|_______In_______|_____Out____|_dHost_|_______Data_______|______Rate_____");
    } else if (h) {
        sprintf(buf, "Current Routing Table:\n_____|______SRC______|______DST______|_______In_______|_____Out____|_dHost_|_______Data_______|______Rate_____\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
    if (! croute) {
        my_log(LOG_DEBUG, 0, "No routes in table...");
    } else do {
        oAddr = croute->origins;
        do {
            if (oAddr) for (Dp = NULL, getNextIf(&Dp); Dp && Dp->index != oAddr->vif; getNextIf(&Dp));
            if (h) {
                strcpy(msg, "%4d |%15s|%15s|%16s| 0x%08x | %5s | %14lld B | %10lld B/s");
            } else {
                strcpy(msg, "%d %s %s %s %08x %s %ld %ld");
            }
            if (! cliSockAddr) {
                my_log(LOG_DEBUG, 0, msg, rcount, oAddr ? inetFmt(oAddr->src, 1) : "-", inetFmt(croute->group, 2), oAddr ? Dp->Name : "",
                    croute->vifBits, ! CONFIG->fastUpstreamLeave ? "not tracked" : testNoDownstreamHost(croute) ? "no" : "yes", oAddr ? oAddr->bytes : 0, oAddr ? oAddr->rate : 0);
            } else {
                sprintf(buf, strcat(msg, "\n"), rcount, oAddr ? inetFmt(oAddr->src, 1) : "-", inetFmt(croute->group, 2), oAddr ? Dp->Name : "",
                    croute->vifBits, ! CONFIG->fastUpstreamLeave ? "not tracked" : testNoDownstreamHost(croute) ? "no" : "yes", oAddr ? oAddr->bytes : 0, oAddr ? oAddr->rate : 0);
                sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
            }
            oAddr = oAddr ? oAddr->next : NULL;
            rcount++;
        } while (oAddr);

        croute = croute->next;
    } while (croute);

    if (! cliSockAddr) {
        my_log(LOG_DEBUG, 0, "--------------------------------------------------------------------------------------------------------------");
    } else if (h) {
        sprintf(buf, "--------------------------------------------------------------------------------------------------------------\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
