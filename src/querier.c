/*
**  igmpv3proxy - IGMPv3 Proxy based multicast router
**  Copyright (C) 2022 Sietse van Zanen <uglymotha@wizdom.nu>
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
*   querier.c: Process group and group and source specific queries.
*/

#include "igmpv3proxy.h"
#include "mctable.h"

static struct qlst *qL = NULL;    // List of running GSQ
static uint32_t     qC = 0;       // Querier count.

/**
*   Function to control the IGMP querier process on interfaces.
*/
void ctrlQuerier(int start, struct IfDesc *IfDp) {
    if (start == 0 || start == 2) {
        // Remove all queries, timers and reset all IGMP status for interface.
        LOG(LOG_INFO, 0, "ctrlQuerier: Stopping querier process on %s", IfDp->Name);
        delQuery(IfDp, NULL, NULL, NULL, 0);
        if ( (SHUTDOWN && IS_DOWNSTREAM(IfDp->state)) ||
             (IS_DOWNSTREAM(IF_OLDSTATE(IfDp)) && !IS_DOWNSTREAM(IF_NEWSTATE(IfDp)))) {
            LOG(LOG_INFO, 0, "ctrlQuerier: Leaving all routers and all igmp groups on %s", IfDp->Name);
            k_updateGroup(IfDp, false, allrouters_group, 1, (uint32_t)-1);
            k_updateGroup(IfDp, false, alligmp3_group, 1, (uint32_t)-1);
        }
        timer_clearTimer(IfDp->querier.Timer);
        timer_clearTimer(IfDp->querier.ageTimer);
        memset(&IfDp->querier, 0, sizeof(struct querier));
        IfDp->querier.ip = (uint32_t)-1;
        if (!IS_DOWNSTREAM(IF_NEWSTATE(IfDp)))
            IfDp->conf->qry.ver = 3;
    }
    if (start && IS_DOWNSTREAM(IF_NEWSTATE(IfDp))) {
        // Join all routers groups and start querier process on new downstream interfaces.
        LOG(LOG_INFO, 0, "ctrlQuerier: Starting querier and joining all routers and all igmp groups on %s", IfDp->Name);
        k_updateGroup(IfDp, true, allrouters_group, 1, (uint32_t)-1);
        k_updateGroup(IfDp, true, alligmp3_group, 1, (uint32_t)-1);
        uint16_t interval = IfDp->conf->qry.ver == 3 ? getIgmpExp(IfDp->conf->qry.interval, 0)
                                                     : IfDp->conf->qry.ver == 2 ? IfDp->conf->qry.interval
                                                     : 10;
        IfDp->conf->qry.startupQueryInterval = interval > 4 ? (IfDp->conf->qry.ver == 3 ? getIgmpExp(interval / 4, 1)
                                                                                        : interval / 4)
                                                            : 1;
        IfDp->conf->qry.startupQueryCount = IfDp->conf->qry.robustness;
        sendGeneralMemberQuery(IfDp);
    }
}

/**
*   Adds a source to list of sources to query. Toggles appropriate flags and adds to qlst array.
*/
inline struct qlst *addSrcToQlst(struct src *src, struct IfDesc *IfDp, struct qlst *qlst, uint32_t srcHash) {
    uint32_t nsrcs = qlst ? qlst->nsrcs : 0;

    // Add source to query list, prevent duplicates.
    if (NOT_SET(src, lm, IfDp) && (nsrcs == 0 || qlst->src[qlst->nsrcs - 1]->ip != src->ip)) {
        // In case source is in running query, remove it there and add to current list.
        if (IS_SET(src, qry, IfDp))
            delQuery(IfDp, NULL, NULL, src, 0);

        // Add to source to the query list. Allocate memory per 32 sources.
        LOG(LOG_DEBUG, 0, "addSrcToQlst: Adding source %s to query list for %s (%d).",
                           inetFmt(src->ip, 1), inetFmt(src->mct->group, 2), nsrcs + 1);
        if ( (nsrcs & 0x1F) == 0 &&
            ! _realloc(qlst, qry, QRYSZ(nsrcs), nsrcs == 0 ? QRYSZ(nsrcs) : QRYSZ(nsrcs) - (32 * sizeof(void *))))
            LOG(LOG_ERR, errno, "addSrcToQlst; Out of Memory.");  // Freed by delQuery().
        if (nsrcs == 0)
            *qlst = (struct qlst){ NULL, NULL, src->mct, IfDp, 0, 4, IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount, 0, 0 };
        BIT_SET(src->vifB.d, IfDp->index);
        BIT_SET(src->vifB.qry, IfDp->index);
        BIT_SET(src->vifB.lm, IfDp->index);
        src->vifB.age[IfDp->index] = qlst->misc;
        qlst->src[qlst->nsrcs++] = src;
        CLR_HASH(src->dHostsHT, srcHash);
        if (srcHash != (uint32_t)-1 && src->vifB.us && NO_HASH(src->dHostsHT)) {
            LOG(LOG_INFO, 0, "addSrcToQlst: Last downstream host, quickleave source %s in group %s on %s.",
                              inetFmt(src->ip, 2), inetFmt(src->mct->group, 3), IfDp->Name);
            joinBlockSrc(src, NULL, false);
        }
    }

    return qlst;
}

/**
*   Process a group specific query received from other querier.
*/
inline void processGroupQuery(struct IfDesc *IfDp, struct igmpv3_query *query, uint32_t nsrcs, uint8_t ver) {
    struct mcTable  *mct = findGroup(query->igmp_group.s_addr, false);
    // If no group found for query, not active or denied on interface return.
    if (! mct || NOT_SET(mct, d, IfDp) || !checkFilters(IfDp, 1, NULL, mct)) {
        LOG(LOG_DEBUG, 0, "processGroupQuery: Query on %s for %s, but %s.", IfDp->Name, inetFmt(query->igmp_group.s_addr, 1),
                           ! mct ? "not found." : NOT_SET(mct, d, IfDp) ? "not active." : "denied.");
    } else if (nsrcs == 0 && NOT_SET(mct, lm, IfDp)) {
        // Only start last member aging when group is allowed on interface.
        LOG(LOG_INFO, 0, "processGroupQuery: Group specific query for %s on %s.", inetFmt(mct->group, 1), IfDp->Name);
        startQuery(IfDp, &(struct qlst){ NULL, NULL, mct, IfDp, 0, 2, query->igmp_code,
                                         ver == 3 ? (query->igmp_misc & ~0x8) : IfDp->conf->qry.lmCount, 0, 0 });
    } else if (nsrcs > 0) {
        // Sort array of sources in query.
        struct qlst *qlst = NULL;
        struct src  *src  = mct->sources;
        nsrcs = sortArr((uint32_t *)query->igmp_src, nsrcs);
        FOR_IF(uint32_t i = 0; src && i < nsrcs; src = src->next, src->ip >= query->igmp_src[i].s_addr) {
            // Do not add denied sources to query list.
            if (src->ip == query->igmp_src[i].s_addr && checkFilters(IfDp, 1, src, mct))
                qlst = addSrcToQlst(src, IfDp, qlst, (uint32_t)-1);
            i++;
        }
        LOG(LOG_INFO, 0, "processGroupQuery: Group group and source specific query for %s with %d sources on %s.",
                           inetFmt(mct->group, 1), nsrcs, IfDp->Name);
        startQuery(IfDp, qlst);
    }
}

/**
*   Start a query or last member aging on interface.
*/
inline void startQuery(struct IfDesc *IfDp, struct qlst *qlst) {
    // We may be called without qlst, in case of gssq which had no valid sources to query.
    if (! qlst)
        return;

    if (qlst->nsrcs == 0) {
        struct qlst *qlst1;
        // Check if we should take over a running GSQ. Allocate a new qlst as given may change when new queries are started. 
        if (! _malloc(qlst1, qry, QLSZ))  // Freed by delQuery().
            LOG(LOG_ERR, errno, "starQuery: Out of Memory.");
        memcpy(qlst1, qlst, sizeof(struct qlst));
        if (BIT_TST(qlst->type, 1) && IS_SET(qlst->mct, qry, IfDp))
            delQuery(IfDp, NULL, qlst->mct, NULL, 2);
        qlst = qlst1;
        LOG(LOG_INFO, 0, "startQuery #%d: Querying group %s on %s", qC + 1, inetFmt(qlst->mct->group, 1), IfDp->Name);
        BIT_SET(qlst->mct->vifB.qry, IfDp->index);
        BIT_SET(qlst->mct->vifB.lm, IfDp->index);
        qlst->mct->vifB.age[IfDp->index] = qlst->misc;
    } else
        LOG(LOG_INFO, 0, "startQuery #%d: Querying %d sources for %s on %s.",
                          qC, qlst->nsrcs, inetFmt(qlst->mct->group, 1), IfDp->Name);

    // Allocate and assign new querier.
    if (qL) {
        qlst->next = qL;
        qL->prev = qlst;
    }
    qL = qlst;
    qC++;

    if (!IQUERY)
        BIT_SET(qlst->type, 3);
    groupSpecificQuery(qlst);
}

/**
*   Sends a group specific query and / or last member ages group and sources.
*   bit 0 - Router Supress flag
*   bit 1 - Group Specific Query
*   bit 2 - Group and Source Specific query
*   bit 3 - Other Querier
*/
void groupSpecificQuery(struct qlst *qlst) {
    struct igmpv3_query *query = NULL, *query1 = NULL, *query2 = NULL;
    uint32_t            i = 0, nsrcs = qlst->nsrcs, group = qlst->mct->group,
                        size = sizeof(struct igmpv3_query) + nsrcs * sizeof(struct in_addr);

    // Do aging upon reentry.
    if (++qlst->cnt > 1) {
        if (BIT_TST(qlst->type, 1)) {
            // Age group in case of GSQ.
            if (NOT_SET(qlst->mct, lm, qlst->IfDp)) {
                LOG(LOG_INFO, 0, "GSQ: %s no longer in last member state on %s.", inetFmt(qlst->mct->group, 1), qlst->IfDp->Name);
                BIT_SET(qlst->type, 0);  // Suppress router processing flag for next query.
                if (BIT_TST(qlst->type, 3))
                    // If aging for other querier, we're done.
                    qlst->cnt = qlst->misc + 1;
            } else if (--qlst->mct->vifB.age[qlst->IfDp->index] == 0)
                qlst->cnt = qlst->misc + 1;  // Make sure we're done.
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
                    } else {
                        // In exclude mode sources should be kept and MFC updated, as traffic should no longer be forwarded.
                        LOG(LOG_INFO, 0, "GSQ: Source %s from group %s on %s expired.",
                                          inetFmt(qlst->src[i]->ip, 1), inetFmt(qlst->mct->group, 2), qlst->IfDp->Name);
                        if (qlst->src[i]->mfc)
                            activateRoute(qlst->src[i]->mfc->IfDp, qlst->src[i], qlst->src[i]->ip, qlst->src[i]->mct->group, true);
                    }
                    qlst->src[i] = qlst->src[--qlst->nsrcs];
                } else
                    // Source still in last member state, add to  query.
                    query1->igmp_src[query1->igmp_nsrcs++].s_addr = qlst->src[i++]->ip;
            }
            if (BIT_TST(qlst->type, 3) && qlst->nsrcs == 0)
                // If aging for other querier and no sources left to age, we're done.
                qlst->cnt = qlst->misc + 1;
        }
    }

    // Send queries if not aging for other querier. Use qlst in case of group query, or first group and source query.
    if (!BIT_TST(qlst->type, 3) && (   (qlst->cnt <= qlst->misc && BIT_TST(qlst->type, 1))
                                    || (qlst->cnt == 1          && BIT_TST(qlst->type, 2)))) {
        if (! (query = malloc(sizeof(struct igmpv3_query) + qlst->nsrcs * sizeof(struct in_addr))))  // Freed by Self
            LOG(LOG_ERR, errno, "GSQ: Out of Memory.");
        *query = (struct igmpv3_query){ qlst->type, qlst->code, 0, {qlst->mct->group}, qlst->misc, 0, qlst->nsrcs };
        if (BIT_TST(qlst->type, 2))
            for (uint32_t i = 0; i < qlst->nsrcs; query->igmp_src[i].s_addr = qlst->src[i]->ip, i++);
        sendIgmp(qlst->IfDp, query);
        free(query);  // Alloced by Self
    } else if (!BIT_TST(qlst->type, 3) && qlst->cnt <= qlst->misc && BIT_TST(qlst->type, 2)) {
        if (query1 && query1->igmp_nsrcs)
            sendIgmp(qlst->IfDp, query1);
        if (query2 && query2->igmp_nsrcs)
            sendIgmp(qlst->IfDp, query2);
    }

    if (qlst->cnt <= qlst->misc && (   (BIT_TST(qlst->type, 1) && IS_SET(qlst->mct, lm, qlst->IfDp))
                                    || (BIT_TST(qlst->type, 2) && qlst->nsrcs > 0))) {
        // Set timer for next round if there is still aging to do.
        uint32_t timeout = (BIT_TST(qlst->type, 3)            ? qlst->code
                         :  qlst->IfDp->querier.ver == 3      ? getIgmpExp(qlst->IfDp->conf->qry.lmInterval, 0)
                         :  qlst->IfDp->conf->qry.lmInterval) + 1;
        sprintf(msg, "GSQ (%s): %15s/%u", qlst->IfDp->Name, inetFmt(qlst->mct->group, 1), qlst->nsrcs);
        qlst->tid = timer_setTimer(timeout, msg, groupSpecificQuery, qlst);
    } else if (qlst->cnt >= qlst->misc && (   (BIT_TST(qlst->type, 2) && !qlst->mct->mode && qlst->mct->nsrcs == 0)
                                           || (BIT_TST(qlst->type, 1) && qlst->mct->vifB.age[qlst->IfDp->index] == 0
                                              && IS_SET(qlst->mct, lm, qlst->IfDp) && !BIT_TST(qlst->mct->v1Bits, qlst->IfDp->index)
                                              && toInclude(qlst->mct, qlst->IfDp)))) {
        // Group in exclude mode has aged, switch to include or inlcude mode group has no more sources.
        // RFC says v2 groups should not switch and age normally, but v2 hosts must respond to query, so should be safe.
        LOG(LOG_DEBUG, 0, "GSQ: Removing group %s from %s after querying.",
                           inetFmt(qlst->mct->group, 1), qlst->IfDp->Name);
        delGroup(qlst->mct, qlst->IfDp, NULL, 1);
    } else {
        LOG(LOG_INFO, 0, "GSQ: done querying %s/%d on %s.", inetFmt(qlst->mct->group, 1), nsrcs, qlst->IfDp->Name);
        delQuery(qlst->IfDp, qlst, NULL, NULL, 0);
    }

    free(query1);  // Alloced by self.
    free(query2);  // Alloced by self.
    logRouteTable("GSQ", 1, -1, group, (uint32_t)-1);
}

/**
*   Removes all active queriers specified by parameters.
*/
void delQuery(struct IfDesc *IfDp, void *qry, void *_mct, void *_src, uint8_t type) {
    struct qlst     *ql  = qry ? qry : qL;
    struct mcTable  *mct = qry ? ql->mct : _mct;
    struct src      *src = _src;
    LOG(LOG_INFO, 0, "delQry: Removing quer%s%s%s%s on %s.", qry || src ? "y" : "ies",
                      mct || src ? " for " : "", src ? inetFmt(src->ip, 1) : "",
                      mct ? inetFmt(mct->group, 2) : "", IfDp->Name);
    while (ql) {
        struct qlst *nql = qry ? NULL : ql->next;
        // Find all queriers for interface, group and type.
        if (ql->IfDp == IfDp && ((! mct || ql->mct == mct) && (!type || !((ql->type - type) & ~0x9)))) {
            if (src) {
                // Find and remove source from all queries.
                uint32_t i;
                for (i = 0; ql && i < ql->nsrcs && ql->src[i] != src; i++);
                if (ql && i < ql->nsrcs) {
                    LOG(LOG_NOTICE, 0, "Existing query for source %s in group %s on %s.",
                                        inetFmt(ql->src[i]->ip, 1), inetFmt(ql->mct->group, 2), ql->IfDp->Name);
                    ql->src[i] = ql->src[--ql->nsrcs];
                }
            } else if (BIT_TST(ql->type, 1)) {
                // Clear last member and query bits for group.
                BIT_CLR(ql->mct->vifB.lm, IfDp->index);
                BIT_CLR(ql->mct->vifB.qry, IfDp->index);
            } else
                // Clear last member and query bits for sources.
                for (uint32_t i = 0; i < ql->nsrcs; BIT_CLR(ql->src[i]->vifB.lm, IfDp->index),
                                                    BIT_CLR(ql->src[i]->vifB.qry, IfDp->index), i++);
            // Unlink from query list and free qlst.
            if (! src || (!ql->nsrcs && BIT_TST(ql->type, 2))) {
                if (! qry)
                    timer_clearTimer(ql->tid);
                if (ql->next)
                    ql->next->prev = ql->prev;
                if (ql->prev)
                    ql->prev->next = ql->next;
                if (qL == ql)
                    qL = ql->next;
                qC--;
                _free(ql, qry, ql->nsrcs ? QRYSZ(ql->nsrcs) : QLSZ);  // Alloced by addSrcToQlst() or startQuery()
            }
        }
        ql = nql;
    }
}
