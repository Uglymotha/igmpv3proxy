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
*   querier.c: Send and process group and group and source specific queries.
*/

#include "igmpv3proxy.h"
#include "mctable.h"

/**
*   Function to control the IGMP querier process on interfaces.
*/
void ctrlQuerier(int start, struct IfDesc *IfDp) {
    if (start != 0 && IfDp->conf->tbl != mrt_tbl)
        LOG(LOG_CRIT, -eABNRML, "Requested to %s querier on table %d interface %s.",
            !start ? "stop" : start == 1 ? "start" : "restart", IfDp->conf->tbl, IfDp->Name);
    if (start == 0 || start == 2) {
        // Remove all queries, timers and reset all IGMP status for interface.
        LOG(LOG_NOTICE, 0, "Stopping querier process on %s", IfDp->Name);
        if ( (SHUTDOWN && IS_DOWNSTREAM(IfDp->state)) ||
             (IS_DOWNSTREAM(IF_OLDSTATE(IfDp)) && !IS_DOWNSTREAM(IF_NEWSTATE(IfDp)))) {
            LOG(LOG_INFO, 0, "Leaving all routers and all igmp groups on %s", IfDp->Name);
            k_updateGroup(IfDp, false, allrouters_group, 1, (uint32_t)-1);
            k_updateGroup(IfDp, false, alligmp3_group, 1, (uint32_t)-1);
        }
        IfDp->querier.Timer = timerClear(IfDp->querier.Timer, false);
        IfDp->querier.ageTimer = timerClear(IfDp->querier.ageTimer, false);
        memset(&IfDp->querier, 0, sizeof(struct querier));
        IfDp->querier.ip = (uint32_t)-1;
        if (!IS_DOWNSTREAM(IF_NEWSTATE(IfDp)))
            IfDp->conf->qry.ver = 3;
    }
    if (start && IS_DOWNSTREAM(IF_NEWSTATE(IfDp))) {
        // Join all routers groups and start querier process on new downstream interfaces.
        LOG(LOG_NOTICE, 0, "Starting querier on %s", IfDp->Name);
        LOG(LOG_INFO, 0, "Joining all routers and all igmp groups on %s", IfDp->Name);
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
*   Adds a source to list of sources to query. Toggles appropriate flags and adds to qry.
*/
inline struct qry *addSrcToQlst(struct src *src, struct IfDesc *IfDp, struct qry *qry) {
    uint32_t       nsrcs = ! qry ? 0 : qry->nsrcs[1] ? qry->nsrcs[1] : qry->nsrcs[0], ix = IfDp->dvifix;
    LOG(LOG_DEBUG, 0, "%s:%s on %s (0x%08x)", inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name, qry);

    // Add source to query list, prevent duplicates.
    if (src->dvif[ix].vp->qry) {
        LOG(LOG_INFO, 0, "Already querying %s:%s on %s.", inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), IfDp->Name);
    } else if (!src->dvif[ix].vp->lm && (nsrcs == 0 || qry->src[qry->nsrcs[0] - 1]->ip != src->ip)) {
        if (IQUERY || (qry && (qry->type & (1 << 3)))) {
            // In case source is in running query return.
            // Add to source to the query list. Allocate memory per 32 sources.
            LOG(LOG_INFO, 0, "Adding source %s to query list for %s (%d).",
                inetFmt(src->ip, 0), inetFmt(src->mct->group, 0), nsrcs + 1);
            if (!(qry && qry->nsrcs[1]) && (nsrcs % 32) == 0)
                _recalloc(qry, qry, QRYSZ(nsrcs), nsrcs ? QRYSZ(nsrcs - 1) : 0);  // Freed by delQuery().
            if (nsrcs == 0)
                *qry = (struct qry){IfDp, src->mct, (intptr_t)NULL, (1 << 2), IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount,
                                    0, src->mct->group, {0}};
            src->dvif[ix].vp->qry = qry;
            src->dvif[ix].vp->lm = 1;
            src->dvif[ix].vp->age = qry->misc;
            qry->src[qry->nsrcs[0]++] = src;
        }
    }
    return qry;
}

/**
*   Process a group specific query received from other querier.
*/
inline void processGroupQuery(struct IfDesc *IfDp, struct igmpv3_query *query, uint32_t nsrcs, uint8_t ver) {
    struct mct *mct = findGroup(IfDp, query->igmp_group.s_addr, 1, false);

    // If no group found for query, not active or denied on interface return.
    if (! mct || ! mct->dvif[IfDp->dvifix].vp) {
        LOG(LOG_DEBUG, 0, "Query on %s for %s, but %s.", IfDp->Name, inetFmt(query->igmp_group.s_addr, 0),
            ! mct ? "not found" : "not active");
    } else if (nsrcs == 0 && !mct->dvif[IfDp->dvifix].vp->lm) {
        // Only start last member aging when group is allowed on interface.
        LOG(LOG_INFO, 0, "Group specific query for %s on %s.", inetFmt(mct->group, 0), IfDp->Name);
        startQuery(IfDp, &(struct qry){ IfDp, mct, (intptr_t)NULL, 0, (1 << 1), query->igmp_code,
                                         ver == 3 ? (query->igmp_misc & ~0x8) : 0, mct->group, {0} });
    } else if (nsrcs > 0) {
        // Sort array of sources in query.
        struct qry *qry = NULL;
        struct src *src  = mct->sources;
        nsrcs = sortArr((uint32_t *)query->igmp_src, nsrcs);
        _calloc(qry, 1, qry, QRYSZ(nsrcs));   // Freed by delQuery().
        *qry = (struct qry){IfDp, mct, (intptr_t)NULL, (1 << 2), IfDp->conf->qry.lmInterval, IfDp->conf->qry.lmCount,
                            0, mct->group, {0, nsrcs}};
        FOR_IF((uint32_t i = 0; src && i < nsrcs; src = src->next), src->ip >= query->igmp_src[i].s_addr) {
            if (src->ip == query->igmp_src[i].s_addr)
                qry = addSrcToQlst(src, IfDp, qry);
            i++;
        }
        LOG(LOG_INFO, 0, "Group group and source specific query for %s with %d sources on %s.",
            inetFmt(mct->group, 0), nsrcs, IfDp->Name);
        qry->type |= (1 << 3);  // Other querier.
        startQuery(IfDp, qry);
    }
}

/**
*   Start a query for last member aging on interface.
*/
inline void startQuery(struct IfDesc *IfDp, struct qry *qry) {
    // We may be called without qry, in case of gssq which had no valid sources to query.
    if (! qry || (BIT_TST(qry->type, 1) && qry->mct->dvif[IfDp->dvifix].vp->qry)) {
        if (qry)
            LOG(LOG_NOTICE, 0, "Already querying group %s on %s", inetFmt(qry->mct->group, 0), IfDp->Name);
        return;
    }
    if (qry->nsrcs[0] == 0) {
        struct qry *qry1;
        _calloc(qry1, 1, qry, QSZ);  // Freed by delQuery().
        memcpy(qry1, qry, sizeof(struct qry));
        qry = qry1;
        LOG(LOG_INFO, 0, "Querying group %s on %s", inetFmt(qry->mct->group, 0), IfDp->Name);
        qry->mct->dvif[IfDp->dvifix].vp->qry = qry;
        qry->mct->dvif[IfDp->dvifix].vp->lm = 1;
        qry->mct->dvif[IfDp->dvifix].vp->age = qry->misc;
    } else
        LOG(LOG_INFO, 0, "Querying %d sources for %s on %s.", qry->nsrcs[0], inetFmt(qry->mct->group, 0), IfDp->Name);
    // Allocate and assign new querier.
    qry->nsrcs[1] = qry->nsrcs[0];
    groupSpecificQuery(qry);
}

/**
*   Sends a group specific query and / or last member ages group and sources.
*   bit 0 - Router Supress flag
*   bit 1 - Group Specific Query
*   bit 2 - Group and Source Specific query
*   bit 3 - Other Querier
*/
void groupSpecificQuery(struct qry *qry) {
    struct igmpv3_query *query = NULL, *query1 = NULL, *query2 = NULL;
    struct IfDesc       *IfDp = qry->IfDp;
    uint32_t             i = 0, nsrcs = qry->nsrcs[1], group = qry->group, ix = IfDp->dvifix,
                         size = sizeof(struct igmpv3_query) + nsrcs * sizeof(struct in_addr);
    LOG(LOG_DEBUG, 0, "%s:%s #%d (%d:%d:%d)", IfDp->Name, inetFmt(group, 0), nsrcs, qry->type, qry->misc, qry->cnt);

    // Do aging upon reentry.
    if (++qry->cnt > 1) {
        if (BIT_TST(qry->type, 1)) {
            // Age group in case of GSQ.
            if (!qry->mct->dvif[qry->IfDp->dvifix].vp->lm) {
                LOG(LOG_INFO, 0, "%s no longer in last member state on %s.", inetFmt(group, 0), IfDp->Name);
                BIT_SET(qry->type, 0);  // Suppress router processing flag for next query.
                if (BIT_TST(qry->type, 3))
                    // If aging for other querier, we're done.
                    qry->cnt = qry->misc + 1;
            } else if (--qry->mct->dvif[ix].vp->age == 0)
                qry->cnt = qry->misc + 1;  // Make sure we're done.
        } else if (BIT_TST(qry->type, 2)) {
            // Age sources in case of GSSQ. Create two queries (1 - sources still last member 2 - active source).
            _malloc(query1, var, size);  // Freed by self.
            _malloc(query2, var, size);  // Freed by self.
            *query1 = (struct igmpv3_query){ qry->type      , qry->code, 0, {group}, qry->misc, 0, 0 };
            *query2 = (struct igmpv3_query){ qry->type | 0x1, qry->code, 0, {group}, qry->misc, 0, 0 };
            while (i < qry->nsrcs[1]) {
                if (!qry->src[i]->dvif[ix].vp->lm && qry->src[i]->dvif[ix].vp) {
                    // Source no longer in last member state.
                    LOG(LOG_INFO, 0, "Source %s for group %s no longer in last member state on %s.",
                        inetFmt(qry->src[i]->ip, 0), inetFmt(group, 0), IfDp->Name);
                    query2->igmp_src[query2->igmp_nsrcs++].s_addr = qry->src[i++]->ip;
                } else if (qry->src[i]->dvif[ix].vp->age > 0 && --qry->src[i]->dvif[ix].vp->age == 0) {
                    // Aged source in include mode should be removed.
                    // In exclude mode sources should be kept and MFC updated, as traffic should no longer be forwarded.
                    qry->src[i]->dvif[ix].vp->qry = NULL;
                    qry->src[i]->dvif[ix].vp->lm = 0;
                    LOG(LOG_INFO, 0, strFmt(IS_IN(qry->mct, IfDp), "Removing inactive source %s from group %s on %s.",
                                            "Source %s from group %s on %s expired.", inetFmt(qry->src[i]->ip, 0),
                                            inetFmt(group, 0), IfDp->Name));
                    delSrc(qry->src[i], IfDp, 1, IS_EX(qry->mct, IfDp) ? 2 : 0, IS_IN(qry->mct, IfDp), NHASH);
                    qry->src[i] = qry->src[--qry->nsrcs[1]];
                } else if (qry->src[i]->dvif[ix].vp)
                    // Source still in last member state, add to  query.
                    query1->igmp_src[query1->igmp_nsrcs++].s_addr = qry->src[i++]->ip;
            }
            if (BIT_TST(qry->type, 3) && qry->nsrcs[1] == 0)
                // If aging for other querier and no sources left to age, we're done.
                qry->cnt = qry->misc + 1;
        }
    }

    // Send queries if not aging for other querier. Use qry in case of group query, or first group and source query.
    if (!BIT_TST(qry->type, 3) && (   (qry->cnt <= qry->misc && BIT_TST(qry->type, 1))
                                    || (qry->cnt == 1        && BIT_TST(qry->type, 2)))) {
        _malloc(query, var, sizeof(struct igmpv3_query) + qry->nsrcs[1] * sizeof(struct in_addr));  // Freed by Self
        *query = (struct igmpv3_query){ qry->type, qry->code, 0, {group}, qry->misc, 0, qry->nsrcs[1] };
        IF_FOR(BIT_TST(qry->type, 2), (uint32_t i = 0; i < qry->nsrcs[1]; query->igmp_src[i].s_addr = qry->src[i]->ip, i++));
        sendIgmp(IfDp, query);
        _free(query, var, sizeof(struct igmpv3_query) + qry->nsrcs[1] * sizeof(struct in_addr));  // Alloced by Self
    } else if (!BIT_TST(qry->type, 3) && qry->cnt <= qry->misc && BIT_TST(qry->type, 2)) {
        if (query1 && query1->igmp_nsrcs)
            sendIgmp(IfDp, query1);
        if (query2 && query2->igmp_nsrcs)
            sendIgmp(IfDp, query2);
    }
    if (qry->cnt <= qry->misc && (   (BIT_TST(qry->type, 1) && qry->mct->dvif[ix].vp->lm)
                                    || (BIT_TST(qry->type, 2) && qry->nsrcs[1] > 0))) {
        // Set timer for next round if there is still aging to do.
        uint32_t timeout = (BIT_TST(qry->type, 3)      ? qry->code
                         :  IfDp->querier.ver == 3      ? getIgmpExp(IfDp->conf->qry.lmInterval, 0)
                         :  IfDp->conf->qry.lmInterval) + 1;
        qry->tid = timerSet(timeout, strFmt(1, "GSQ (%s): %s/%u", "", IfDp->Name, inetFmt(group, 0), qry->nsrcs[1]),
                             groupSpecificQuery, qry);
    } else {
        if (BIT_TST(qry->type, 1)) {
            qry->mct->dvif[qry->IfDp->dvifix].vp->lm = 0;
            qry->mct->dvif[ix].vp->qry = NULL;
        }
        if (qry->cnt >= qry->misc) {
            if (BIT_TST(qry->type, 2) && !qry->mct->dvif[ix].vp->mode && !qry->mct->nsrcs[0]) {
                // Group in include mode has no more sources, remove.
                LOG(LOG_DEBUG, 0, "Removing group %s on %s.", inetFmt(group, 0), IfDp->Name);
                delGroup(qry->mct, IfDp, 1);
            } else if (BIT_TST(qry->type, 1) && qry->mct->dvif[ix].vp->age == 0 && qry->mct->dvif[ix].vp->lm
                                             && qry->mct->dvif[ix].vp->v1age == -1 && qry->mct->dvif[ix].vp->v1age == -1) {
                // Group in exclude mode has aged, switch to include.
                LOG(LOG_DEBUG, 0, "Switching group %s to include on %s.", inetFmt(group, 0),
                    IfDp->Name);
                toInclude(qry->mct, IfDp);
            }
        }
        LOG(LOG_INFO, 0, "Done querying %s/%d on %s.", inetFmt(group, 0), nsrcs, IfDp->Name);
        qry->tid = (intptr_t)NULL;
        delQuery(qry, NULL, NULL);
    }

    if (query1)
        _free(query1, var, size);  // Alloced by self.
    if (query2)
        _free(query2, var, size);  // Alloced by self.
    logRouteTable("GSQ", 1, -1, group, (uint32_t)-1, IfDp);
}

/**
*   Removes all active queriers specified by parameters.
*     IfDp / ! mct    - Removes all queries on specified interface.
*     qry             - Removes specific query.
*     mct / mct & src - Removes all queries for (source within) group from interface.
*   Do NOT use qry->mct here, it may have already been deleted by delGroup().
*/
void delQuery(struct qry *qry, struct mct *mct, struct src *src) {
    if (src) {
        uint32_t i;
        for (i = 0; i < qry->nsrcs[1] && qry->src[i] != src; i++);
        if (i < qry->nsrcs[1]) {
            LOG(LOG_INFO, 0, "Removing source %s from query for group %s on %s.",
                inetFmt(qry->src[i]->ip, 0), inetFmt(qry->group, 0), qry->IfDp->Name);
            qry->src[i] = qry->src[--qry->nsrcs[1]];
        }
        src->dvif[qry->IfDp->dvifix].vp->lm = 0;
        src->dvif[qry->IfDp->dvifix].vp->qry = NULL;
    } else if (mct) {
        qry->mct->dvif[qry->IfDp->dvifix].vp->lm = 0;
        qry->mct->dvif[qry->IfDp->dvifix].vp->qry = NULL;
    }
    if (! src || !qry->nsrcs[1]) {
        LOG(LOG_INFO, 0, "Removing query for group %s on %s.", inetFmt(qry->group, 0), qry->IfDp->Name);
        if (qry->tid)
            timerClear(qry->tid, false);
        // Alloced by addSrcToQlst(), processGroupQuery() or startQuery()
        _free(qry, qry, qry->nsrcs[0] ? QRYSZ(qry->nsrcs[0]) : QSZ);
    }
}
