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
*   mctable.h
*   Common multicast group structures and functions.
*/

#ifndef MCTABLE_H
#define MCTABLE_H

struct mvif {
    void               *prev;                     // Previous mct/src for vif
    void               *next;                     // Next mct/src for vif
    struct src         *prevmfc;                  // Previous mfc on upstream interface
    struct src         *nextmfc;                  // Next mfc on upstream interface
    struct dvif        *vp;                       // Downstream vif parameters
    uint8_t             s;                        // Filters set flag for vif
    uint8_t             d;                        // Denied vif
    uint8_t             j;                        // Upstream joined
};

struct nvif {
    vif_t               i;                        // Nr include mode vifs
    vif_t               e;                        // Nr exclude mode vifs
    vif_t               d;                        // Nr downstream vifs
    vif_t               u;                        // Nr upstream vifs
};

struct mct {
    // Keeps multicast group and source membership information.
    struct mct         *prev;                     // Previous group in table.
    struct mct         *next;                     // Next group in table.
    struct mvif        *uvif;                     // Active upstream vifs for group
    struct mvif        *dvif;                     // Downstream vifs for group
    struct timespec     stamp;                    // Time group was installed
    uint32_t            group;                    // The group to route
    bool                mode;                     // Group upstream filter mode
    uint32_t            nsrcs[2];                 // Nr of sources, 0 = include mode sources, 1 = origins
    struct src         *sources;                  // Downstream source list for group
    struct src        **firstsrc;                 // Per interface first source
    struct nvif         nvif;                     // Nr of vifs
};

struct src {
    // Keeps information on sources
    struct src         *prev;                     // Previous source in group.
    struct src         *next;                     // Next source in group
    struct mvif        *uvif;                     // Active upstream vifs for source
    struct mvif        *dvif;                     // Active downstream vifs for source
    uint8_t            *ttl;                      // Outgoing vifs ttl
    struct timespec     stamp;                    // Time src was installed
    uint32_t            ip;                       // Source IP adress
    struct mct         *mct;                      // Pointer to group
    struct IfDesc      *IfDp;                     // Incoming interface
    uint64_t            bytes;                    // Incoming data counter
    uint64_t            rate;                     // Bwcontrol counters
    struct nvif         nvif;                     // Nr of vifs
};

struct dvif {
    uint8_t             mode;                     // Filter mode for group / src
    uint8_t             lm;                       // Last member vif
    uint8_t             age;                      // Downstream vif age
    int8_t              v1age;                    // V1 mode flag for downstream vif
    int8_t              v2age;                    // V2 mode flag for downstream vif
    struct qry         *qry;                      // Active query timer id
    uint64_t           *dht;                      // Downstream hosts hash table
};

struct qry {
    struct IfDesc      *IfDp;                     // Interfce for Query
    struct mct         *mct;                      // Pointer to group being queried
    intptr_t            tid;                      // Timer ID
    uint8_t             type;                     // Query type (GSQ/GSSQ)
    uint8_t             code;                     // Query max response code (LMI)
    uint8_t             misc;                     // Query misc (RA/QRV)
    uint8_t             cnt;                      // Nr of queries sent
    uint32_t            group;                    // Group for query
    uint32_t            nsrcs[2];                 // Nr of sources in query, 0 = original, 1 = current
    struct src         *src[];                    // Array of pointers to sources
};

#define MCTSZ              ((1 << CONF->mcTables) * sizeof(void *))
#define MCESZ              (sizeof(struct mct))
#define SRCSZ              (sizeof(struct src))
#define MFCSZ              (sizeof(struct mfc))
#define VIFSZ              (sizeof(struct mvif))
#define DVIFSZ             (sizeof (struct dvif))
#define DHTSZ               IfDp->conf->dhtSz * sizeof(uint64_t)
#define TTLSZ              (src->nvif.d * sizeof(uint8_t))
#define VPSZ(x, y)         ((x ? downvifcount : upvifcount)  * sizeof(y))
#define PVPSZ(x, y, z)     (! x->nvif.y ? 0 : x->nvif.y * sizeof(z))
#define QSZ                (sizeof(struct qry))
#define QRYSZ(n)           (QSZ + ((((n) / 32) + 1) * 32 * sizeof(void *)))
#define IS_EX(x, y)        (x->dvif[y->dvifix].vp->mode)
#define IS_IN(x, y)        (!x->dvif[y->dvifix].vp->mode)
#define NHASH               (64)
#define HASH(if, ip)       (if->conf->dhtSz ? murmurhash3(ip) : NHASH)
#define MCTLST              0, 0,   0, 0,         mct, MCESZ
#define SRCLST              0, 0,   0, 0,         src, SRCSZ
#define DVIFLST(i)          2, 1,   0, i * VIFSZ, ifm, DVIFSZ
#define UVIFLST(i)          2, 0,   0, i * VIFSZ, ifm, 0
#define MFCLST(i)           2, dir, 2, i * VIFSZ, ifm, TTLSZ
#define SET_HASH(t, v, h)  {if (v->conf->dhtSz && h != 64)                                                           \
                            BIT_SET(t->dvif[v->dvifix].vp->dht[(h >> 7) % v->conf->dhtSz], h % 64);}
#define CLR_HASH(t, v, h)  {if (h != 64 && v->conf->dhtSz && t->dvif[v->dvifix].vp && t->dvif[v->dvifix].vp->dht)    \
                            BIT_CLR(t->dvif[v->dvifix].vp->dht[(h >> 7) % v->conf->dhtSz], h % 64);}
#define TST_HASH(t, v, h)  (h != 64 && v->conf->dhtSz && t->dvif[v->dvifix].vp && t->dvif[v->dvifix].vp->dht &&      \
                            BIT_TST(t->dvif[v->dvifix].vp->dht[(h >> 7) % v->conf->dhtSz], h % 64))
#define NO_HASH(t, v)      ({register uint64_t i = 0, n = v->conf->dhtSz;                                            \
                             if (n && t->dvif && t->dvif[v->dvifix].vp && t->dvif[v->dvifix].vp->dht)               \
                                 while(i < n && t->dvif[v->dvifix].vp->dht[i] == 0) i++;                            \
                             else n = 1; i >= n; })

// Prototypes
struct mct  *findGroup(struct IfDesc *IfDp, register uint32_t group, int dir, bool create);
struct mct  *delGroup(struct mct *mct, struct IfDesc *IfDp, int dir);
struct src  *delSrc(struct src *src, struct IfDesc *IfDp, int dir, int mode, bool leave, uint32_t srcHash);
void         joinBlockSrc(struct src *src, struct IfDesc *IfDp, bool join, int mode);
bool         checkFilters(struct IfDesc *IfDp, int dir, struct src *src, struct mct *mct);
struct qry  *addSrcToQlst(struct src *src, struct IfDesc *IfDp, struct qry *qry);
void         toInclude(struct mct *mfc, struct IfDesc *IfDp);
void         startQuery(struct IfDesc *IfDp, struct qry *qry);
void         groupSpecificQuery(struct qry *qry);
void         delQuery(struct qry *qry, struct mct *mct, struct src *src);

#endif // MCTABLE_H_INCLUDED
