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
*   ifvc.c - Maintains list of system interfaces.
*/

#include "igmpv3proxy.h"

// Linked list of igmpv3proxy system interfaces and ulticast vifs.
static struct   IfDesc   *IfDescL = NULL, *vifL = NULL;
int             vifcount, upvifcount, downvifcount;
extern volatile uint64_t  sighandled;  // From igmpv3proxy.c signal handler.

static void configureVifs(void);

/**
*   Frees the IfDesc table and cleans up on interface removal.
*/
void freeIfDescL(void) {
    struct IfDesc *IfDp = IfDescL, *fIfDp;
    while (IfDp) {
        if (SHUTDOWN || IfDp->state & 0x80 || (IfDp->next && IfDp->next->state & 0x80)) {
            // Remove interface marked for deletion.
            LOG(LOG_WARNING, 0, "Interface %s was removed.", SHUTDOWN || IfDp->state & 0x80 ? IfDp->Name : IfDp->next->Name);
            fIfDp = SHUTDOWN || (IfDp->state & 0x80) ? IfDescL : IfDp->next;
            if (SHUTDOWN || IfDp->state & 0x80)
                IfDescL = IfDp = IfDp->next;
            else
                IfDp->next = IfDp->next->next;
            _free(fIfDp, ifd, IFSZ);
        } else
            IfDp = IfDp->next;
    }

    LOG(LOG_DEBUG, 0, "Interfaces List cleared.");
}

/**
*   Returns pointer to the list of system interfaces.
*/
inline struct IfDesc **getIfL(bool vifl) {
    return vifl ? &vifL : &IfDescL;
}

/**
*   Returns pointer to interface based on given name, sys- or vif-index or NULL if not found.
*   mode 0 = search by vifindex, 1 = search by sysindex, 2= search by name.
*   if bit 3 of mode is set search the active vifs, all system interfaces otherwise.
*/
inline struct IfDesc *getIf(unsigned int ix, char name[IF_NAMESIZE], int mode) {
    struct IfDesc *IfDp = mode & SRCHVIFL ? vifL : IfDescL;
    while (IfDp && !((mode & 3) == 2 ? strcmp(name, IfDp->Name) == 0 : ((mode & 3) == 1 ? IfDp->sysidx : IfDp->index) == ix))
         IfDp = mode & SRCHVIFL ? IfDp->nextvif : IfDp->next;
    return IfDp;
}

/**
*   Rebuilds the list of interfaces.
*/
void rebuildIfVc(intptr_t *tid) {
    // Build new IfDEsc table on SIGHUP, SIGUSR2 or timed rebuild.
    if (tid)
        sigstatus |= GOT_SIGUSR2;
    if (! IfDescL || IFREBUILD || SHUP)
        buildIfVc();
    configureVifs();
    freeIfDescL();

    // Restart timer when doing timed reload.
    if (!SHUTDOWN && CONF->rescanVif > 1 && tid)
        *tid = timerSet(CONF->rescanVif * 10, "Rebuild Interfaces", rebuildIfVc, tid);
    if ((IFREBUILD || STARTUP || RESTART) && CONF->logLevel == LOG_DEBUG) {
        sigstatus &= ~GOT_SIGUSR2;
        LOG(LOG_DEBUG, 0, "Memory Stats: %lldb total, %lldb interfaces, %lldb config, %lldb filters.",
            memuse.ifd + memuse.vif + memuse.fil, memuse.ifd, memuse.vif, memuse.fil);
        LOG(LOG_DEBUG, 0, "              %lld allocs total, %lld interfaces, %lld config, %lld filters.",
            memalloc.ifd + memalloc.vif + memalloc.fil, memalloc.ifd, memalloc.vif, memalloc.fil);
        LOG(LOG_DEBUG, 0, "              %lld  frees total, %lld interfaces, %lld config, %lld filters.",
            memfree.ifd + memfree.vif + memfree.fil, memfree.ifd, memfree.vif, memfree.fil);
    }
}

/**
*   Builds up a list with all usable interfaces of the machine.
*   Sets bit 8 of IfDp->state when new interface is detected (DEFAULT_IFDESC).
*   Sets bit 7 when existing interface is seen.
*   These bits are used by configureVifs() below.
*/
void buildIfVc(void) {
    struct ifreq    ifr;
    struct ifaddrs *ifAddrs, *fifAddrs;
    struct IfDesc  *IfDp;

    // Get the system interface list.
    if ((getifaddrs(&fifAddrs)) == -1)
        LOG(STARTUP ? LOG_CRIT : LOG_ERR, eNOINIT, "Cannot enumerate interfaces.");
    else for (ifAddrs = fifAddrs; ifAddrs; ifAddrs = ifAddrs->ifa_next) {
        if (   ifAddrs->ifa_flags & IFF_LOOPBACK   || ifAddrs->ifa_addr->sa_family != AF_INET
            || (!((ifAddrs->ifa_flags & IFF_UP)    && (ifAddrs->ifa_flags & IFF_RUNNING)))
#ifdef IFF_CANTCONFIG
            || (!(ifAddrs->ifa_flags & IFF_MULTICAST) && (ifAddrs->ifa_flags & IFF_CANTCONFIG))
#endif
            || ((IfDp = getIf(0, ifAddrs->ifa_name, FINDNAME)) && (IfDp->state & 0xC0))) {
            // Only build Ifdesc for up & running IP interfaces (no aliases), and can be configured for multicast if not enabled.
            continue;
        } else if (! IfDp) {
            // New interface, allocate and initialize.
            _malloc(IfDp, ifd, IFSZ);  // Freed by freeIfDescL()
            *IfDp = DEFAULT_IFDESC;
            IfDescL = IfDp;
            memcpy(IfDp->Name, ifAddrs->ifa_name, strlen(ifAddrs->ifa_name));
            LOG(LOG_NOTICE, 0, "Found new interface %s.", IfDp->Name);
        } else {
            // Rebuild Interface. For disappeared interface state is not reset here and configureVifs() can mark it for deletion.
            IfDp->state |= 0x40;
            LOG(LOG_INFO, 0, "Found existing interface %s.", IfDp->Name);
        }
        // Set the interface flags, index and IP.
        IfDp->sysidx  = if_nametoindex(ifAddrs->ifa_name);
        IfDp->Flags   = ifAddrs->ifa_flags;
        IfDp->ip.ip   = uint32_t_from_sockaddr(ifAddrs->ifa_addr);
        IfDp->ip.mask = uint32_t_from_sockaddr(ifAddrs->ifa_netmask);
        // Get interface mtu.
        memset(&ifr, 0, sizeof(struct ifreq));
        memcpy(ifr.ifr_name, ifAddrs->ifa_name, strlen(ifAddrs->ifa_name));
        if (ioctl(MROUTERFD, SIOCGIFMTU, &ifr) < 0) {
            LOG(LOG_ERR, 1, "Failed to get MTU for %s, disabling.", IfDp->Name);
            IfDp->mtu = 0;
        } else
            IfDp->mtu = ifr.ifr_mtu;
        // Enable multicast if necessary.
        if (!(IfDp->Flags & IFF_MULTICAST)) {
            ifr.ifr_flags = IfDp->Flags | IFF_MULTICAST;
            if (ioctl(MROUTERFD, SIOCSIFFLAGS, &ifr) < 0)
                LOG(LOG_ERR, 1, "Failed to enable multicast on %s, disabling.", IfDp->Name);
            else {
                IfDp->Flags = ifr.ifr_flags;
                LOG(LOG_NOTICE, 0, "Multicast enabled on %s.", IfDp->Name);
            }
        }
        LOG(LOG_INFO, 0, "Interface %s, IP: %s, Flags: 0x%04x, MTU: %d", IfDp->Name,
            inetFmt(IfDp->ip.ip, IfDp->ip.mask), IfDp->Flags, IfDp->mtu);
    }
    freeifaddrs(fifAddrs);   // Alloced by getiffaddrs()
}

/**
*   Configures all multicast vifs and links to interface configuration. This function is responsible for:
*   - All active interfaces have a matching configuration. Either explicit through config file or implicit defaults.
*   - Establish correct old and new state of interfaces.
*   - Control querier process and do route maintenance when interfaces transitions.
*   - Add and remove vifs from the kernel if needed and start/stop querier.
*   - IfDp->state represents the old and new state of interfaces as below. bits 7 & 8 are set by buildIfVc().
*      8        7         6       5       4       3       2       1
*      new      existing  monitor unused  olddown oldup   down    up
*/
void configureVifs(void) {
    struct IfDesc     *IfDp = NULL, *If;
    struct vifConfig  *vifConf = NULL;
    struct filters    *fil, *ofil;
    bool               quickLeave = false;
    LOG(LOG_INFO, 0, "Configuring MC vifs.");

    uVifs = vifcount = upvifcount = downvifcount = 0;
    GETIFL(IfDp) {
        // When config is reloaded, find and link matching config to interfaces.
        if (STARTUP || CONFRELOAD || SHUP || ! IfDp->conf) {
            for (vifConf = *VIFCONF; vifConf && strcmp(IfDp->Name, vifConf->name); vifConf = vifConf->next);
            if (vifConf) {
                LOG(LOG_NOTICE, 0, "Found config for %s", IfDp->Name);
            } else {
                // Interface has no matching config, create default config.
                LOG(LOG_NOTICE, 0, "Creating default config for %s interface %s.",
                    IS_DISABLED(CONF->defaultInterfaceState)     ? "disabled"     :
                    IS_UPDOWNSTREAM(CONF->defaultInterfaceState) ? "updownstream" :
                    IS_UPSTREAM(CONF->defaultInterfaceState)     ? "upstream"     : "downstream", IfDp->Name);
                _calloc(vifConf, 1, vif, VIFSZ);  // Freed by freeConfig()
                *vifConf = DEFAULT_VIFCONF;
                *VIFCONF = vifConf;
                strcpy(vifConf->name, IfDp->Name);
                vifConf->filters = CONF->defaultFilters;
            }
            IfDp->oconf = IfDp->conf;
            IfDp->conf = vifConf;
            if (mrt_tbl < 0 && (IfDp->state & 0x80) && (IfDp->state = 0x20))
                // We will sig proxy on seeing new interfaces and set state to monitor disabled.
                sighandled |= GOT_SIGPROXY;
        }
        if (mrt_tbl < 0)
            // Monitor process only needs config.
            continue;
        // Evaluate to old and new state of interface.
        if ((CONFRELOAD || (IfDp->state & 0x40)) && IfDp->conf->tbl == mrt_tbl) {
            // Existing interface, oldstate is curre nt state, newstate is configured state.= ((IfDp->state & 0x3) << 2)
            IfDp->state = ((IfDp->state & 0x3) << 2) | (IfDp->mtu && (IfDp->Flags & IFF_MULTICAST) ? IfDp->conf->state : 0);
        } else if (!(IfDp->state & 0xC0) || SHUTDOWN) {
            // Removed interface. Old state is current, new is disabled, flagged for removal.
            IfDp->state = ((IfDp->state & 0x03) << 2) | 0x80;
        } else if ((IfDp->state & 0x80) && IfDp->conf->tbl != mrt_tbl) {
            LOG(LOG_INFO, 0, "Not enabling table %d interface %s", IfDp->conf->tbl, IfDp->Name);
            IfDp->state &= ~0xC3;  // Keep old state, new state disabled.
        } else if ((IfDp->state & 0x80)) {
            // New interface, old state is disabled new state is configured state.
            IfDp->state = IfDp->mtu && (IfDp->Flags & IFF_MULTICAST) ? IfDp->conf->state : IF_STATE_DISABLED;
        } else
            IfDp->state &= ~0x3;  // Keep old state, new state disabled.
        register uint8_t oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);
        quickLeave |= !IS_DISABLED(IfDp->state) && IfDp->conf->quickLeave;

        // Set configured querier ip to interface address if not configured
        // and set version to 3 for disabled/upstream only interface.
        if (IfDp->conf->qry.ip == (uint32_t)-1)
            IfDp->conf->qry.ip = IfDp->ip.ip;
        if (!IS_DOWNSTREAM(IfDp->state))
            IfDp->conf->qry.ver = 3;
        if (IfDp->conf->qry.ver == 1)
            IfDp->conf->qry.interval = IfDp->conf->qry.responseInterval = 10;
        // Check if filters have changed so that ACLs will be reevaluated.
        if (!IfDp->filCh && (CONFRELOAD || SHUP)) {
            for (fil = vifConf->filters, ofil = IfDp->oconf ? IfDp->oconf->filters : NULL;
                 fil && ofil && !memcmp(fil, ofil, sizeof(struct filters) - sizeof(void *));
                 fil = fil->next, ofil = ofil->next);
            if (fil || ofil) {
                LOG(LOG_INFO, 0, "Filters changed for %s.", IfDp->Name);
                IfDp->filCh = true;
            }
        }
        // Check if querier process needs to be restarted, because election was turned of and other querier present.
        if (!IfDp->conf->qry.election && IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate)
                                      && IfDp->querier.ip != IfDp->conf->qry.ip)
            ctrlQuerier(2, IfDp);
        // Reinitialize vif if ratelimit changed.
        if ((CONFRELOAD || SHUP) && IfDp->oconf->ratelimit != IfDp->conf->ratelimit)
            k_addVIF(IfDp);
        // Check if vifs need to be added or removed and (re)init the group table.
        if (!IS_DISABLED(newstate) && (IfDp->index >= 0 || k_addVIF(IfDp))) {
            vifcount++;
            if (IS_DOWNSTREAM(newstate))
                downvifcount++;
            if (IS_UPSTREAM(newstate)) {
                upvifcount++;
                BIT_SET(uVifs, IfDp->index);
                IF_GETVIFL_IF(!STARTUP && !IS_UPSTREAM(oldstate), If, If != IfDp && IS_DOWNSTREAM(If->state)) {
                    LOG(LOG_NOTICE, 0, "New upstream interface %s. Sending query on interface %s.", IfDp->Name, If->Name);
                    sendIgmp(If, NULL);
                }
            } else
                BIT_CLR(uVifs, IfDp->index);
            if (IS_DISABLED(oldstate) || (!STARTUP && oldstate != newstate))
                ctrlQuerier(IS_DISABLED(oldstate) ? 1 : 2, IfDp);
        }
        if ((newstate != oldstate || IfDp->filCh) && IfDp->conf->tbl == mrt_tbl)
            clearGroups(IfDp);
        IfDp->filCh = false;
        if (IS_DISABLED(newstate) && IfDp->index >= 0) {
            IfDp->bwTimer = timerClear(IfDp->bwTimer, false);
            if (!IS_DISABLED(oldstate))
                ctrlQuerier(0, IfDp);
            BIT_CLR(uVifs, IfDp->index);
            k_delVIF(IfDp);
            if (vifcount)
                vifcount--;
            if (IS_DOWNSTREAM(oldstate) && downvifcount)
                downvifcount--;
            if (IS_UPSTREAM(oldstate)   && upvifcount)
                upvifcount--;
        }
        IfDp->oconf = NULL;
    }
    if (mrt_tbl < 0)
        return;

    // Set hashtable size to 0 when quickleave is not enabled on any interface.
    if (!quickLeave && !RESTART) {
        LOG(LOG_NOTICE, 0, "Disabling quickleave, no interfaces have it enabled.");
        CONF->quickLeave = false;
        CONF->dHostsHTSize = 0;
    }
    // Check if quickleave was enabled or disabled due to config change.
    if ((CONFRELOAD || SHUP) && OLDCONF->dHostsHTSize != CONF->dHostsHTSize) {
        LOG(LOG_WARNING, 0, "Downstream host hashtable size changed from %d to %d, restarting.",
            OLDCONF->dHostsHTSize, CONF->dHostsHTSize);
        sighandled |= GOT_SIGURG | GOT_SIGTERM;
    }
    // All vifs created / updated, check if there is an upstream and at least one downstream.
    if (!SHUTDOWN && (vifcount < 2 || upvifcount == 0 || downvifcount == 0))
        LOG(STARTUP || RESTART ? LOG_CRIT : LOG_ERR, -eNOINIT,
            "There must be at least 2 interfaces, 1 upstream and 1 dowstream.");
}

/**
*   Outputs interface statistics to socket specified in arguments.
*/
void getIfStats(struct IfDesc *IfDp, int h, int fd) {
    char          *buf;
    int            i = 1;
    struct totals {
        uint64_t   bytes;
        uint64_t   rate;
        uint64_t   ratelimit;
    }              total = { 0, 0, 0 };
    if (! IfDp && h) {
        buf = strFmt(h, "Current Interface Table:\n_____|______Name_____|%s|Ver|_______IP______|___State____|Checksum"
                           "|Quickleave|____Querier____|_______Data______|______Rate______|___Ratelimit___\n", "",
                     mrt_tbl < 0 ? "Tbl" : "Vif");
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
    if (IfDp) {
        buf = strFmt(h, "Details for Interface: %s\n    IGMP Queries Received: %lu\n    IGMP Queries Sent:     %lu\n",
                        "%s%lu,%lu\n", h ? IfDp->Name : "", IfDp->stats.rqCnt, IfDp->stats.sqCnt);
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
        return;
    } else GETIFL_IF(IfDp, mrt_tbl < 0 || IfDp->conf->tbl == mrt_tbl) {
        if (h)
            total = (struct totals){ total.bytes + IfDp->stats.iBytes + IfDp->stats.oBytes,
                                     total.rate + IfDp->stats.iRate + IfDp->stats.oRate,
                                     total.ratelimit + IfDp->conf->ratelimit };
        buf = strFmt(h, "%4d |%15s|%3s| v%1d|%15s|%12s|%8s|%10s|%15s|%14lld B | %10lld B/s | %10lld B/s\n",
                         "%d %s %d %d %s %s %s %s %s %lld %lld %lld\n", i++, IfDp->Name,
                     mrt_tbl < 0 ? strFmt(1, "%2d", "", IfDp->conf->tbl) :
                                   strFmt(IfDp->index < 0, "-", "%2d", IfDp->index),
                     IfDp->querier.ver, inetFmt(IfDp->ip.ip, 0),
                         IS_DISABLED(mrt_tbl < 0 ? IfDp->conf->state : IfDp->state) ? "Disabled" :
                     IS_UPDOWNSTREAM(mrt_tbl < 0 ? IfDp->conf->state : IfDp->state) ? "UpDownstream" :
                       IS_DOWNSTREAM(mrt_tbl < 0 ? IfDp->conf->state : IfDp->state) ? "Downstream" : "Upstream",
                     IfDp->conf->cksumVerify ? "Enabled" : "Disabled", IfDp->conf->quickLeave ? "Enabled" : "Disabled",
                     inetFmt(IfDp->querier.ip, 0), IfDp->stats.iBytes + IfDp->stats.oBytes,
                     IfDp->stats.iRate + IfDp->stats.oRate,
                     !IS_DISABLED(IfDp->state) ? IfDp->conf->ratelimit : 0);
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
    buf = strFmt(h, "Total|---------------|---|---|---------------|------------|--------|----------|---------------|%14ld B "
                        "| %10ld B/s | %10ld B/s\n", "", total.bytes, total.rate, total.ratelimit);
    send(fd, buf, strlen(buf), MSG_DONTWAIT);
}

/**
*   Outputs configured filters to socket specified in arguments.
*/
void getIfFilters(struct IfDesc *IfDp2, int h, int fd) {
    char          *buf;
    struct IfDesc *IfDp = NULL;
    int            i = 1;

    if (h) {
        buf = strFmt(h, "Current Active Filters%s%s:\n_______Int______|_nr_|__________SRC________|__________DST________|___Dir__"
                        "|___Action___|______Rate_____\n", "", IfDp ? " for " : "", IfDp2 ? IfDp2->Name : "");
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    }
    GETIFL_IF(IfDp, mrt_tbl < 0 || IfDp->conf->tbl == mrt_tbl) {
        struct filters *filter;
        int             i = 1;
        char           *s = NULL;
        if ((mrt_tbl >= 0 && IfDp->conf->tbl != mrt_tbl) || (IfDp2 && IfDp != IfDp2))
            continue;
        for (filter = IfDp->conf->filters; filter; filter = filter->next, i++) {
            if (filter->action > ALLOW)
                s = strFmt(h, "%10lld B/s", "%lld", filter->action);
            buf = strFmt(h, "%15s |%4d| %19s | %19s | %6s | %10s | %s\n", "%s %d %s %s %s %s %s\n", !h || i == 1 ? IfDp->Name : "",
                         i, inetFmt(filter->src.ip, filter->src.mask), inetFmt(filter->dst.ip, filter->dst.mask),
                         filter->dir == 1 ? "up" : filter->dir == 2 ? "down" : "both",
                         filter->action == ALLOW ? "Allow" : filter->action == BLOCK ? "Block" : "Ratelimit", s ? s : "");
            send(fd, buf, strlen(buf), MSG_DONTWAIT);
        }
    }

    if (h)
        send(fd, "-------------------------------------------------------------------------------------------------------\n",
             125 , MSG_DONTWAIT);
}
