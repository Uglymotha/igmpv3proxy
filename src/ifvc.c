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
*   ifvc.c - Maintains list of system interfaces.
*/

#include "igmpv3proxy.h"

// Linked list of igmpv3proxy interfaces.
static struct IfDesc *IfDescL = NULL;

/**
*   Frees the IfDesc table and cleans up on interface removal.
*/
static void freeIfDescL() {
    struct IfDesc *IfDp = IfDescL, *fIfDp;
    while (IfDp) {
        if ((IfDp->state & 0x80) || (IfDp->next && (IfDp->next->state & 0x80))) {
            // Remove interface marked for deletion.
            if (!SHUTDOWN)
                LOG(LOG_WARNING, 0, "Interface %s was removed.", (IfDp->state & 0x80) ? IfDp->Name : IfDp->next->Name);
            fIfDp = (IfDp->state & 0x80) ? IfDescL : IfDp->next;
            if (IfDp->state & 0x80L)
                IfDescL = IfDp = IfDp->next;
            else
                IfDp->next = IfDp->next->next;
            free(fIfDp);
        } else
            IfDp = IfDp->next;
    }

    LOG(LOG_DEBUG, 0, "freeIfDescL: Interfaces List cleared.");
}

/**
*   Rebuilds the list of interfaces.
*/
void rebuildIfVc(uint64_t *tid) {
    // Check and set sigstatus to what we are actually doing right now.
    sigstatus = NOSIG ? GOT_IFREB : sigstatus;

    // Build new IfDEsc table on SIGHUP, SIGUSR2 or timed rebuild.
    if (!CONFRELOAD && !SHUTDOWN)
        buildIfVc();

    // Call configureVifs to link the new IfDesc table.
    LOG(LOG_INFO,0,"rebuildIfVc: Configuring MC vifs.");
    configureVifs();

    // Free removed interfaces.
    freeIfDescL();

    // Restart timer when doing timed reload.
    if (tid && sigstatus == GOT_IFREB && CONFIG->rescanVif)
        *tid = timer_setTimer(TDELAY(CONFIG->rescanVif * 10), "Rebuild Interfaces", rebuildIfVc, tid);

    sigstatus = IFREBUILD ? 0 : sigstatus;
}

/**
*   Builds up a list with all usable interfaces of the machine.
*/
void buildIfVc(void) {
    struct ifreq ifr;
    struct ifaddrs *IfAddrsP, *tmpIfAddrsP;
    struct IfDesc *IfDp;

    // Get the system interface list.
    if ((getifaddrs(&IfAddrsP)) == -1)
        LOG((STARTUP ? LOG_ERR : LOG_WARNING), errno, "Cannot enumerate interfaces.");
    else for (tmpIfAddrsP = IfAddrsP; tmpIfAddrsP; tmpIfAddrsP = tmpIfAddrsP->ifa_next) {
        unsigned int ix = if_nametoindex(tmpIfAddrsP->ifa_name);
        if (tmpIfAddrsP->ifa_flags & IFF_LOOPBACK || tmpIfAddrsP->ifa_addr->sa_family != AF_INET
            || (!((tmpIfAddrsP->ifa_flags & IFF_UP) && (tmpIfAddrsP->ifa_flags & IFF_RUNNING)))
            || s_addr_from_sockaddr(tmpIfAddrsP->ifa_addr) == 0
#ifdef IFF_CANTCONFIG
            || (!(tmpIfAddrsP->ifa_flags & IFF_MULTICAST) && (tmpIfAddrsP->ifa_flags & IFF_CANTCONFIG))
#endif
            || ((IfDp = getIf(ix, 1)) && ! IfDp->conf))
            // Only build Ifdesc for up & running IP interfaces (no aliases), and can be configured for multicast if not enabled.
            continue;

        uint32_t       addr = s_addr_from_sockaddr(tmpIfAddrsP->ifa_addr), mask = s_addr_from_sockaddr(tmpIfAddrsP->ifa_netmask);
        if (! IfDp) {
            // New interface, allocate and initialize.
            if (! (IfDp  = malloc(sizeof(struct IfDesc))))
                LOG(LOG_ERR, errno, "builfIfVc: Out of memory.");  // Freed by freeIfDescL()
            *IfDp = DEFAULT_IFDESC;
            IfDescL = IfDp;
            memcpy(IfDp->Name, tmpIfAddrsP->ifa_name, strlen(tmpIfAddrsP->ifa_name));
        } else
            // Rebuild Interface. For disappeared interface state is not reset here and configureVifs() can mark it for deletion.;
            IfDp->state |= 0x40;

        // Set the interface flags, index and IP.
        IfDp->sysidx       = ix;
        IfDp->Flags        = tmpIfAddrsP->ifa_flags;
        IfDp->InAdr.s_addr = addr;

        // Get interface mtu.
        memset(&ifr, 0, sizeof(struct ifreq));
        memcpy(ifr.ifr_name, tmpIfAddrsP->ifa_name, strlen(tmpIfAddrsP->ifa_name));
        if (ioctl(MROUTERFD, SIOCGIFMTU, &ifr) < 0) {
            LOG(LOG_WARNING, errno, "Failed to get MTU for %s, disabling.", IfDp->Name);
            IfDp->mtu = 0;
        } else
            IfDp->mtu = ifr.ifr_mtu;

        // Enable multicast if necessary.
        if (! (IfDp->Flags & IFF_MULTICAST)) {
            ifr.ifr_flags = IfDp->Flags | IFF_MULTICAST;
            if (ioctl(MROUTERFD, SIOCSIFFLAGS, &ifr) < 0)
                LOG(LOG_WARNING, errno, "Failed to enable multicast on %s, disabling.", IfDp->Name);
            else {
                IfDp->Flags = ifr.ifr_flags;
                LOG(LOG_NOTICE, 0, "Multicast enabled on %s.", IfDp->Name);
            }
        }

        // Log the result...
        LOG(LOG_INFO, 0, "buildIfVc: Interface %s, IP: %s/%d, Flags: 0x%04x, MTU: %d",
                          IfDp->Name, inetFmt(IfDp->InAdr.s_addr, 1), 33 - ffs(ntohl(mask)), IfDp->Flags, IfDp->mtu);
    }

    // Free the getifadds struct.
    free(IfAddrsP);   // Alloced by getiffaddrs()
}

/**
*   Sets the supplied pointer to the next interface in the array.
*   If called with NULL pointer walk current table, if called with pointer to self walk old table.
*/
inline struct IfDesc *getIfL(void) {
    return IfDescL;
}

/**
*   Returns pointer to interface based on given sys or vif index or NULL if not found.
*/
inline struct IfDesc *getIf(unsigned int ix, int sys) {
    struct IfDesc *IfDp;
    for (IfDp = IfDescL; IfDp && !((sys ? IfDp->sysidx : IfDp->index) == ix); IfDp = IfDp->next);
    return IfDp;
}

/**
*   Outputs interface statistics to socket specified in arguments.
*/
void getIfStats(int h, struct sockaddr_un *cliSockAddr, int fd) {
    struct IfDesc *IfDp;
    char           buf[CLI_CMD_BUF] = "", msg[CLI_CMD_BUF] = "";
    int            i = 1;
    struct totals {
        uint64_t   bytes;
        uint64_t   rate;
        uint64_t   ratelimit;
    }              total = { 0, 0, 0 };

    if (h) {
        sprintf(buf, "Current Interface Table:\n_____|______Name_____|Vif|Ver|_______IP______|___State____|____Querier____|_______Data______|______Rate______|___Ratelimit___\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }

    for (IFL(IfDp), i++) {
        if (h) {
            total = (struct totals){ total.bytes + IfDp->bytes, total.rate + IfDp->rate, total.ratelimit + IfDp->conf->ratelimit };
            strcpy(msg, "%4d |%15s| %2d| v%1d|%15s|%12s|%15s|%14lld B | %10lld B/s | %10lld B/s\n");
        } else {
            strcpy(msg, "%d %s %d %d %s %s %s %lld %lld %lld\n");
        }
        sprintf(buf, msg, i, IfDp->Name, IfDp->index == (uint8_t)-1 ? -1 : IfDp->index, IfDp->querier.ver, inetFmt(IfDp->InAdr.s_addr, 1), IS_DISABLED(IfDp->state) ? "Disabled" : IS_UPDOWNSTREAM(IfDp->state) ? "UpDownstream" : IS_DOWNSTREAM(IfDp->state) ? "Downstream" : "Upstream", inetFmt(IfDp->querier.ip, 2), IfDp->bytes, IfDp->rate, !IS_DISABLED(IfDp->state) ? IfDp->conf->ratelimit : 0);
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }

    if (h) {
        strcpy(msg, "Total|---------------|---|---|---------------|------------|---------------|%14lld B | %10lld B/s | %10lld B/s\n");
        sprintf(buf, msg, total.bytes, total.rate, total.ratelimit);
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}

/**
*   Outputs configured filters to socket specified in arguments.
*/
void getIfFilters(int h, struct sockaddr_un *cliSockAddr, int fd) {
    struct IfDesc *IfDp;
    char           buf[CLI_CMD_BUF] = "", msg[CLI_CMD_BUF] = "";
    int            i = 1;

    if (h) {
        sprintf(buf, "Current Active Filters:\n_______Int______|_nr_|__________SRC________|__________DST________|___Dir__|___Action___|______Rate_____\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }

    for (IFL(IfDp), i++) {
        struct filters *filter;
        int             i = 1;
        for (filter = IfDp->conf->filters; filter; filter = filter->next, i++) {
            char s[10] = "";
            if (filter->action > ALLOW) {
                strcpy(msg, h ? "%10lld B/s" : "%lld");
                sprintf(s, msg, filter->action);
            }
            if (h)
                strcpy(msg, "%15s |%4d| %19s | %19s | %6s | %10s | %s\n");
            else
                strcpy(msg, "%s %d %s %s %s %s %s\n");
            sprintf(buf, msg, !h || i == 1 ? IfDp->Name : "", i, inetFmts(filter->src.ip, filter->src.mask, 1), inetFmts(filter->dst.ip, filter->dst.mask, 2), filter->dir == 1 ? "up" : filter->dir == 2 ? "down" : "both", filter->action == ALLOW ? "Allow" : filter->action == BLOCK ? "Block" : "Ratelimit", s);
            sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
        }
    }

    if (h) {
        sprintf(buf, "-------------------------------------------------------------------------------------------------------\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
