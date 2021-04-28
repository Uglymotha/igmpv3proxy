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

#include "igmpproxy.h"

// Linked list of igmpproxy interfaces.
static struct IfDesc *IfDescL = NULL;

/**
*   Frees the IfDesc table. Paramter specifies cleanup after an interface rebuild.
*/
void freeIfDescL() {
    struct IfDesc *IfDp = NULL, *pIfDp = NULL, *nIfDp = NULL;

    for (IfDp = IfDescL; IfDp; IfDp = nIfDp) {
        nIfDp = IfDp->next;
        if (SHUTDOWN || (IfDp->state & 0x80)) {
            // Free filter dSources and uSources.
            for (struct ifRoutes *ifr = IfDp->dRoutes, *nifr = NULL; ifr; nifr = ifr->next, free(ifr), ifr = nifr);
            IfDp->dRoutes = NULL;
            for (struct ifRoutes *ifr = IfDp->uRoutes, *nifr = NULL; ifr; nifr = ifr->next, free(ifr), ifr = nifr);
            IfDp->uRoutes = NULL;
            // On shutdown, or when interface is marked for deletion, remove it and its aliases.
            if (SHUTDOWN || !IfDp->gsq) {
                for (struct filters *fil = IfDp->aliases, *nfil = NULL; fil; nfil = fil->next, free(fil), fil = nfil);
                if (!SHUTDOWN) {
                    LOG(LOG_DEBUG, 0, "freeIfDescL: Interface %s disappeared, removing from list.", IfDp->Name);
                    if (pIfDp)
                        pIfDp->next = IfDp->next;
                    else
                        IfDescL = IfDp->next;
                }
                free(IfDp);  // Alloced by buildIfvc()
            } else {
                LOG(LOG_NOTICE, 0, "Interface %s actively queried, Delaying removal.", IfDp->Name);
                IfDp->state = IF_STATE_DISABLED;
                IfDp->mtu   = IfDp->Flags = 0;
                IfDp->conf->state = IF_STATE_DISABLED | 0x40;
                IfDp->oldconf = NULL;
                pIfDp = IfDp;
            }
        } else {
            IfDp->oldconf = NULL;
            pIfDp = IfDp;
        }
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
    if (!CONFRELOAD)
        buildIfVc();

    // Call configureVifs to link the new IfDesc table.
    LOG(LOG_DEBUG,0,"rebuildIfVc: Configuring vifs, New ptr: %x", IfDescL);
    configureVifs();

    // Free removed interfaces.
    freeIfDescL();

    // Restart timer when doing timed reload.
    if (tid && sigstatus == GOT_IFREB && CONFIG->rescanVif)
        *tid = timer_setTimer(TDELAY(CONFIG->rescanVif * 10), "Rebuild Interfaces", (timer_f)rebuildIfVc, tid);

    sigstatus = IFREBUILD ? 0 : sigstatus;
}

/**
*   Builds up a list with all usable interfaces of the machine.
*/
void buildIfVc(void) {
    // Get the system interface list.
    struct ifreq ifr;
    struct ifaddrs *IfAddrsP, *tmpIfAddrsP;
    struct filters *nfil, *fil;
    if ((getifaddrs (&IfAddrsP)) == -1)
        LOG(STARTUP ? LOG_ERR : LOG_WARNING, errno, "buildIfVc: getifaddr() failed, cannot enumerate interfaces");

    // Only build Ifdesc for up & running & configured IP interfaces, and can be configured for multicast if not enabled.
    for (tmpIfAddrsP = IfAddrsP; tmpIfAddrsP; tmpIfAddrsP = tmpIfAddrsP->ifa_next) {
        if (tmpIfAddrsP->ifa_flags & IFF_LOOPBACK || tmpIfAddrsP->ifa_addr->sa_family != AF_INET
            || s_addr_from_sockaddr(tmpIfAddrsP->ifa_addr) == 0
#ifdef IFF_CANTCONFIG
            || (! (tmpIfAddrsP->ifa_flags & IFF_MULTICAST) && (tmpIfAddrsP->ifa_flags & IFF_CANTCONFIG))
#endif
            || (! ((tmpIfAddrsP->ifa_flags & IFF_UP) && (tmpIfAddrsP->ifa_flags & IFF_RUNNING)))) {
            continue;
        }

        struct IfDesc *IfDp;
        uint32_t addr   = s_addr_from_sockaddr(tmpIfAddrsP->ifa_addr), mask = s_addr_from_sockaddr(tmpIfAddrsP->ifa_netmask),
                 subnet = (tmpIfAddrsP->ifa_flags & IFF_POINTOPOINT ? s_addr_from_sockaddr(tmpIfAddrsP->ifa_dstaddr) : addr) & mask;
        if ((IfDp = getIfByName(tmpIfAddrsP->ifa_name)) && (! IfDp->conf)) {
            // Check if the interface is an alias for an already created or rebuild IfDesc.
            // If the alias lies within any of the existing subnets or is /32 it does not need to be added to the list of aliases.
            for (fil = IfDp->aliases; fil && ! ((addr & fil->src.mask) == fil->src.ip); fil = fil->next);
            if (! fil && mask != 0xFFFFFFFF) {
                // Create new alias and prepend to list of existing aliases.
                fil = IfDp->aliases;
                if (! (IfDp->aliases = malloc(sizeof(struct filters))))
                    LOG(LOG_ERR, errno, "buildIfVc: Out of memory !");   // Freed by Self or freeIfDescL()
                *IfDp->aliases = (struct filters){ {subnet, mask}, {INADDR_ANY, 0}, ALLOW, (uint8_t)-1, fil };
            }
            LOG(LOG_INFO, 0, "builfIfVc: Interface %s Addr: %s, Network: %s, Ptr: %p", IfDp->Name,
                              inetFmt(addr, 1), inetFmts(subnet, mask, 2), IfDp->aliases);
            continue;

        } else if (! IfDp) {
            // New interface, allocate and initialize.
            if (! (IfDp  = malloc(sizeof(struct IfDesc))))
                LOG(LOG_ERR, errno, "builfIfVc: Out of memory.");  // Freed by freeIfDescL()
            *IfDp = DEFAULT_IFDESC;
            IfDescL = IfDp;
            // Copy the interface name. Make 100% sure it is NULL terminated.
            memcpy(IfDp->Name, tmpIfAddrsP->ifa_name, IF_NAMESIZE);
            IfDp->Name[IF_NAMESIZE - 1] = '\0';

        } else {
            // Rebuild Interface. Free current aliases and update oldstate.
            for (fil = IfDp->aliases; fil; nfil = fil->next, free(fil), fil = nfil);   // Alloced by self
            // If an interface has disappeared state is not reset here and createVifs() can mark it for deletion.
            IfDp->oldconf = IfDp->conf;
            IfDp->conf    = NULL;
        }

        // Set the interface flags and IP.
        IfDp->Flags        = tmpIfAddrsP->ifa_flags;
        IfDp->InAdr.s_addr = addr;

        // Get interface mtu.
        memset(&ifr, 0, sizeof(struct ifreq));
        memcpy(ifr.ifr_name, tmpIfAddrsP->ifa_name, IF_NAMESIZE);
        if (ioctl(MROUTERFD, SIOCGIFMTU, &ifr) < 0)
            LOG(LOG_WARNING, errno, "buildIfVc: Failed to get MTU for %s, disabling.", IfDp->Name);
        else
            IfDp->mtu = ifr.ifr_mtu;

        // Enable multicast if necessary.
        if (! (IfDp->Flags & IFF_MULTICAST)) {
            ifr.ifr_flags = IfDp->Flags | IFF_MULTICAST;
            if (ioctl(MROUTERFD, SIOCSIFFLAGS, &ifr) < 0)
                LOG(LOG_WARNING, errno, "buildIfVc: Failed to enable multicast on %s, disabling.", IfDp->Name);
            else {
                IfDp->Flags = ifr.ifr_flags;
                LOG(LOG_NOTICE, 0, "buildIfVc: Multicast Enabled on %s.", IfDp->Name);
            }
        }

        // Insert the verified subnet as first alias.
        if (! (IfDp->aliases = malloc(sizeof(struct filters))))
            LOG(LOG_ERR, errno, "buildIfVc: Out of memory !");   // Freed by freeIfDescP()
        *IfDp->aliases = (struct filters){ {subnet, mask}, {INADDR_ANY, 0}, ALLOW, (uint8_t)-1, NULL };

        // Debug log the result...
        LOG( LOG_DEBUG, 0, "buildIfVc: Interface %s Addr: %s, Flags: 0x%04x, MTU: %d, Network: %s, Ptr: %p",
                            IfDp->Name, inetFmt(IfDp->InAdr.s_addr, 1), IfDp->Flags, IfDp->mtu,
                            inetFmts(IfDp->aliases->src.ip, IfDp->aliases->src.mask, 2), IfDp->aliases);
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
*   Returns pointer to interface based on given name or NULL if not found.
*/
inline struct IfDesc *getIfByName(const char *IfName) {
    struct IfDesc *IfDp;
    for (IfDp = IfDescL; IfDp && strcmp(IfName, IfDp->Name) != 0; IfDp = IfDp->next);
    return IfDp;
}

/**
*   Returns pointer to interface based on given vif index or NULL if not found.
*/
inline struct IfDesc *getIfByIx(uint8_t ix) {
    struct IfDesc *IfDp;
    for (IfDp = IfDescL; IfDp && IfDp->index != ix; IfDp = IfDp->next);
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

    for (GETIFL(IfDp), i++) {
        if (h) {
            total = (struct totals){ total.bytes + IfDp->bytes, total.rate + IfDp->rate, total.ratelimit + IfDp->conf->ratelimit };
            strcpy(msg, "%4d |%15s| %2d| v%1d|%15s|%12s|%15s|%14lld B | %10lld B/s | %10lld B/s\n");
        } else {
            strcpy(msg, "%d %s %d %d %s %s %s %d %lld %lld %lld\n");
        }
        sprintf(buf, msg, i, IfDp->Name, IfDp->index, IfDp->querier.ver, inetFmt(IfDp->InAdr.s_addr, 1), IS_DISABLED(IfDp->state) ? "Disabled" : IS_UPDOWNSTREAM(IfDp->state) ? "UpDownstream" : IS_DOWNSTREAM(IfDp->state) ? "Downstream" : "Upstream", inetFmt(IfDp->querier.ip, 2), IfDp->bytes, IfDp->rate, !IS_DISABLED(IfDp->state) ? IfDp->conf->ratelimit : 0);
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

    for (GETIFL(IfDp), i++) {
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
