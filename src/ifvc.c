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

// Arrays of system interfaces.
static struct IfDescP {
    struct IfDesc       *S;
    struct IfDesc       *E;
    unsigned int        nrint;
}   IfDescP = { NULL, NULL, 0 }, oldIfDescP = { NULL, NULL, 0 };

// We need a temporary copy to not break strict aliasing rules
static inline uint32_t s_addr_from_sockaddr(const struct sockaddr *addr) {
    struct sockaddr_in addr_in;
    memcpy(&addr_in, addr, sizeof(addr_in));
    return addr_in.sin_addr.s_addr;
}

/**
*   Frees the IfDesc table.
*/
void freeIfDescP(int old) {
    struct IfDescP clrIfDescP = old ? oldIfDescP : IfDescP;
    struct IfDesc *Dp;

    for (Dp = clrIfDescP.S; Dp < clrIfDescP.E; Dp++) {
        struct filters *fil;
        for (fil = Dp->aliases; Dp->aliases; Dp->aliases = fil) {
            fil = Dp->aliases->next;
            free(Dp->aliases);  // Alloced by buildIfvc()
        }
    }
    free(clrIfDescP.S);   // Alloced by buildIfVc()
    my_log(LOG_DEBUG, 0, "freeIfDescP: %s cleared.", (old ? "Old IfDesc table" : "IfDesc table"));
}

/**
*   Rebuilds the list of interfaces.
*/
void rebuildIfVc(uint64_t *tid) {
    // Build new IfDesc Table. Keep Copy of Old.
    oldIfDescP = IfDescP;

    // Check and set sigstatus to what we are actually doing right now.
    sigstatus = NOSIG ? GOT_IFREB : sigstatus;

    // Build new IfDEsc table on SIGHUP, SIGUSR2 or timed rebuild.
    if (IFREBUILD || SSIGHUP) {
        buildIfVc();
    }

    // Call configureVifs to link the new IfDesc table.
    configureVifs();

    // Call createvifs with pointer to IfDesc table for relinking vifs and removing or adding interfaces if required.
    my_log(LOG_DEBUG,0,"rebuildIfVc: creating vifs, Old IfDescP: %x, New: %x", oldIfDescP.S, IfDescP.S);
    createVifs();

    // Free the old IfDesc table when new was build.
    if (IFREBUILD || SSIGHUP) {
        freeIfDescP(1);
    }

    // Restart timer shen doing timed reload.
    if (sigstatus == GOT_IFREB && CONFIG->rescanVif) *tid = timer_setTimer(0, CONFIG->rescanVif * 10, "Rebuild Interfaces", (timer_f)rebuildIfVc, tid);

    sigstatus = IFREBUILD ? 0 : sigstatus;
}

/**
*   Builds up a vector with all usable interfaces of the machine.
*/
void buildIfVc() {
    // Get the system interface list.
    struct ifaddrs *IfAddrsP, *tmpIfAddrsP;
    if ((getifaddrs (&IfAddrsP)) == -1) {
        my_log (LOG_WARNING, errno, "buildIfVc: getifaddr() failed, cannot enumerate interfaces");
        if (STARTUP) exit(-1);
    }

    // Check nr of IP interfaces in system.
    for (IfDescP.nrint = 0, tmpIfAddrsP = IfAddrsP; tmpIfAddrsP; tmpIfAddrsP = tmpIfAddrsP->ifa_next) {
        if (tmpIfAddrsP->ifa_addr->sa_family == AF_INET && (tmpIfAddrsP->ifa_flags & (IFF_UP | IFF_RUNNING)) && ! (tmpIfAddrsP->ifa_flags & IFF_LOOPBACK)) IfDescP.nrint++;
    }
    my_log (LOG_DEBUG, 0 , "buildIfVc: Found %u interface(s) on system", IfDescP.nrint);

    // Allocate memory for IfDesc Table. // Freed by freeIfDescP()
    if (! (IfDescP.S = IfDescP.E = (struct IfDesc*)calloc(IfDescP.nrint, sizeof(struct IfDesc))) || ! memset(IfDescP.S, 0, IfDescP.nrint * sizeof(struct IfDesc))) {
        my_log(LOG_ERR, 0, "buildIfVc: Out of memory !");
    }
    my_log(LOG_DEBUG, 0, "buildIfVc: Table size %dB", IfDescP.nrint * sizeof(struct IfDesc));

    // loop over IP interfaces and copy interface info to IfDescP
    for (tmpIfAddrsP = IfAddrsP; tmpIfAddrsP; tmpIfAddrsP = tmpIfAddrsP->ifa_next) {
        struct IfDesc *Dp;
        uint32_t       addr   = tmpIfAddrsP->ifa_addr->sa_family == AF_INET ? s_addr_from_sockaddr(tmpIfAddrsP->ifa_addr)    : 0,
                       mask   = tmpIfAddrsP->ifa_addr->sa_family == AF_INET ? s_addr_from_sockaddr(tmpIfAddrsP->ifa_netmask) : 0,
                       subnet = (tmpIfAddrsP->ifa_addr->sa_family == AF_INET && tmpIfAddrsP->ifa_flags & IFF_POINTOPOINT ? s_addr_from_sockaddr(tmpIfAddrsP->ifa_dstaddr) : addr) & mask;

        // Only build Ifdesc for up & running & configured IP interfaces, and can be configured for multicast if not enabled.
        if (tmpIfAddrsP->ifa_flags & IFF_LOOPBACK || tmpIfAddrsP->ifa_addr->sa_family != AF_INET || addr == 0 ||
#ifdef IFF_CANTCONFIG
           (! (tmpIfAddrsP->ifa_flags & IFF_MULTICAST) && (tmpIfAddrsP->ifa_flags & IFF_CANTCONFIG)) ||
#endif
           (! ((tmpIfAddrsP->ifa_flags & IFF_UP) && (tmpIfAddrsP->ifa_flags & IFF_RUNNING)))) {
            continue;

        } else if ((Dp = getIfByName(tmpIfAddrsP->ifa_name, 0))) {
            // Check if the interface is an alias for an already created IfDesc.
            // If the alias lies within any of the existing subnets or is /32 it does not need to be added to the list of aliases.
            struct filters *fil;
            for (fil = Dp->aliases; fil && ! ((addr & fil->src.mask) == fil->src.ip); fil = fil->next);
            if (! fil && mask != 0xFFFFFFFF) {
                // Create new alias and prepend to list of existing aliases.
                fil = Dp->aliases;
                if (! (Dp->aliases = (struct filters *)malloc(sizeof(struct filters)))) {   // Freed by freeIfDescP()
                    my_log(LOG_ERR, 0, "buildIfVc: Out of memory !");
                }
                *Dp->aliases     = (struct filters){ {subnet, mask}, {INADDR_ANY, 0}, ALLOW, NULL };
            }
            my_log(LOG_INFO, 0, "builfIfVc: Interface %s Addr: %s, Network: %s, Ptr: %p", Dp->Name ,inetFmt(addr, 1), inetFmts(subnet, mask, 2), Dp->aliases);
            continue;

        } else if (!STARTUP && (Dp = getIfByName(tmpIfAddrsP->ifa_name, 1))) {
            // Relink existing interface during interface rebuild. Update any running timers with the new IfDesc pointer.
            memcpy(IfDescP.E, Dp, sizeof(struct IfDesc));
            IfDescP.E->filters = IfDescP.E->aliases = NULL;
            IfDescP.E->igmp.v1Timer = IfDescP.E->igmp.v1Timer ? timer_setTimer(IfDescP.E->igmp.v1Timer, 0, "", NULL, IfDescP.E) : 0;
            IfDescP.E->igmp.v2Timer = IfDescP.E->igmp.v2Timer ? timer_setTimer(IfDescP.E->igmp.v2Timer, 0, "", NULL, IfDescP.E) : 0;
            IfDescP.E->querier.v1Timer = IfDescP.E->querier.v1Timer ? timer_setTimer(IfDescP.E->querier.v1Timer, 0, "", NULL, IfDescP.E) : 0;
            IfDescP.E->querier.v2Timer = IfDescP.E->querier.v2Timer ? timer_setTimer(IfDescP.E->querier.v2Timer, 0, "", NULL, IfDescP.E) : 0;
            IfDescP.E->querier.v3Timer = IfDescP.E->querier.v3Timer ? timer_setTimer(IfDescP.E->querier.v3Timer, 0, "", NULL, IfDescP.E) : 0;
            IfDescP.E->querier.ageTimer = IfDescP.E->querier.ageTimer ? timer_setTimer(IfDescP.E->querier.ageTimer, 0, "", NULL, IfDescP.E) : 0;

        } else {
            // New interface, set default params.
            *IfDescP.E     = (struct IfDesc){ "", {0}, 0, CONFIG->defaultInterfaceState, NULL, {0, 0, 0, 0, 0, 0, 0, 0, 0}, {3, 0, 0}, NULL, NULL, CONFIG->defaultThreshold, 0, 0, 0, 0, 0, (unsigned int)-1 };
            // Copy the interface name. Make 100% sure it is NULL terminated.
            memcpy(IfDescP.E->Name, tmpIfAddrsP->ifa_name, IF_NAMESIZE);
            IfDescP.E->Name[IF_NAMESIZE - 1] = '\0';
            if (! (tmpIfAddrsP->ifa_flags & IFF_MULTICAST)) {
                // Enable multicast on interface if necessary.
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(struct ifreq));
                strncpy(ifr.ifr_name, IfDescP.E->Name, IF_NAMESIZE);
                ifr.ifr_flags = tmpIfAddrsP->ifa_flags | IFF_MULTICAST;
                if (ioctl(getMrouterFD(), SIOCSIFFLAGS, &ifr)) continue;
                my_log(LOG_INFO, 0, "buildIfVc: Interface %s Multicast Enabled.", IfDescP.E->Name); 
            }
        }

        // Set the interface flags and IP.
        IfDescP.E->Flags        = tmpIfAddrsP->ifa_flags | IFF_MULTICAST;
        IfDescP.E->InAdr.s_addr = addr;

        // Insert the verified subnet as first alias.
        if (! (IfDescP.E->aliases = (struct filters *)malloc(sizeof(struct filters)))) {   // Freed by freeIfDescP()
            my_log(LOG_ERR, 0, "buildIfVc: Out of memory !");
        }
        *IfDescP.E->aliases = (struct filters){ {subnet, mask}, {INADDR_ANY, 0}, ALLOW, NULL };

        // Debug log the result...
        my_log( LOG_DEBUG, 0, "buildIfVc: Interface %s Addr: %s, Flags: 0x%04x, Network: %s, Ptr: %p",
             IfDescP.E->Name, fmtInAdr(IfDescP.E->InAdr, 1), IfDescP.E->Flags, inetFmts(IfDescP.E->aliases->src.ip, IfDescP.E->aliases->src.mask, 2), IfDescP.E->aliases);

        // Build next IfDesc.
        IfDescP.E++;
    }
    
    // Free the getifadds struct.
    free (IfAddrsP);   // Alloced by getiffaddrs()
}

/**
*   Sets the supplied pointer to the next interface in the array.
*   If called with NULL pointer walk current table, if called with pointer to self walk old table.
*/
void getNextIf(struct IfDesc **IfDp) {
    *IfDp = *IfDp == NULL ? IfDescP.S : *IfDp == (void *)&getNextIf ? oldIfDescP.S : ++*IfDp == IfDescP.E || *IfDp == oldIfDescP.E ? NULL : *IfDp;
}

/**
*   Returns pointer to interface based on given name or NULL if not found.
*/
struct IfDesc *getIfByName(const char *IfName, int old) {
    struct IfDesc *Dp;
    for (Dp = (old ? oldIfDescP.S : IfDescP.S); Dp < (old ? oldIfDescP.E : IfDescP.E) && strcmp(IfName, Dp->Name) != 0; Dp++);
    return Dp < (old ? oldIfDescP.E : IfDescP.E) ? Dp : NULL;
}

/**
*   Function that checks if a given ipaddress is a valid address for the supplied pointer.
*   The pointer may be an IfDesc or a vifconfig, selected by second parameter.
*   The last parameter specifies whether to check against allowed / deniednets or whitelist / blacklist.
*/
uint64_t isAddressValidForIf(void *Dp, register int ifdesc, register uint32_t src, register uint32_t group) {
    struct filters      *filter;
    struct IfDesc       *IfDp = Dp;
    struct vifconfig    *vifDp = Dp;
    uint64_t             bw = ALLOW;

    // Filters are processed top down until a definitive action (BLOCK or ALLOW) is found. The default action when no filter applies is block.
    // Whenever a ratelimit statement is encountered the the total bandwidth of all groups the filter applies to over the interface is calculated.
    // If the result is over the ratelimit specified by the bw variable is updated and processing continues. If more than one ratelimit is applicable
    // only the last is applied. In any case block still means block.
    for (filter = ifdesc ? IfDp->filters : vifDp->filters; filter; filter = filter->next) {
        if (src == 0 && (group & filter->dst.mask) == filter->dst.ip) {
           if (filter->action > ALLOW) {
               // Set ratelimit for filter. If we are called with a pointer to vifconfig it is for evaluating bwl and we do not do bw control.
               if ((bw = getGroupBw(filter->dst, Dp, ifdesc)) && bw >= filter->action) {
                   my_log(LOG_NOTICE, 0, "BW_CONTROL: Group %s (%lld B/s) ratelimited on %s by filter %s (%lld B/s).", inetFmt(group, 1), bw, ifdesc ? IfDp->Name : vifDp->name, inetFmts(filter->dst.ip, filter->dst.mask, 2), filter->action);
               } else if (bw < filter->action) {
                   bw = BLOCK;
               }
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
        sprintf(buf, "Current Interface Table:\n_____|______Name_____|Ver|_______IP______|___State__|______Querier_____|_______Data______|______Rate______|___Ratelimit___\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }

    for (IfDp = IfDescP.S; IfDp < IfDescP.E; IfDp++, i++) {
        if (h) {
            total = (struct totals){ total.bytes + IfDp->bytes, total.rate + IfDp->rate, total.ratelimit + IfDp->ratelimit };
            strcpy(msg, "%4d |%15s| v%1d|%15s|%10s|%15s/v%1d|%14lld B | %10lld B/s | %10lld B/s\n");
            sprintf(buf, msg, i, IfDp->Name, IfDp->igmp.ver, inetFmt(IfDp->InAdr.s_addr, 1), IfDp->state == IF_STATE_UPSTREAM ? "Upstream" : IfDp->state == IF_STATE_DOWNSTREAM ? "Downstream" : "Disabled", inetFmt(IfDp->querier.ip, 2), IfDp->querier.ver, IfDp->bytes, IfDp->rate, IfDp->ratelimit);
        } else {
            strcpy(msg, "%d %s %d %s %s %s %d %lld %lld %lld\n");
            sprintf(buf, msg, i, IfDp->Name, IfDp->igmp.ver, inetFmt(IfDp->InAdr.s_addr, 1), IfDp->state == IF_STATE_UPSTREAM ? "Upstream" : IfDp->state == IF_STATE_DOWNSTREAM ? "Downstream" : "Disabled", inetFmt(IfDp->querier.ip, 2), IfDp->querier.ver, IfDp->bytes, IfDp->rate, IfDp->ratelimit);
        }
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }

    if (h) {
        strcpy(msg, "Total|---------------|---|---------------|----------|------------------|%14lld B | %10lld B/s | %10lld B/s\n");
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
        sprintf(buf, "Current Active Filters:\n_______Int______|_nr_|__________SRC________|__________DST________|___Action___|______Rate_____\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }

    for (IfDp = IfDescP.S; IfDp < IfDescP.E; IfDp++, i++) {
        struct filters *filter;
        int             i = 1;
        for (filter = IfDp->filters; filter; filter = filter->next, i++) {
            char s[10] = "";
            if (filter->action > ALLOW) {
                strcpy(msg, h ? "%10lld B/s" : "%lld");
                sprintf(s, msg, filter->action);
            }
            if (h) {
                strcpy(msg, "%15s |%4d| %19s | %19s | %10s | %s\n");
                sprintf(buf, msg, i == 1 ? IfDp->Name : "", i, inetFmts(filter->src.ip, filter->src.mask, 1), inetFmts(filter->dst.ip, filter->dst.mask, 2), filter->action == ALLOW ? "Allow" : filter->action == BLOCK ? "Block" : "Ratelimit", s);
            } else {
                strcpy(msg, "%s %d %s %s %s %s\n");
                sprintf(buf, msg, IfDp->Name, i, inetFmts(filter->src.ip, filter->src.mask, 1), inetFmts(filter->dst.ip, filter->dst.mask, 2) , filter->action == ALLOW ? "Allow" : filter->action == BLOCK ? "Block" : "Ratelimit", s);
            }
            sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
        }
    }

    if (h) {
        sprintf(buf, "----------------------------------------------------------------------------------------------\n");
        sendto(fd, buf, strlen(buf), MSG_DONTWAIT, (struct sockaddr *)cliSockAddr, sizeof(struct sockaddr_un));
    }
}
