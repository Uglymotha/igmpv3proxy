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

struct IfDescP IfDescP = { NULL, NULL, 0 };

/* We need a temporary copy to not break strict aliasing rules */
static inline uint32_t s_addr_from_sockaddr(const struct sockaddr *addr) {
    struct sockaddr_in addr_in;
    memcpy(&addr_in, addr, sizeof(addr_in));
    return addr_in.sin_addr.s_addr;
}

/* aimwang: add for detect interface and rebuild IfVc record */
/***************************************************
 * TODO:    Only need run me when detect downstream changed.
 *          For example: /etc/ppp/ip-up & ip-down can touch a file /tmp/ppp_changed
 *          So I can check if the file exist then run me and delete the file.
 ***************************************************/
void rebuildIfVc() {
    // Build new IfDesc Table. Keep Copy of Old.
    struct IfDescP OldIfDescP = IfDescP;
    buildIfVc();

    // Call configureVifs to link the new IfDesc table.
    configureVifs();

    // Call createvifs with pointers  IfDesc tables for relinking vifs and removing or adding interfaces if required.
    my_log(LOG_DEBUG,0,"RebuildIfVc: creating vifs, Old IfDescP: %x, New: %x", OldIfDescP.S, IfDescP.S);
    createVifs(&OldIfDescP);

    // Free the old IfDesc Table and linked subnet lists.
    struct IfDesc *Dp;
    for (Dp = OldIfDescP.S; Dp < OldIfDescP.E; Dp++) {
        int i;
        for (i = 1; i <= 4; i++) {
            struct SubnetList *TmpNetPtr, *currsubnet;
            currsubnet = i == 1 ? Dp->allowednets :
                         i == 2 ? Dp->deniednets :
                         i == 3 ? Dp->allowedgroups :
                                  Dp->deniedgroups;
            for (TmpNetPtr = currsubnet ? currsubnet->next : NULL; currsubnet; currsubnet = TmpNetPtr, TmpNetPtr = currsubnet->next) {
                free(currsubnet);  // Alloced by builfIfVc and allocSubnet().
            }
        }
    }
    free(OldIfDescP.S);   // Alloced by buildIfVc()
}

/*
** Builds up a vector with the interface of the machine. Calls to the other functions of
** the module will fail if they are called before the vector is build.
**
*/
void buildIfVc() {
    // Get the config.
    struct Config *config = getCommonConfig();

    struct ifaddrs *IfAddrsP, *TmpIfAddrsP;
    if ((getifaddrs (&IfAddrsP)) == -1) {
        my_log (LOG_ERR, errno, "buildIfVc: getifaddr() failed, cannot enumerate interfaces");
        exit (1);
    }

    // Check nr of interfaces in system.
    unsigned int NrInt = 0;
    for (TmpIfAddrsP=IfAddrsP; TmpIfAddrsP; NrInt++, TmpIfAddrsP = TmpIfAddrsP->ifa_next);
    IfDescP.nrint = NrInt;
    my_log (LOG_DEBUG, 0 , "buildIfVc: Found %u interface(s) on system", NrInt);

    // Allocate memory for IfDesc Table. Freed by rebuildIfVc().
    struct IfDesc *IfDescA = (struct IfDesc*)calloc(IfDescP.nrint,sizeof(struct IfDesc));
    if(IfDescA == NULL) {
        my_log(LOG_ERR, 0, "Out of memory !");
    }
    IfDescP.S = IfDescP.E = IfDescA;

    // loop over interfaces and copy interface info to IfDescP
    for (TmpIfAddrsP = IfAddrsP; TmpIfAddrsP; TmpIfAddrsP = TmpIfAddrsP->ifa_next) {
        // Temp keepers of interface params...
        uint32_t addr, subnet, mask;
        char FmtBu[32];

        // don't create IfDesc for non-IP interfaces.
        if (TmpIfAddrsP->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        // Copy the interface name.
        int sz = strlen(TmpIfAddrsP->ifa_name) < sizeof(IfDescP.E->Name) ? strlen(TmpIfAddrsP->ifa_name) : sizeof(IfDescP.E->Name);
        memcpy(IfDescP.E->Name, TmpIfAddrsP->ifa_name, sz);
        IfDescP.E->Name[sz]='\0';

        // Set the index to -1 by default.
        IfDescP.E->index = (unsigned int)-1;

        // Get the interface adress...
        IfDescP.E->InAdr.s_addr = s_addr_from_sockaddr(TmpIfAddrsP->ifa_addr);
        addr = IfDescP.E->InAdr.s_addr;

        // Get the subnet mask...
        mask = s_addr_from_sockaddr(TmpIfAddrsP->ifa_netmask);
        subnet = addr & mask;

        /* get if flags
        **
        ** typical flags:
        ** lo    0x0049 -> Running, Loopback, Up
        ** ethx  0x1043 -> Multicast, Running, Broadcast, Up
        ** ipppx 0x0091 -> NoArp, PointToPoint, Up
        ** grex  0x00C1 -> NoArp, Running, Up
        ** ipipx 0x00C1 -> NoArp, Running, Up
        */
        IfDescP.E->Flags = TmpIfAddrsP->ifa_flags;

        // aimwang: when pppx get dstaddr for use
        if (0x10d1 == IfDescP.E->Flags) {
            addr = s_addr_from_sockaddr(TmpIfAddrsP->ifa_dstaddr);
            subnet = addr & mask;
        }

        // Insert the verified subnet as an allowed net... Freed by rebuildIfVc();
        IfDescP.E->allowednets = (struct SubnetList *)malloc(sizeof(struct SubnetList));
        if(! IfDescP.E->allowednets) {
            my_log(LOG_ERR, 0, "Out of memory !");
        }

        // Create the network address for the IF..
        IfDescP.E->allowednets->next = NULL;
        IfDescP.E->allowednets->subnet_mask = mask;
        IfDescP.E->allowednets->subnet_addr = subnet;

        // Set the default params for the IF...
        IfDescP.E->state         = config->defaultInterfaceState;
        IfDescP.E->robustness    = DEFAULT_ROBUSTNESS;
        IfDescP.E->threshold     = DEFAULT_THRESHOLD;   /* ttl limit */
        IfDescP.E->ratelimit     = DEFAULT_RATELIMIT;

        // Debug log the result...
        my_log( LOG_DEBUG, 0, "buildIfVc: Interface %s Addr: %s, Flags: 0x%04x, Network: %s",
             IfDescP.E->Name,
             fmtInAdr(FmtBu, IfDescP.E->InAdr),
             IfDescP.E->Flags,
             inetFmts(subnet,mask, s1));
        IfDescP.E++;
    }
    
    // Free the getifadds struct.
    free (IfAddrsP);   // Alloced by getiffaddrs()
}

/*
** Returns a pointer to the IfDesc of the interface 'IfName'
**
** returns: - pointer to the IfDesc of the requested interface
**          - NULL if no interface 'IfName' exists
**
*/
struct IfDesc *getIfByName(const char *IfName, struct IfDescP *RebuildP) {
    struct IfDescP *checkIfDescP = RebuildP ? RebuildP : &IfDescP;
    struct IfDesc *Dp;
    for (Dp = checkIfDescP->S; Dp < checkIfDescP->E && strcmp(IfName, Dp->Name); Dp++);
    return Dp < checkIfDescP->E ? Dp : NULL;
}

/*
** Returns a pointer to the IfDesc of the interface 'Ix'
**
** returns: - pointer to the IfDesc of the requested interface
**          - NULL if no interface 'Ix' exists
**
*/
struct IfDesc *getIfByIx(unsigned Ix, struct IfDescP *RebuildP) {
    struct IfDescP *checkIfDescP = RebuildP ? RebuildP : &IfDescP;
    struct IfDesc *Dp = checkIfDescP->S+Ix;
    return Dp < checkIfDescP->E ? Dp : NULL;
}

/**
*   Returns a pointer to the IfDesc whose subnet matches
*   the supplied IP adress. The IP must match a interfaces
*   subnet, or any configured allowed subnet on a interface.
*/
struct IfDesc *getIfByAddress(uint32_t ipaddr) {
    struct IfDesc       *Dp;
    for (Dp = IfDescP.S; Dp < IfDescP.E && ! isAdressValidForIf(Dp, ipaddr, 0); Dp++);
    return Dp < IfDescP.E ? Dp : NULL;
}

/**
*   Function that checks if a given ipaddress is a valid
*   address for the supplied VIF.
*/
int isAdressValidForIf(struct IfDesc* IfDp, uint32_t ipaddr, int wl) {
    struct SubnetList   *sn;

    // Check allowednets or whitelist if wl is set.
    if (! wl || (wl && IfDp->allowedgroups)) {
        // Loop through all registered allowed and denied nets of the VIF, and check if ip is allowed.
        for (sn = wl ? IfDp->allowedgroups : IfDp->allowednets; sn && (ipaddr & sn->subnet_mask) != sn->subnet_addr; sn = sn->next);
        if (! sn) {
            return 0;
        }
    }

    // Check if the ip address is blacklisted.
    for (sn = wl ? IfDp->deniedgroups : IfDp->deniednets; sn && (ipaddr & sn->subnet_mask) != sn->subnet_addr; sn = sn->next);
    if (sn) {
        return 0;
    }

    return 1;
}
