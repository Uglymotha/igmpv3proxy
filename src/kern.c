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
*   Kern.c - Kernel mroute API functions.
*/

#include "igmpv3proxy.h"

static int      mrouterFD = -1, nlFD = -1;
static uint32_t vifBits   =  0;

/**
*   Returns the mrouter FD.
*/
int k_getMrouterFD(void) {
    return mrouterFD;
}

/**
*   Returns the netlink FD.
*/
int k_getNlFD(void) {
    return nlFD;
}

/**
*   Initializes the netlink API..
*/
void k_enableNl(void) {
#ifdef HAVE_NETLINK
    struct sockaddr_nl nl;
    nl.nl_family = AF_NETLINK;
    nl.nl_pid = getpid();
    nl.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
    if ((nlFD = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        LOG(LOG_ERR, 1, "Failed to open netlink socket.");
    } else if (bind(nlFD, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
        nlFD = -1;
        LOG(LOG_ERR, 1, "Failed netlink socket bind.");
    } else
        LOG(LOG_NOTICE, 0, "Opened netlink socket.");
#endif
}

/**
*   Closes netlink socket.
*/
void k_disableNl(void) {
    if (nlFD == -1)
        return;
    else if (close(nlFD) < 0)
        LOG(LOG_WARNING, 1, "Netlink socket CLOSE failed.");
    else {
        LOG(LOG_NOTICE, 0, "Closed netlink Socket.");
        nlFD = -1;
    }
}

/**
*   Initializes the mrouted API and locks it by this exclusively.
*/
void k_enableMRouter(void) {
    int Va = 1;

    if (mrt_tbl < 0 && (mrouterFD = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        LOG(LOG_CRIT, eNOINIT, "Failed to open UDP socket.");
    else if (mrt_tbl < 0)
        LOG(LOG_NOTICE, 0, "Opened UDP socket.");
    else if ((mrouterFD = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0)
        LOG(LOG_CRIT, eNOINIT, "IGMP socket open Failed");
#ifdef __linux__
    else if (setsockopt(mrouterFD, IPPROTO_IP, MRT_TABLE, &mrt_tbl, sizeof(mrt_tbl)) < 0)
        errno == ENOPROTOOPT ? LOG(LOG_CRIT, eNOINIT, "IGMP socket MRT_TABLE Failed. Make sure your kernel has"
                                                      "CONFIG_IP_MROUTE_MULTIPLE_TABLES=y")
                             : LOG(LOG_CRIT, eNOINIT, "IGMP socket MRT_TABLE Failed.");
#endif
    else if (setsockopt(mrouterFD, IPPROTO_IP, IP_HDRINCL, (void *)&Va, sizeof(Va)) < 0)
        LOG(LOG_CRIT, eNOINIT, "IGMP socket IP_HDRINCL Failed");
    else if (setsockopt(mrouterFD, IPPROTO_IP, MRT_INIT, (void *)&Va, sizeof(Va)) < 0)
        LOG(LOG_CRIT, eNOINIT, "IGMP socket MRT_INIT Failed");
    else if (setsockopt(mrouterFD, IPPROTO_IP, IFINFO, (void *)&Va, sizeof(Va)) < 0)
        LOG(LOG_CRIT, eNOINIT, "IGMP socket IP_IFINFO Failed");
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
    else if (((Va = MRT_MFC_BW_UPCALL) && setsockopt(mrouterFD, IPPROTO_IP, MRT_API_CONFIG, (void *)&Va, sizeof(Va)) < 0)
             || ! (Va & MRT_MFC_BW_UPCALL)) {
        LOG(LOG_WARNING, 1, "IGMP socket MRT_API_CONFIG Failed. Disabling bandwidth control.");
        CONF->bwControl = (uint32_t)-1;
    }
#endif
    else
        LOG(LOG_NOTICE, 0, "Opened IGMP socket.");
    fcntl(mrouterFD, F_SETFD, O_NONBLOCK);
}

/**
*   Disable the mrouted API and relases by this the lock.
*/
void k_disableMRouter(void) {
    if (!STARTUP && !SPROXY && mrt_tbl >= 0 && setsockopt(mrouterFD, IPPROTO_IP, MRT_DONE, NULL, 0) != 0)
        LOG(LOG_WARNING, 1, "IGMP socket MRT_DONE failed.");
    if (mrouterFD >= 0 && close(mrouterFD) < 0)
        LOG(LOG_WARNING, 1, "%s socket CLOSE failed.", mrt_tbl < 0 ? "UDP" : "IGMP");
    else {
        LOG(LOG_NOTICE, 0, "Closed %s Socket.", mrt_tbl < 0 || SPROXY ? "UDP" : "IGMP");
        mrouterFD = -1;
    }
}

/**
*   Set the socket buffer. If we can't set it as large as we want, search around to try to find the highest acceptable
*   value. The highest acceptable value being smaller than minsize is a fatal error.
*/
void k_set_rcvbuf(int bufsize) {
    int minsize = 48*1024, delta = bufsize / 2, i = 0;      // No less than 48Kb of kernel ring bufer space.

    if (setsockopt(mrouterFD, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
        bufsize -= delta;
        while (1) {
            i++;
            if (delta > 1)
                 delta /= 2;
            if (setsockopt(mrouterFD, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
                if (bufsize < minsize)
                    LOG(LOG_CRIT, eNOMEM, "OS-allowed buffer size %u < app min %u",  bufsize, minsize);
                bufsize -= delta;
            } else {
                if (delta < 1024)
                    break;
                bufsize += delta;
            }
        }
    }
    memuse.rcv += bufsize;

    LOG(LOG_DEBUG, 0, "Got %d byte buffer size in %d iterations", bufsize, i);
}

void k_set_ttl(uint8_t ttl) {
#ifndef RAW_OUTPUT_IS_RAW
    if (setsockopt(mrouterFD, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) < 0)
        LOG(LOG_WARNING, 1, "setsockopt IP_MULTICAST_TTL %u", ttl);
#endif
}

void k_set_loop(bool loop) {
    if (setsockopt(mrouterFD, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0)
        LOG(LOG_WARNING, 1, "setsockopt IP_MULTICAST_LOOP %u", loop);
}

void k_set_if(struct IfDesc *IfDp) {
    struct in_addr adr = { IfDp ? IfDp->InAdr.s_addr : INADDR_ANY };
    if (setsockopt(mrouterFD, IPPROTO_IP, IP_MULTICAST_IF, (char *)&adr, sizeof(adr)) < 0)
        LOG(LOG_WARNING, 1, "setsockopt IP_MULTICAST_IF %s", inetFmt(adr.s_addr, 0));
}

/**
 *   Adds the interface '*IfDp' as virtual interface to the mrouted API
 */
bool k_addVIF(struct IfDesc *IfDp) {
    struct vifctl   vifCtl;
    uint8_t         Ix;

    // Find available vif index.
    if (vifBits == (uint32_t)-1) {
        LOG(LOG_WARNING, 0, "Out of VIF space");
        IfDp->state &= ~0x03;
        return false;
    }
    for (Ix = 0; Ix < MAXVIFS && (vifBits & (1 << Ix)); Ix++);

    // Set the vif parameters, reset bw counters.
    memset(&vifCtl, 0, sizeof(struct vifctl));
#ifdef HAVE_STRUCT_VIFCTL_VIFC_LCL_IFINDEX
    vifCtl = (struct vifctl){ Ix, 0, IfDp->conf->threshold, 0, {{IfDp->InAdr.s_addr}}, {INADDR_ANY} };
#else
    vifCtl = (struct vifctl){ Ix, 0, IfDp->conf->threshold, 0, {IfDp->InAdr.s_addr}, {INADDR_ANY} };
#endif
    // Add the vif.
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_VIF, (char *)&vifCtl, sizeof(vifCtl)) < 0) {
        LOG(LOG_ERR, 1, "Error adding VIF %d:%s", Ix, IfDp->Name);
        IfDp->state &= ~0x03;
        return false;
    }
    IfDp->stats.iBytes = IfDp->stats.oBytes = IfDp->stats.iRate = IfDp->stats.oRate = 0;
    IfDp->index = Ix;
    BIT_SET(vifBits, IfDp->index);
    LOG(LOG_NOTICE, 0, "Adding VIF: %s, Ix: %d, Fl: 0x%x, IP: %s, Threshold: %d, Ratelimit: %d", IfDp->Name, vifCtl.vifc_vifi,
        vifCtl.vifc_flags, inetFmt(vifCtl.vifc_lcl_addr.s_addr, 0), vifCtl.vifc_threshold, IfDp->conf->ratelimit);
    return true;
}

/**
 *   Delete vif when removed from config or disappeared from system.
 */
void k_delVIF(struct IfDesc *IfDp) {
    struct vifctl vifCtl;
    memset(&vifCtl, 0, sizeof(struct vifctl));

    vifCtl.vifc_vifi = IfDp->index;
    LOG(LOG_NOTICE, 0, "Removing VIF: %s, Ix: %d, Fl: 0x%x, IP: %s, Threshold: %d, Ratelimit: %d", IfDp->Name, IfDp->index,
        IfDp->Flags, inetFmt(IfDp->InAdr.s_addr, 0), IfDp->conf->threshold, IfDp->conf->ratelimit);
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_VIF, (char *)&vifCtl, sizeof(vifCtl)) < 0)
        LOG(LOG_ERR, 1, "Error removing VIF %d:%s", IfDp->index, IfDp->Name);

    // Reset vif index.
    BIT_CLR(vifBits, IfDp->index);
    IfDp->index = (uint8_t)-1;
}

/**
*   Joins the MC group with the address 'McAdr' on the interface 'IfName'.
*   The join is bound to the UDP socket 'udpSock', so if this socket is
*   closed the membership is dropped.
*/
bool k_updateGroup(struct IfDesc *IfDp, bool join, uint32_t group, int mode, uint32_t source) {
    struct group_req        grpReq  = { 0 };
    struct group_source_req grpSReq = { 0 };
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    struct sockaddr_in grp = { sizeof(struct sockaddr_in), AF_INET, 0, group };
    struct sockaddr_in src = { sizeof(struct sockaddr_in), AF_INET, 0, source };
#else
    struct sockaddr_in grp = { AF_INET, 0, {group}, {0} };
    struct sockaddr_in src = { AF_INET, 0, {source}, {0} };
#endif
    source == (uint32_t)-1 ? (grpReq.gr_interface = IfDp->sysidx) : (grpSReq.gsr_interface = IfDp->sysidx);
    memcpy(source == (uint32_t)-1 ? &grpReq.gr_group : &grpSReq.gsr_group, &grp, sizeof(grp));
    memcpy(&grpSReq.gsr_source, &src, sizeof(src));

    if (setsockopt(mrouterFD, IPPROTO_IP,
                   source == (uint32_t)-1 ? (join ?         MCAST_JOIN_GROUP     : MCAST_LEAVE_GROUP)
                                          :  join ? (mode ? MCAST_BLOCK_SOURCE   : MCAST_JOIN_SOURCE_GROUP)
                                                  : (mode ? MCAST_UNBLOCK_SOURCE : MCAST_LEAVE_SOURCE_GROUP),
                   source == (uint32_t)-1 ? (void *)&grpReq : (void *)&grpSReq,
                   source == (uint32_t)-1 ? sizeof(grpReq)  : sizeof(grpSReq)) < 0) {
        LOG(LOG_WARNING, 1, "%s %s%s%s on %s failed",
            join ? (source == (uint32_t)-1 ? "MCAST_JOIN_GROUP"  : mode ? "MCAST_BLOCK_SOURCE"   : "MCAST_JOIN_SOURCE_GROUP")
                 : (source == (uint32_t)-1 ? "MCAST_LEAVE_GROUP" : mode ? "MCAST_UNBLOCK_SOURCE" : "MCAST_LEAVE_SOURCE_GROUP"),
            inetFmt(group, 0), source == (uint32_t)-1 ? "" : ":", source == (uint32_t)-1 ? "" : inetFmt(source, 0), IfDp->Name);
        if (errno == ENOBUFS) {
            LOG(LOG_WARNING, 0, "Maximum number of multicast groups or sources was exceeded");
#ifdef __linux__
            LOG(LOG_WARNING, 0, "Check settings of '/sbin/sysctl net.ipv4.igmp_max_memberships / net.ipv4.igmp_max_msf'.");
#endif
        }
        return false;
    }

    return true;
}

/**
*   Sets group filter for group on iupstream interface.
*/
inline int k_setSourceFilter(struct IfDesc *IfDp, uint32_t group, uint32_t fmode, uint32_t nsrcs, uint32_t *slist) {
    uint32_t i, err = 0, size = (nsrcs + 1) * sizeof(struct sockaddr_storage);
    struct sockaddr_storage *ss;

    _malloc(ss, var, size);  // Freed by self.
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    int er = EADDRNOTAVAIL;  // Freebsd errno when group is not joined.
    struct sockaddr_in sin = (struct sockaddr_in){ sizeof(struct sockaddr_in), AF_INET, 0, group };
    for(i = 0; i < nsrcs; i++)
        *(struct sockaddr_in *)(ss + i) = (struct sockaddr_in){ sizeof(struct sockaddr_in), AF_INET, 0, slist[i]};
#else
    int er = EINVAL;  // Linux errno when group is not joined.
    struct sockaddr_in sin = (struct sockaddr_in){ AF_INET, 0, {group}, {0} };
    for(i = 0; i < nsrcs; i++)
        *(struct sockaddr_in *)(ss + i) = (struct sockaddr_in){ AF_INET, 0, {slist[i]}, {0} };
#endif
    LOG(LOG_INFO, 0, "Setting source filter on %s for %s (%s) with %d sources.", IfDp->Name, inetFmt(group, 0),
        fmode ? "IN" : "EX", nsrcs);
    if (setsourcefilter(mrouterFD, if_nametoindex(IfDp->Name), (struct sockaddr *)&sin, sizeof(struct sockaddr_in),
                        fmode, nsrcs, ss) < 0 && ((err = errno) != er || nsrcs == 0))
        LOG(LOG_WARNING, 1, "Failed to update source filter list for %s on %s.", inetFmt(group, 0), IfDp->Name);

    _free(ss, var, size);  // Alloced by self.
    return err ? EADDRNOTAVAIL : 0;
}

/**
*   Adds a multicast MFT to the kernel.
*/
bool k_addMRoute(uint32_t src, uint32_t group, struct IfDesc *IfDp, uint8_t ttlVc[MAXVIFS]) {
    // Inialize the mfc control structure.
#ifdef HAVE_STRUCT_MFCCTL2_MFCC_TTLS
    struct mfcctl2 CtlReq;
    memset(&CtlReq, 0, sizeof(struct mfcctl2));
    CtlReq = (struct mfcctl2){ {src}, {group}, IfDp->index, {0}, {0}, 0 };
#else
    struct mfcctl CtlReq;
    memset(&CtlReq, 0, sizeof(struct mfcctl));
    CtlReq = (struct mfcctl){ {src}, {group}, IfDp->index, {0}, 0, 0, 0, 0 };
#endif
    memcpy(CtlReq.mfcc_ttls, ttlVc, sizeof(CtlReq.mfcc_ttls));

    // Add the mfc to the kernel.
    LOG(LOG_INFO, 0, "Adding MFC: %s -> %s, InpVIf: %d.", inetFmt(CtlReq.mfcc_origin.s_addr, 0),
        inetFmt(CtlReq.mfcc_mcastgrp.s_addr, 0), (int)CtlReq.mfcc_parent);
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_MFC, (void *)&CtlReq, sizeof(CtlReq)) < 0) {
        LOG(LOG_WARNING, 1, "MRT_ADD_MFC %d - %s failed.", IfDp->index, inetFmt(group, 0));
        return false;
    }
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
    if (IfDp->conf->bwControl > 0) {
        struct bw_upcall bwUpc = { {src}, {group}, BW_UPCALL_UNIT_BYTES | BW_UPCALL_LEQ,
                                   { {IfDp->conf->bwControl, 0}, 0, (uint64_t)-1 }, { {0}, 0, 0 } };
        if (setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_BW_UPCALL, (void *)&bwUpc, sizeof(bwUpc)) < 0)
            LOG(LOG_WARNING, 1, "MRT_ADD_BW_UPCALL %s:%s on %s failed.", inetFmt(src, 0), inetFmt(group, 0), IfDp->Name);
    }
#endif
    return true;
}

/**
*   Remove multicast MFC from the kernel.
*/
bool k_delMRoute(uint32_t src, uint32_t group, struct IfDesc *IfDp) {
    // Inialize the mfc control structure.
#ifdef HAVE_STRUCT_MFCCTL2_MFCC_TTLS
    struct mfcctl2 CtlReq;
    memset(&CtlReq, 0, sizeof(struct mfcctl2));
    CtlReq = (struct mfcctl2){ {src}, {group}, IfDp->index, {0}, {0}, 0 };
#else
    struct mfcctl CtlReq;
    memset(&CtlReq, 0, sizeof(struct mfcctl));
    CtlReq =  (struct mfcctl){ {src}, {group}, IfDp->index, {0}, 0, 0, 0, 0 };
#endif
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
    if (IfDp->conf->bwControl)
        k_deleteUpcall(src, group);
#endif
    // Remove mfc from kernel.
    LOG(LOG_INFO, 0, "Removing MFC: %s -> %s, InpVIf: %d", inetFmt(CtlReq.mfcc_origin.s_addr, 0),
        inetFmt(CtlReq.mfcc_mcastgrp.s_addr, 0), (int)CtlReq.mfcc_parent);
    if (!(errno = 0) && setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_MFC, (void *)&CtlReq, sizeof(CtlReq)) < 0)
        LOG(LOG_WARNING, 1, "MRT_DEL_MFC %d - %s failed.", IfDp->index, inetFmt(group, 0));
    return errno;
}

#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
/**
*   Delete all BW_UPCALLS for S,G
*/
void k_deleteUpcall(uint32_t src, uint32_t group) {
    struct bw_upcall bwUpc = { {src}, {group}, BW_UPCALL_DELETE_ALL, { {0}, 0, 0 }, { {0}, 0, 0} };
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_BW_UPCALL, (void *)&bwUpc, sizeof(bwUpc)) < 0)
        LOG(LOG_WARNING, 0, "Failed to delete BW upcall for Src %s, Dst %s.", inetFmt(src, 0), inetFmt(group, 0));
    else
        LOG(LOG_INFO, 0, "Deleted BW upcalls for Src %s, Dst %s.", inetFmt(src, 0), inetFmt(group, 0));
}
#endif
