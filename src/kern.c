/*
**  igmpv3proxy - IGMP proxy based multicast router
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
*/

#include "igmpv3proxy.h"

static int curttl = 0, mrouterFD = -1;
static bool k_joinleave(int Cmd, struct IfDesc *IfDp, uint32_t mcastaddr);

/**
*   Set the socket buffer.  If we can't set it as large as we want, search around to try to find the highest acceptable
*   value.  The highest acceptable value being smaller than minsize is a fatal error.
*/
void k_set_rcvbuf(int bufsize, int minsize) {
    int delta = bufsize / 2;
    int iter = 0;

    if (setsockopt(mrouterFD, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
        bufsize -= delta;
        while (1) {
            iter++;
            if (delta > 1) delta /= 2;

            if (setsockopt(mrouterFD, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
                if (bufsize < minsize)
                    LOG(LOG_ERR, 0, "OS-allowed buffer size %u < app min %u",  bufsize, minsize);
                bufsize -= delta;
            } else {
                if (delta < 1024)
                    break;
                bufsize += delta;
            }
        }
    }

    LOG(LOG_DEBUG, 0, "Got %d byte buffer size in %d iterations", bufsize, iter);
}

inline int k_set_ttl(uint8_t t) {
#ifndef RAW_OUTPUT_IS_RAW
    uint8_t ttl = t;

    if (setsockopt(mrouterFD, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) < 0)
        LOG(LOG_WARNING, errno, "setsockopt IP_MULTICAST_TTL %u", ttl);
#endif
    curttl = t;
    return curttl;
}

inline void k_set_loop(int l) {
    unsigned char loop = l;

    if (setsockopt(mrouterFD, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0)
        LOG(LOG_WARNING, errno, "setsockopt IP_MULTICAST_LOOP %u", loop);
}

inline void k_set_if(struct IfDesc *IfDp) {
    struct in_addr adr = { IfDp ? IfDp->InAdr.s_addr : INADDR_ANY };

    if (setsockopt(mrouterFD, IPPROTO_IP, IP_MULTICAST_IF, (char *)&adr, sizeof(adr)) < 0)
        LOG(LOG_WARNING, errno, "setsockopt IP_MULTICAST_IF %s", inetFmt(adr.s_addr, 1));
}

/**
*   Common function for joining or leaving a MCast group.
*/
static bool k_joinleave(int Cmd, struct IfDesc *IfDp, uint32_t mcastaddr) {
#if defined HAVE_STRUCT_GROUP_REQ_GR_INTERFACE
    struct group_req GrpReq;
 #ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    struct sockaddr_in Grp = { sizeof(struct sockaddr_in), AF_INET, 0, mcastaddr };
 #else
    struct sockaddr_in Grp = { AF_INET, 0, {mcastaddr}, {0} };
 #endif
    GrpReq.gr_interface = IfDp ? if_nametoindex(IfDp->Name) : 0;
    memcpy(&GrpReq.gr_group, &Grp, sizeof(Grp));
#else
    struct ip_mreq GrpReq;
    GrpReq.imr_multiaddr.s_addr = mcastaddr;
    GrpReq.imr_interface.s_addr = IfDp ? IfDp->InAdr.s_addr : (struct in_addr){ 0 };
#endif

    if (setsockopt(mrouterFD, IPPROTO_IP, Cmd == 'j' ? MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP, &GrpReq, sizeof(GrpReq)) < 0) {
        int mcastGroupExceeded = (Cmd == 'j' && errno == ENOBUFS);
        LOG(LOG_WARNING, errno, "MCAST_%s_GROUP %s on %s failed", Cmd == 'j' ? "JOIN" : "LEAVE",
                                 inetFmt(mcastaddr, 1), IfDp->Name)
;
        if (mcastGroupExceeded) {
            LOG(LOG_WARNING, 0, "Maximum number of multicast groups were exceeded");
#ifdef __linux__
            LOG(LOG_WARNING, 0, "Check settings of '/sbin/sysctl net.ipv4.igmp_max_memberships'");
#endif
        }
        return false;
    }

    return true;
}

/**
*   Joins the MC group with the address 'McAdr' on the interface 'IfName'.
*   The join is bound to the UDP socket 'udpSock', so if this socket is
*   closed the membership is dropped.
*/
inline bool k_joinMcGroup(struct IfDesc *IfDp, uint32_t mcastaddr) {
    bool r = k_joinleave('j', IfDp, mcastaddr);
    return r;
}

/**
*   Leaves the MC group with the address 'McAdr' on the interface 'IfName'.
*/
inline bool k_leaveMcGroup(struct IfDesc *IfDp, uint32_t mcastaddr) {
    bool r = k_joinleave('l', IfDp, mcastaddr);
    return r;
}

/**
*   Returns the mrouter FD.
*/
inline int k_getMrouterFD(void) {
    return mrouterFD;
}

/**
*   Initializes the mrouted API and locks it by this exclusively.
*/
int k_enableMRouter(void) {
    int Va = 1;

    if ((mrouterFD  = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0)
        LOG(LOG_ERR, errno, "IGMP socket open Failed");
    else if (setsockopt(mrouterFD, IPPROTO_IP, IP_HDRINCL, (void *)&Va, sizeof(Va)) < 0)
        LOG(LOG_ERR, errno, "IGMP socket IP_HDRINCL Failed");
    else if (setsockopt(mrouterFD, IPPROTO_IP, MRT_INIT, (void *)&Va, sizeof(Va)) < 0)
        LOG(LOG_ERR, errno, "IGMP socket MRT_INIT Failed");
    else if (setsockopt(mrouterFD, IPPROTO_IP, IFINFO, (void *)&Va, sizeof(Va)) < 0)
        LOG(LOG_ERR, errno, "IGMP socket IP_IFINFO Failed");
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
    if (((Va = MRT_MFC_BW_UPCALL) && setsockopt(mrouterFD, IPPROTO_IP, MRT_API_CONFIG, (void *)&Va, sizeof(Va)) < 0)
               || ! (Va & MRT_MFC_BW_UPCALL)) {
        LOG(LOG_WARNING, errno, "IGMP socket MRT_API_CONFIG Failed. Disabling bandwidth control.");
        CONFIG->bwControlInterval = 0;
    }
#endif
    fcntl(mrouterFD, F_SETFD, O_NONBLOCK);

    return mrouterFD;
}

/**
*   Disable the mrouted API and relases by this the lock.
*/
void k_disableMRouter(void) {
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DONE, NULL, 0) != 0 || close(mrouterFD) < 0)
        LOG(LOG_WARNING, errno, "MRT_DONE/close");

    mrouterFD = -1;
}

/**
*   Delete vif when removed from config or disappeared from system.
*/
void k_delVIF(struct IfDesc *IfDp) {
    struct vifctl vifCtl;

    if (IfDp->index == (uint8_t)-1) return;
    vifCtl.vifc_vifi = IfDp->index;

    LOG(LOG_NOTICE, 0, "removing VIF, Ix %d Fl 0x%x IP 0x%08x %s, Threshold: %d, Ratelimit: %d", IfDp->index,
                        IfDp->Flags, IfDp->InAdr.s_addr, IfDp->Name, IfDp->conf->threshold, IfDp->conf->ratelimit);
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_VIF, (char *)&vifCtl, sizeof(vifCtl)) < 0)
        LOG(LOG_WARNING, errno, "delVIF: Error removing VIF %d:%s", IfDp->index, IfDp->Name);

    // Reset vif index.
    IfDp->index = (uint8_t)-1;
}

/**
*   Adds the interface '*IfDp' as virtual interface to the mrouted API
*/
bool k_addVIF(struct IfDesc *IfDp) {
    struct vifctl  vifCtl;
    struct IfDesc *Dp = NULL;
    uint8_t        Ix = 0;
    uint32_t       vifBits = 0;

    // Find available vifindex.
    for (GETIFL(Dp)) if (Dp->index != (uint8_t)-1) BIT_SET(vifBits, Dp->index);
    while (Ix < MAXVIFS && (vifBits & (1 << Ix))) Ix++;
    if (Ix >= MAXVIFS) {
        LOG(LOG_WARNING, ENOMEM, "addVIF: out of VIF space");
        return false;
    } else
        IfDp->index = Ix;

    // Set the vif parameters, reset bw counters.
#ifdef HAVE_STRUCT_VIFCTL_VIFC_LCL_IFINDEX
    vifCtl = (struct vifctl){ Ix, 0, IfDp->conf->threshold, 0, {{IfDp->InAdr.s_addr}}, {INADDR_ANY} };
#else
    vifCtl = (struct vifctl){ Ix, 0, IfDp->conf->threshold, 0, {IfDp->InAdr.s_addr}, {INADDR_ANY} };
#endif
    IfDp->bytes = IfDp->rate = 0;

    // Log the VIF information.
    LOG(LOG_NOTICE, 0, "adding VIF %s, Ix %d, Fl 0x%x, IP %s, Threshold: %d, Ratelimit: %d", IfDp->Name, vifCtl.vifc_vifi,
                 vifCtl.vifc_flags, inetFmt(vifCtl.vifc_lcl_addr.s_addr, 1), vifCtl.vifc_threshold, IfDp->conf->ratelimit);
    for (struct filters *filter = IfDp->aliases; filter; filter = filter->next)
        LOG(LOG_DEBUG, 0, "        Network for [%s] : %s", IfDp->Name, inetFmts(filter->src.ip, filter->src.mask, 1));

    // Add the vif.
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_VIF, (char *)&vifCtl, sizeof(vifCtl)) < 0) {
        LOG(LOG_WARNING, errno, "addVIF: Error adding VIF %d:%s", IfDp->index, IfDp->Name);
        IfDp->index = (uint8_t)-1;
        return false;
    }

    return true;
}

/**
*   Adds the multicast routed '*Dp' to the kernel routes
*   Returns: - 0 if the function succeeds
*            - the errno value for non-fatal failure condition
*/
void k_addMRoute(uint32_t src, uint32_t group, int vif, uint8_t ttlVc[MAXVIFS]) {
    // Inialize the mfc control structure.
#ifdef HAVE_STRUCT_MFCCTL2_MFCC_TTLS
    struct mfcctl2 CtlReq = { {src}, {group}, vif, {0}, {0}, 0 };
#else
    struct mfcctl CtlReq = { {src}, {group}, vif, {0}, 0, 0, 0, 0 };
#endif
    memcpy(CtlReq.mfcc_ttls, ttlVc, sizeof(CtlReq.mfcc_ttls));

    // Add the mfc to the kernel.
    LOG(LOG_INFO, 0, "Adding MFC: %s -> %s, InpVIf: %d", inetFmt(CtlReq.mfcc_origin.s_addr, 1),
                      inetFmt(CtlReq.mfcc_mcastgrp.s_addr, 2), (int)CtlReq.mfcc_parent);
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_MFC, (void *)&CtlReq, sizeof(CtlReq)) < 0)
        LOG(LOG_WARNING, errno, "MRT_ADD_MFC %d - %s", vif, inetFmt(group, 1));
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
    if (CONFIG->bwControlInterval) {
        struct bw_upcall bwUpc = { {src}, {group}, BW_UPCALL_UNIT_BYTES | BW_UPCALL_LEQ, { {CONFIG->bwControlInterval, 0}, 0, (uint64_t)-1 }, { {0}, 0, 0 } };
        if (setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_BW_UPCALL, (void *)&bwUpc, sizeof(bwUpc)) < 0)
            LOG(LOG_WARNING, errno, "MRT_ADD_BW_UPCALL %d - %s", vif, inetFmt(group, 1));
        else
            LOG(LOG_DEBUG, 0, "Added BW_UPCALL: Src %s, Dst %s", inetFmt(bwUpc.bu_src.s_addr, 1), inetFmt(bwUpc.bu_dst.s_addr, 2));
    }
#endif
}

/**
*   Removes the multicast routed '*Dp' from the kernel routes
*   Returns: - 0 if the function succeeds
*            - the errno value for non-fatal failure condition
*/
void k_delMRoute(uint32_t src, uint32_t group, int vif) {
    // Inialize the mfc control structure.
#ifdef HAVE_STRUCT_MFCCTL2_MFCC_TTLS
    struct mfcctl2 CtlReq = { {src}, {group}, vif, {0}, {0}, 0 };
#else
    struct mfcctl CtlReq = { {src}, {group}, vif, {0}, 0, 0, 0, 0 };
#endif

    // Remove mfc from kernel.
    LOG(LOG_NOTICE, 0, "Removing MFC: %s -> %s, InpVIf: %d", inetFmt(CtlReq.mfcc_origin.s_addr, 1),
                        inetFmt(CtlReq.mfcc_mcastgrp.s_addr, 2), (int)CtlReq.mfcc_parent);
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_MFC, (void *)&CtlReq, sizeof(CtlReq)) < 0)
        LOG(LOG_WARNING, errno, "MRT_DEL_MFC %d - %s", vif, inetFmt(group, 1));
}

#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
/**
*   Delete all BW_UPCALLS for S,G
*/
void k_deleteUpcalls(uint32_t src, uint32_t group) {
    struct bw_upcall bwUpc = { {src}, {group}, BW_UPCALL_DELETE_ALL, { {0}, 0, 0 }, { {0}, 0, 0} };
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_BW_UPCALL, (void *)&bwUpc, sizeof(bwUpc)) < 0)
        LOG(LOG_NOTICE, 0, "Failed to delete BW upcall for Src %s, Dst %s.", inetFmt(src, 1), inetFmt(group, 2));
    else
        LOG(LOG_INFO, 0, "Deleted BW upcalls for Src %s, Dst %s.", inetFmt(src, 1), inetFmt(group, 2));
}
#endif
