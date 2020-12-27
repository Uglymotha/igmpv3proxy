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
/**
*   This module contains the interface routines to the mrouted API
*/

#include "igmpproxy.h"

static int mrouterFD = -1;

/**
*   Returns the mrouter FD.
*/
int getMrouterFD(void) {
    return mrouterFD;
}

/**
*   Initializes the mrouted API and locks it by this exclusively.
*/
int enableMRouter(void) {
    int Va = 1;

    if ((mrouterFD  = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0) myLog(LOG_ERR, errno, "IGMP socket open Failed");
    else if (setsockopt(mrouterFD, IPPROTO_IP, IP_HDRINCL, (void *)&Va, sizeof(Va)) != 0) myLog(LOG_ERR, errno, "IGMP socket IP_HDRINCL Failed");
    else if (setsockopt(mrouterFD, IPPROTO_IP, MRT_INIT, (void *)&Va, sizeof(Va)) != 0) myLog(LOG_ERR, errno, "IGMP socket MRT_INIT Failed");
    else if (setsockopt(mrouterFD, IPPROTO_IP, IFINFO, (void *)&Va, sizeof(Va)) != 0) myLog(LOG_ERR, errno, "IGMP socket IP_IFINFO Failed");
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
    if (((Va = MRT_MFC_BW_UPCALL) && setsockopt(mrouterFD, IPPROTO_IP, MRT_API_CONFIG, (void *)&Va, sizeof(Va)) != 0) || ! (Va & MRT_MFC_BW_UPCALL)) {
        myLog(LOG_WARNING, errno, "IGMP socket MRT_API_CONFIG Failed. Disabling bandwidth control.");
        CONFIG->bwControlInterval = 0;
    }
#endif
    fcntl(mrouterFD, F_SETFD, O_NONBLOCK);

    return mrouterFD;
}

/**
*   Disable the mrouted API and relases by this the lock.
*/
void disableMRouter(void) {
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DONE, NULL, 0) != 0 || close(mrouterFD) != 0) myLog(LOG_ERR, errno, "MRT_DONE/close");

    mrouterFD = -1;
}

/**
*   Delete vif when removed from config or disappeared from system.
*/
void delVIF(struct IfDesc *IfDp) {
    struct vifctl vifCtl;

    if (IfDp->index == (unsigned int)-1) return;
    vifCtl.vifc_vifi = IfDp->index;

    myLog(LOG_NOTICE, 0, "removing VIF, Ix %d Fl 0x%x IP 0x%08x %s, Threshold: %d, Ratelimit: %d", IfDp->index, IfDp->Flags, IfDp->InAdr.s_addr, IfDp->Name, IfDp->threshold, IfDp->ratelimit);
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_VIF, (char *)&vifCtl, sizeof(vifCtl)) != 0) myLog(LOG_WARNING, errno, "delVIF: Error removing VIF %d:%s", IfDp->index, IfDp->Name);

    // Reset vif index.
    IfDp->index = (unsigned int)-1;
}

/**
*   Adds the interface '*IfDp' as virtual interface to the mrouted API
*/
bool addVIF(struct IfDesc *IfDp) {
    struct vifctl  vifCtl;
    struct IfDesc *Dp = NULL;
    unsigned int   Ix = 0;
    uint32_t       vifBits = 0;

    // Find available vifindex.
    for (GETIFL(Dp)) if (Dp->index != (unsigned int)-1) BIT_SET(vifBits, Dp->index);
    while (Ix < MAXVIFS && (vifBits & (1 << Ix))) Ix++;
    if (Ix >= MAXVIFS) {
        myLog(LOG_WARNING, ENOMEM, "addVIF: out of VIF space");
        return false;
    } else IfDp->index = Ix;

    // Set the vif parameters, reset bw counters.
#ifdef HAVE_STRUCT_VIFCTL_VIFC_LCL_IFINDEX
    vifCtl = (struct vifctl){ Ix, 0, IfDp->threshold, 0, {{IfDp->InAdr.s_addr}}, {INADDR_ANY} };
#else
    vifCtl = (struct vifctl){ Ix, 0, IfDp->threshold, 0, {IfDp->InAdr.s_addr}, {INADDR_ANY} };
#endif
    IfDp->bytes = IfDp->rate = 0;

    // Log the VIF information.
    myLog(LOG_NOTICE, 0, "adding VIF %s, Ix %d, Fl 0x%x, IP %s, Threshold: %d, Ratelimit: %d", IfDp->Name, vifCtl.vifc_vifi, vifCtl.vifc_flags, inetFmt(vifCtl.vifc_lcl_addr.s_addr, 1), vifCtl.vifc_threshold, IfDp->ratelimit);
    for (struct filters *filter = IfDp->aliases; filter; filter = filter->next) myLog(LOG_DEBUG, 0, "        Network for [%s] : %s", IfDp->Name, inetFmts(filter->src.ip, filter->src.mask, 1));

    // Add the vif.
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_VIF, (char *)&vifCtl, sizeof(vifCtl)) != 0) {
        myLog(LOG_WARNING, errno, "addVIF: Error adding VIF %d:%s", IfDp->index, IfDp->Name);
        IfDp->index = (unsigned int)-1;
        return false;
    }

    return true;
}

/**
*   Adds the multicast routed '*Dp' to the kernel routes
*   Returns: - 0 if the function succeeds
*            - the errno value for non-fatal failure condition
*/
int addMRoute(uint32_t src, uint32_t group, int vif, uint8_t ttlVc[MAXVIFS]) {
    int            rc;

    // Inialize the mfc control structure.
#ifdef HAVE_STRUCT_MFCCTL2_MFCC_TTLS
    struct mfcctl2 CtlReq = { {src}, {group}, vif, {0}, {0}, 0 };
#else
    struct mfcctl CtlReq = { {src}, {group}, vif, {0}, 0, 0, 0, 0 };
#endif
    memcpy(CtlReq.mfcc_ttls, ttlVc, sizeof(CtlReq.mfcc_ttls));

    // Add the mfc to the kernel.
    myLog(LOG_INFO, 0, "Adding MFC: %s -> %s, InpVIf: %d", fmtInAdr(CtlReq.mfcc_origin, 1), fmtInAdr(CtlReq.mfcc_mcastgrp, 2), (int)CtlReq.mfcc_parent);
    if ((rc = setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_MFC, (void *)&CtlReq, sizeof(CtlReq)))) myLog(LOG_WARNING, errno, "MRT_ADD_MFC %d - %s", vif, inetFmt(group, 1));
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
    if (CONFIG->bwControlInterval) {
        struct bw_upcall bwUpc = { {src}, {group}, BW_UPCALL_UNIT_BYTES | BW_UPCALL_LEQ, { {CONFIG->bwControlInterval, 0}, 0, (uint64_t)-1 }, { {0}, 0, 0 } };
        if (setsockopt(mrouterFD, IPPROTO_IP, MRT_ADD_BW_UPCALL, (void *)&bwUpc, sizeof(bwUpc))) myLog(LOG_WARNING, errno, "MRT_ADD_BW_UPCALL %d - %s", vif, inetFmt(group, 1));
        else myLog(LOG_DEBUG, 0, "Added BW_UPCALL: Src %s, Dst %s", inetFmt(bwUpc.bu_src.s_addr, 1), inetFmt(bwUpc.bu_dst.s_addr, 2));
    }
#endif

    return rc;
}

/**
*   Removes the multicast routed '*Dp' from the kernel routes
*   Returns: - 0 if the function succeeds
*            - the errno value for non-fatal failure condition
*/
int delMRoute(uint32_t src, uint32_t group, int vif) {
    int rc;

    // Inialize the mfc control structure.
#ifdef HAVE_STRUCT_MFCCTL2_MFCC_TTLS
    struct mfcctl2 CtlReq = { {src}, {group}, vif, {0}, {0}, 0 };
#else
    struct mfcctl CtlReq = { {src}, {group}, vif, {0}, 0, 0, 0, 0 };
#endif

    // Remove mfc from kernel.
    myLog(LOG_NOTICE, 0, "Removing MFC: %s -> %s, InpVIf: %d", fmtInAdr(CtlReq.mfcc_origin, 1), fmtInAdr(CtlReq.mfcc_mcastgrp, 2), (int)CtlReq.mfcc_parent);
    if ((rc = setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_MFC, (void *)&CtlReq, sizeof(CtlReq)))) myLog(LOG_WARNING, errno, "MRT_DEL_MFC %d - %s", vif, inetFmt(group, 1));

    return rc;
}

#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
/**
*   Delete all BW_UPCALLS for S,G
*/
void deleteUpcalls(uint32_t src, uint32_t group) {
    struct bw_upcall bwUpc = { {src}, {group}, BW_UPCALL_DELETE_ALL, { {0}, 0, 0 }, { {0}, 0, 0} };
    if (setsockopt(mrouterFD, IPPROTO_IP, MRT_DEL_BW_UPCALL, (void *)&bwUpc, sizeof(bwUpc)) != 0) myLog(LOG_INFO, 0, "Failed to delete BW upcall for Src %s, Dst %s.", inetFmt(src, 1), inetFmt(group, 2));
    else myLog(LOG_INFO, 0, "Deleted BW upcalls for Src %s, Dst %s.", inetFmt(src, 1), inetFmt(group, 2));
}
#endif
