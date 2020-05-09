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
*   mroute-api.c
*
*   This module contains the interface routines to the Linux mrouted API
*/


#include "igmpproxy.h"

// need an IGMP socket as interface for the mrouted API
// - receives the IGMP messages
int         MRouterFD;          /* socket for all network I/O  */
char        *recv_buf;          /* input packet buffer         */
char        *send_buf;          /* output packet buffer        */


// my internal virtual interfaces descriptor vector
struct VifDesc {
    struct IfDesc *IfDp;
    struct VifDesc *next;
}; 
struct VifDesc *VifDescVc = NULL;

/*
** Initialises the mrouted API and locks it by this exclusively.
**
** returns: - 0 if the functions succeeds
**          - the errno value for non-fatal failure condition
*/
int enableMRouter(void)
{
    int Va = 1;

    if ( (MRouterFD  = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0 )
        my_log( LOG_ERR, errno, "IGMP socket open" );

    if ( setsockopt( MRouterFD, IPPROTO_IP, MRT_INIT,
                     (void *)&Va, sizeof( Va ) ) )
        return errno;

    return 0;
}

/*
** Diable the mrouted API and relases by this the lock.
**
*/
void disableMRouter(void)
{
    if ( setsockopt( MRouterFD, IPPROTO_IP, MRT_DONE, NULL, 0 )
         || close( MRouterFD )
    ) {
        MRouterFD = 0;
        my_log( LOG_ERR, errno, "MRT_DONE/close" );
    }

    MRouterFD = 0;
}

/*
 * aimwang: delVIF()
 */
void delVIF( struct IfDesc *IfDp )
{
    struct vifctl VifCtl;
    struct VifDesc *VifDp, *FVifDp;

    if ((unsigned int)-1 == IfDp->index)
        return;

    VifCtl.vifc_vifi = IfDp->index;

    my_log(LOG_NOTICE, 0, "removing VIF, Ix %d Fl 0x%x IP 0x%08x %s, Threshold: %d, Ratelimit: %d",
         IfDp->index, IfDp->Flags, IfDp->InAdr.s_addr, IfDp->Name, IfDp->threshold, IfDp->ratelimit);

    if (setsockopt(MRouterFD, IPPROTO_IP, MRT_DEL_VIF, (char *)&VifCtl, sizeof(VifCtl))) {
        my_log( LOG_WARNING, errno, "MRT_DEL_VIF" );
    }

    // Remove Vif from list.
    if (VifDescVc->IfDp == IfDp) {
        FVifDp = VifDescVc;
        VifDescVc = VifDescVc->next;
    } else {
        for (VifDp = VifDescVc; VifDp->next && VifDp->next->IfDp != IfDp; VifDp = VifDp->next);
        FVifDp = VifDp->next;
        VifDp->next = VifDp->next->next;
    }
    free(FVifDp);   // Alloced by addVIF()
}

/*
** Adds the interface '*IfDp' as virtual interface to the mrouted API
**
*/
void addVIF(struct IfDesc *IfDp, struct IfDesc *oDp)
{
    struct vifctl VifCtl;
    struct VifDesc *VifDp, *NewVifDp;
    unsigned nrVif = 0, Ix = 0;

    // Search IfDescVc for available vif Ix and relink vifs during rebuild.
    for (VifDp = VifDescVc; VifDp; VifDp=VifDp->next, nrVif++) {
        if (oDp && VifDp->IfDp == oDp) {
            // Relink vifindex during rebuild or SIGHUP
            VifDp->IfDp = IfDp;
            VifDp->IfDp->index = oDp->index;
            my_log (LOG_DEBUG,0,"addVIF: relinking %s as vif Ix %d",VifDp->IfDp->Name, VifDp->IfDp->index);
            return;
        }
        if (VifDp->next) {
            // Middle of list if next Ix is free, set.
            if (VifDp->IfDp->index == nrVif && VifDp->IfDp->index < VifDp->next->IfDp->index - 1) {
                Ix = VifDp->IfDp->index + 1;
            }
        } else if (VifDp->IfDp->index == nrVif) {
            // List in order set Ix to next. Otherwise Ix is already set above (or 0 if available).
            Ix = nrVif + 1;
        }
    }

    // no more space
    if (nrVif >= MAXVIFS) {
        my_log(LOG_ERR, ENOMEM, "addVIF: out of VIF space");
    }

    // Allocate memory for new VifDesc. Freed by delVIF()
    NewVifDp = (struct VifDesc*)malloc(sizeof(struct VifDesc));
    if (! NewVifDp) {
        my_log(LOG_ERR, 0, "addVIF: Out of memory.");
    }
    NewVifDp->next = NULL;

    // Insert vif into the list at the correct spot.
    if (! VifDescVc) {
        // List is empty, new list.
        VifDescVc = NewVifDp;
    } else if (Ix == 0) {
        // Insert at begin of list.
        NewVifDp->next = VifDescVc;
        VifDescVc = NewVifDp;
    } else {
        // Find spot for Ix.
        for (VifDp = VifDescVc; VifDp->next && VifDp->next->IfDp->index < Ix; VifDp = VifDp->next);
        NewVifDp->next = VifDp->next;
        VifDp->next = NewVifDp;
    }

    // Set the index flags etc...
    NewVifDp->IfDp = IfDp;
    VifCtl.vifc_vifi = IfDp->index = Ix;
    VifCtl.vifc_flags = 0;        /* no tunnel, no source routing, register ? */
    VifCtl.vifc_threshold  = IfDp->threshold;    // Packet TTL must be at least 1 to pass them
    VifCtl.vifc_rate_limit = IfDp->ratelimit;    // Ratelimit

    VifCtl.vifc_lcl_addr.s_addr = IfDp->InAdr.s_addr;
    VifCtl.vifc_rmt_addr.s_addr = INADDR_ANY;

    my_log(LOG_NOTICE, 0, "adding VIF, Ix %d Fl 0x%x IP 0x%08x %s, Threshold: %d, Ratelimit: %d",
         VifCtl.vifc_vifi, VifCtl.vifc_flags,  VifCtl.vifc_lcl_addr.s_addr, IfDp->Name,
         VifCtl.vifc_threshold, VifCtl.vifc_rate_limit);

    struct SubnetList *currSubnet;
    for(currSubnet = IfDp->allowednets; currSubnet; currSubnet = currSubnet->next) {
        my_log(LOG_DEBUG, 0, "        Network for [%s] : %s", IfDp->Name, inetFmts(currSubnet->subnet_addr, currSubnet->subnet_mask, s1));
    }

    if (setsockopt(MRouterFD, IPPROTO_IP, MRT_ADD_VIF, (char *)&VifCtl, sizeof(VifCtl))) {
        my_log( LOG_ERR, errno, "MRT_ADD_VIF" );
    }
}

/*
** Adds the multicast routed '*Dp' to the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
int addMRoute( struct MRouteDesc *Dp )
{
    struct mfcctl CtlReq;
    int rc;

    CtlReq.mfcc_origin    = Dp->OriginAdr;
    CtlReq.mfcc_mcastgrp  = Dp->McAdr;
    CtlReq.mfcc_parent    = Dp->InVif;

    /* copy the TTL vector
     */

    memcpy( CtlReq.mfcc_ttls, Dp->TtlVc, sizeof( CtlReq.mfcc_ttls ) );

    {
        char FmtBuO[ 32 ], FmtBuM[ 32 ];

        my_log( LOG_NOTICE, 0, "Adding MFC: %s -> %s, InpVIf: %d",
             fmtInAdr( FmtBuO, CtlReq.mfcc_origin ),
             fmtInAdr( FmtBuM, CtlReq.mfcc_mcastgrp ),
             (int)CtlReq.mfcc_parent
           );
    }

    rc = setsockopt( MRouterFD, IPPROTO_IP, MRT_ADD_MFC,
                    (void *)&CtlReq, sizeof( CtlReq ) );
    if (rc)
        my_log( LOG_WARNING, errno, "MRT_ADD_MFC" );

    return rc;
}

/*
** Removes the multicast routed '*Dp' from the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
int delMRoute( struct MRouteDesc *Dp )
{
    struct mfcctl CtlReq;
    int rc;

    CtlReq.mfcc_origin    = Dp->OriginAdr;
    CtlReq.mfcc_mcastgrp  = Dp->McAdr;
    CtlReq.mfcc_parent    = Dp->InVif;

    /* clear the TTL vector
     */
    memset( CtlReq.mfcc_ttls, 0, sizeof( CtlReq.mfcc_ttls ) );

    {
        char FmtBuO[ 32 ], FmtBuM[ 32 ];

        my_log( LOG_NOTICE, 0, "Removing MFC: %s -> %s, InpVIf: %d",
             fmtInAdr( FmtBuO, CtlReq.mfcc_origin ),
             fmtInAdr( FmtBuM, CtlReq.mfcc_mcastgrp ),
             (int)CtlReq.mfcc_parent
           );
    }

    rc = setsockopt( MRouterFD, IPPROTO_IP, MRT_DEL_MFC,
                    (void *)&CtlReq, sizeof( CtlReq ) );
    if (rc)
        my_log( LOG_WARNING, errno, "MRT_DEL_MFC" );

    return rc;
}
