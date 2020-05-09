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

static int curttl = 0;
static bool k_joinleave(int Cmd, struct IfDesc *IfDp, uint32_t mcastaddr);

/**
*   Set the socket buffer.  If we can't set it as large as we want, search around to try to find the highest acceptable
*   value.  The highest acceptable value being smaller than minsize is a fatal error.
*/
void k_set_rcvbuf(int bufsize, int minsize) {
    int delta = bufsize / 2;
    int iter = 0;

    if (setsockopt(getMrouterFD(), SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
        bufsize -= delta;
        while (1) {
            iter++;
            if (delta > 1) {
                delta /= 2;
            }

            if (setsockopt(getMrouterFD(), SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
                if (bufsize < minsize) {
                    my_log(LOG_ERR, 0, "OS-allowed buffer size %u < app min %u",  bufsize, minsize);
                }
                bufsize -= delta;
            } else {
                if (delta < 1024) {
                    break;
                }
                bufsize += delta;
            }
        }
    }

    my_log(LOG_DEBUG, 0, "Got %d byte buffer size in %d iterations", bufsize, iter);
}

int k_set_ttl(int t) {
#ifndef RAW_OUTPUT_IS_RAW
    unsigned char ttl = t;

    if (setsockopt(getMrouterFD(), IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) < 0) {
        my_log(LOG_WARNING, errno, "setsockopt IP_MULTICAST_TTL %u", ttl);
    }
#endif
    curttl = t;
    return curttl;
}

void k_set_loop(int l) {
    unsigned char loop = l;

    if (setsockopt(getMrouterFD(), IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0) {
        my_log(LOG_WARNING, errno, "setsockopt IP_MULTICAST_LOOP %u", loop);
    }
}

void k_set_if(struct IfDesc *IfDp) {
    struct in_addr adr = { IfDp ? IfDp->InAdr.s_addr : INADDR_ANY };

    if (setsockopt(getMrouterFD(), IPPROTO_IP, IP_MULTICAST_IF, (char *)&adr, sizeof(adr)) < 0) {
        my_log(LOG_WARNING, errno, "setsockopt IP_MULTICAST_IF %s", inetFmt(adr.s_addr, 1));
    }
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
    GrpReq.imr_interface = IfDp ? IfDp->InAdr : (struct in_addr){ 0 };
#endif

    if (setsockopt(getMrouterFD(), IPPROTO_IP, Cmd == 'j' ? MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP, &GrpReq, sizeof(GrpReq))) {
        int mcastGroupExceeded = (Cmd == 'j' && errno == ENOBUFS);
        my_log(LOG_WARNING, errno, "MCAST_%s_GROUP %s on %s failed", Cmd == 'j' ? "JOIN" : "LEAVE", inetFmt(mcastaddr, 1), IfDp->Name)
;
        if (mcastGroupExceeded) {
            my_log(LOG_WARNING, 0, "Maximum number of multicast groups were exceeded");
#ifdef __linux__
            my_log(LOG_WARNING, 0, "Check settings of '/sbin/sysctl net.ipv4.igmp_max_memberships'");
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
bool k_joinMcGroup(struct IfDesc *IfDp, uint32_t mcastaddr) {
    bool r = k_joinleave('j', IfDp, mcastaddr);
    return r;
}

/**
*   Leaves the MC group with the address 'McAdr' on the interface 'IfName'.
*/
bool k_leaveMcGroup(struct IfDesc *IfDp, uint32_t mcastaddr) {
    bool r = k_joinleave('l', IfDp, mcastaddr);
    return r;
}
