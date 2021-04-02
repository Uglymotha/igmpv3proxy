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
*   igmp.c - Implements RFC3376 IGMPv3.
*/

#include "igmpproxy.h"
#include "igmpv3.h"

// Local prototypes.
static void sendIgmp(struct IfDesc *IfDp, struct igmpv3_grec *query);
static bool checkIgmp(struct IfDesc *IfDp, register uint32_t group, register uint8_t ifstate);
static void expireQuerierTimer(struct IfDesc *IfDp);
static void acceptGeneralMemberQuery(struct IfDesc *IfDp, uint32_t src, struct igmpv3_query *igmpv3, int ipdatalen);

// Global statics for common IGMP groups.
uint32_t    allhosts_group;            // All hosts addr in net order
uint32_t    allrouters_group;          // All hosts addr in net order
uint32_t    alligmp3_group;            // IGMPv3 addr in net order

// Buffers for sending and receiving IGMP packets.
static char recv_buf[BUF_SIZE];        // input packet buffer
static char send_buf[BUF_SIZE];        // output packet buffer
static char msg[TMNAMESZ];
static int  curttl = 1;

// Keep list of groupvifdescs for group specific queries.
struct gvDescL *qgvDescL = NULL;

/**
*   Open and initialize the igmp socket, and fill in the non-changing IP header fields in the output packet buffer.
*   Returns pointer to the receive buffer.
*/
char *initIgmp(void) {
    struct ip *ip = (struct ip *)send_buf;
    memset(ip, 0, sizeof(struct ip));

    k_set_rcvbuf(256*1024,48*1024); // lots of input buffering
    curttl = k_set_ttl(1);          // restrict multicasts to one hop
    k_set_loop(false);              // disable multicast loopback

    /*
     * Fields zeroed that aren't filled in later:
     * - IP ID (let the kernel fill it in)
     * - Offset (we don't send fragments)
     * - Checksum (let the kernel fill it in)
     */
    ip->ip_v   = IPVERSION;
    ip->ip_hl  = (sizeof(struct ip) + 4) >> 2; // +4 for Router Alert option
    ip->ip_tos = 0xc0;                         // Internet Control
    ip->ip_ttl = MAXTTL;                       // applies to unicasts only
    ip->ip_p   = IPPROTO_IGMP;
    /* Add Router Alert option */
    ((unsigned char*)send_buf + MIN_IP_HEADER_LEN)[0] = IPOPT_RA;
    ((unsigned char*)send_buf + MIN_IP_HEADER_LEN)[1] = 0x04;
    ((unsigned char*)send_buf + MIN_IP_HEADER_LEN)[2] = 0x00;
    ((unsigned char*)send_buf + MIN_IP_HEADER_LEN)[3] = 0x00;


    allhosts_group   = htonl(INADDR_ALLHOSTS_GROUP);
    allrouters_group = htonl(INADDR_ALLRTRS_GROUP);
    alligmp3_group   = htonl(INADDR_ALLIGMPV3_GROUP);

    return recv_buf;
}

/**
*   Finds the textual name of the supplied IGMP request.
*/
static const char *igmpPacketKind(unsigned int type, unsigned int code) {
    static char unknown[20];

    switch (type) {
    case IGMP_MEMBERSHIP_QUERY:      return "Membership query  ";
    case IGMP_V1_MEMBERSHIP_REPORT:  return "V1 member report  ";
    case IGMP_V2_MEMBERSHIP_REPORT:  return "V2 member report  ";
    case IGMP_V3_MEMBERSHIP_REPORT:  return "V3 member report  ";
    case IGMP_V2_LEAVE_GROUP:        return "Leave message     ";

    default:
        sprintf(unknown, "unk: 0x%02x/0x%02x    ", type, code);
        return unknown;
    }
}

/**
*  Checks if request is valid.
*/
static bool checkIgmp(struct IfDesc *IfDp, register uint32_t group, register uint8_t ifstate) {
    bool res = false;
    // Sanitycheck the group adress...
    if (! IN_MULTICAST(ntohl(group)))
        myLog(LOG_WARNING, 0, "checkGrpRec: The group address %s is not a valid Multicast group. Ignoring", inetFmt(group, 1));
    /* filter local multicast 224.0.0.0/8 */
    else if (! CONFIG->proxyLocalMc && ((htonl(group) & 0xFFFFFF00) == 0xE0000000))
        myLog(LOG_NOTICE, 0, "checkGrpRec: The IGMP message to %s was local multicast and proxylocalmc is not set. Ignoring.", inetFmt(group, 1));
    else if ((IfDp->state & ifstate) == 0) {
        strcat(strcpy(msg, ""), IS_UPSTREAM(IfDp->state) ? "upstream interface " : IS_DOWNSTREAM(IfDp->state) ? "downstream interface " : "disabled interface ");
        myLog(LOG_INFO, 0, "checkGrpRec: Message was received on %s. Ignoring.", strcat(msg, IfDp->Name));
    } else
        res = true;

    return res;
}

/**
*   Process a newly received IGMP packet that is sitting in the input packet buffer.
*/
void acceptIgmp(int recvlen, struct msghdr msgHdr) {
    char               ifName[IF_NAMESIZE];
    struct ip         *ip = (struct ip *)recv_buf;
    register uint32_t  src = ip->ip_src.s_addr, dst = ip->ip_dst.s_addr;
    register int       ipdatalen = IPDATALEN, iphdrlen = ip->ip_hl << 2, ngrec, ifindex = 0;
    struct igmp       *igmp = (struct igmp *)(recv_buf + iphdrlen);
    struct cmsghdr    *cmsgPtr;
    struct IfDesc     *IfDp = NULL;

    // Handle kernel upcall messages first.
    if (ip->ip_p == 0) {
        struct igmpmsg *igmpMsg = (struct igmpmsg *)(recv_buf);
        if (! (IfDp = getIfByIx(igmpMsg->im_vif)))
            return;
        switch (igmpMsg->im_msgtype) {
        case IGMPMSG_NOCACHE:
            if (checkIgmp(IfDp, dst, IF_STATE_UPSTREAM))
                activateRoute(IfDp, src, dst);
            return;
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        case IGMPMSG_BW_UPCALL:
            if (CONFIG->bwControlInterval)
                processBwUpcall((struct bw_upcall *)(recv_buf + sizeof(struct igmpmsg)), ((recvlen - sizeof(struct igmpmsg)) / sizeof(struct bw_upcall)));
            return;
#endif
#ifdef IGMPMSG_WRONGVIF
        case IGMPMSG_WRONGVIF:
            myLog(LOG_NOTICE, 0, "Received WRONGVIF Upcall for Src %s Dst %s on %s.", inetFmt(igmpMsg->im_src.s_addr, 1), inetFmt(igmpMsg->im_dst.s_addr, 2), IfDp->Name);
            return;
#endif
        default:
            myLog(LOG_NOTICE, 0, "Received unsupported upcall %d.", igmpMsg->im_msgtype);
            return;
        }
    }

    //  Get the source interface from the control message.
    for (cmsgPtr = CMSG_FIRSTHDR(&msgHdr); cmsgPtr; cmsgPtr = CMSG_NXTHDR(&msgHdr, cmsgPtr)) {
        if (cmsgPtr->cmsg_level == IPPROTO_IP && cmsgPtr->cmsg_type == IFINFO) {
#ifdef IP_PKTINFO
            struct in_pktinfo *inp = (struct in_pktinfo *)CMSG_DATA(cmsgPtr);
            ifindex = inp->ipi_ifindex;
#elif IP_RECVIF
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)CMSG_DATA(cmsgPtr);
            ifindex = sdl->sdl_index;
#endif
            IfDp = getIfByName(if_indextoname(ifindex, ifName));
            break;
        }
    }

    // Sanity check the request, only allow requests for valid interface, valid src & dst and no corrupt packets.
    register uint16_t cksum = igmp->igmp_cksum;
    igmp->igmp_cksum = 0;
    if (! IfDp)
        myLog(LOG_NOTICE, 0, "acceptIgmp: No valid interface found for src: %s dst: %s on %s", inetFmt(src, 1), inetFmt(dst, 2), ifindex ? ifName : "unk");
    else if (src == IfDp->InAdr.s_addr || (IfDp->querier.ip == IfDp->conf->qry.ip && src == IfDp->querier.ip))
        myLog(LOG_NOTICE, 0, "acceptIgmp: The request from: %s for: %s on: %s is from myself. Ignoring.", inetFmt(src, 1), inetFmt(dst, 2), IfDp->Name);
    else if (src == 0xFFFFFFFF || dst == 0 || dst == 0xFFFFFFFF)
        myLog(LOG_NOTICE, 0, "acceptIgmp: The request from: %s for: %s on: %s is invalid. Ignoring.", inetFmt(src, 1), inetFmt(dst, 2), IfDp->Name);
    else if (iphdrlen + ipdatalen != recvlen)
        myLog(LOG_WARNING, 0, "acceptIgmp: received packet from %s shorter (%u bytes) than hdr+data length (%u+%u)", inetFmt(src, 1), recvlen, iphdrlen, ipdatalen);
    else if ((ipdatalen < IGMP_MINLEN) || (igmp->igmp_type == IGMP_V3_MEMBERSHIP_REPORT && ipdatalen <= IGMPV3_MINLEN))
        myLog(LOG_WARNING, 0, "acceptIgmp: received IP data field too short (%u bytes) for IGMP, from %s", ipdatalen, inetFmt(src, 1));
    else if (cksum != inetChksum((uint16_t *)igmp, ipdatalen))
        myLog(LOG_WARNING, 0, "acceptIgmp: Received packet from: %s for: %s on: %s checksum incorrect.", inetFmt(src, 1), inetFmt(dst, 2), IfDp->Name);
    else {
        struct igmpv3_query  *igmpv3   = (struct igmpv3_query *)(recv_buf + iphdrlen);
        struct igmpv3_report *igmpv3gr = (struct igmpv3_report *)(recv_buf + iphdrlen);
        struct igmpv3_grec   *grec     = &igmpv3gr->igmp_grec[0];
        myLog(LOG_DEBUG, 0, "RECV %s from %-15s to %s", igmpPacketKind(igmp->igmp_type, igmp->igmp_code), inetFmt(src, 1), inetFmt(dst, 2) );

        switch (igmp->igmp_type) {
        case IGMP_V1_MEMBERSHIP_REPORT:
        case IGMP_V2_LEAVE_GROUP:
        case IGMP_V2_MEMBERSHIP_REPORT:
            if (checkIgmp(IfDp, igmp->igmp_group.s_addr, IF_STATE_DOWNSTREAM))
                updateRoute(IfDp, src, igmp);
            return;

        case IGMP_V3_MEMBERSHIP_REPORT:
            ngrec = ntohs(igmpv3gr->igmp_ngrec);
            while (ngrec-- && (uint8_t *)igmpv3gr + ipdatalen >= (uint8_t *)grec + sizeof(*grec)) {
                if (grec->grec_type < 1 || grec->grec_type > 6)
                    myLog(LOG_NOTICE, 0, "ignoring unknown IGMPv3 group record type %x from %s to %s for %s", grec->grec_type, inetFmt(src, 1), inetFmt(dst, 2), inetFmt(grec->grec_mca.s_addr, 3));
                else if (checkIgmp(IfDp, grec->grec_mca.s_addr, IF_STATE_DOWNSTREAM))
                    updateRoute(IfDp, src, grec);
                grec = (struct igmpv3_grec *)(&grec->grec_src[grec->grec_nsrcs] + grec->grec_auxwords * 4);
            }
            return;

        case IGMP_MEMBERSHIP_QUERY:
            if (dst == allhosts_group && CONFIG->querierElection && IfDp->conf->qry.election && !IS_DISABLED(IfDp->state))
                acceptGeneralMemberQuery(IfDp, src, igmpv3, ipdatalen);
            return;

        default:
            myLog(LOG_DEBUG, 0, "ignoring unknown IGMP message type %x from %s to %s", igmp->igmp_type, inetFmt(src, 1), inetFmt(dst, 2));
            return;
        }
    }
}

/**
*   Construct an IGMP query message in the output packet buffer and send it.
*/
static void sendIgmp(struct IfDesc *IfDp, struct igmpv3_grec *grec) {
    struct ip           *ip = (struct ip *)send_buf;
    struct igmpv3_query *igmpv3 = (struct igmpv3_query *)(send_buf + IP_HEADER_RAOPT_LEN);
    struct sockaddr_in   sdst;
    int                  len = 0, setloop = 0, setigmpsource = 0;
    memset(igmpv3, 0, sizeof(struct igmpv3_query));
    memset(&sdst, 0, sizeof(struct sockaddr_in));
    sdst.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sdst.sin_len = sizeof(sdst);
#endif

    // Set IP / IGMP packet data.
    ip->ip_src.s_addr  = IfDp->querier.ip;
    ip->ip_dst.s_addr  = sdst.sin_addr.s_addr = grec ? grec->grec_mca.s_addr : allhosts_group;
    igmpv3->igmp_type         = IGMP_MEMBERSHIP_QUERY;
    igmpv3->igmp_code         = IfDp->querier.ver == 1 ? 0 : grec ? IfDp->conf->qry.lmInterval : IfDp->querier.mrc;
    igmpv3->igmp_group.s_addr = grec ? grec->grec_mca.s_addr : 0;
    igmpv3->igmp_misc         = (grec && grec->grec_type == 1 ? 0x8 : 0) + IfDp->querier.qrv;    // When sending 1st group and source specific query, set router suppress flag.
    igmpv3->igmp_qqi          = grec ? IfDp->conf->qry.lmInterval : IfDp->querier.qqi;

    if (grec && grec->grec_nsrcs > 0) {
        for (int i = 0; i < grec->grec_nsrcs; igmpv3->igmp_sources[i] = grec->grec_src[i], i++);
        igmpv3->igmp_numsrc = grec->grec_nsrcs;
    }

    // Set packet length and calculate checksum.
    len = IP_HEADER_RAOPT_LEN + (IfDp->querier.ver != 3 ? 8 : IGMPV3_MINLEN + (igmpv3->igmp_numsrc * sizeof(struct in_addr)));
    igmpv3->igmp_cksum        = inetChksum((uint16_t *)igmpv3, len);

    if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
        ip->ip_ttl = curttl;
        k_set_if(IfDp);
        setigmpsource = 1;
        if (igmpv3->igmp_type != IGMP_DVMRP || ip->ip_dst.s_addr == allhosts_group) {
            setloop = 1;
            k_set_loop(true);
        }
    } else
        ip->ip_ttl = MAXTTL;

    IPSETLEN;
    if (sendto(MROUTERFD, send_buf, len, MSG_DONTWAIT, (struct sockaddr *)&sdst, sizeof(sdst)) < 0)
        myLog(LOG_WARNING, errno, "sendIGMP: from %s to %s (%d) on %s", inetFmt(IfDp->querier.ip, 2), inetFmt(ip->ip_dst.s_addr, 1), len, IfDp->Name);

    if (setigmpsource) {
        if (setloop) k_set_loop(false);
        // Restore original...
        k_set_if(NULL);
    }

    myLog(LOG_DEBUG, 0, "sendIGMP: %s from %-15s to %s (%d:%d:%d)", igmpPacketKind(igmpv3->igmp_type, igmpv3->igmp_code), IfDp->querier.ip == INADDR_ANY ? "INADDR_ANY" : inetFmt(IfDp->querier.ip, 1), inetFmt(ip->ip_dst.s_addr, 2), igmpv3->igmp_code, igmpv3->igmp_misc, igmpv3->igmp_qqi);
}

/**
*   Function to control the IGMP querier process on interfaces.
*/
void ctrlQuerier(int start, struct IfDesc *IfDp) {
    if (! start || start == 2) {
        // Remove all timers and reset all IGMP status.
        if (IS_DOWNSTREAM(IfDp->state) || IS_DISABLED(IfDp->state)) {
            k_leaveMcGroup(IfDp, allrouters_group);
            k_leaveMcGroup(IfDp, alligmp3_group);
        }
        timer_clearTimer(IfDp->querier.Timer);
        timer_clearTimer(IfDp->querier.ageTimer);
        memset(&IfDp->querier, 0, sizeof(struct querier));
        IfDp->querier.ip = (uint32_t)-1;
        if (!IS_DOWNSTREAM(IfDp->state)) IfDp->conf->qry.ver = 3;
    }
    if (start && IS_DOWNSTREAM(IfDp->state)) {
        // Join all routers groups and start querier process on new downstream interfaces.
        k_joinMcGroup(IfDp, allrouters_group);
        k_joinMcGroup(IfDp, alligmp3_group);
        uint16_t interval = IfDp->conf->qry.ver == 3 ? getIgmpExp(IfDp->conf->qry.interval, 0) : IfDp->conf->qry.ver == 2 ? IfDp->conf->qry.interval : 10;
        IfDp->conf->qry.startupQueryInterval = interval > 4 ? (IfDp->conf->qry.ver == 3 ? getIgmpExp(interval / 4, 1) : interval / 4) : 1;
        IfDp->conf->qry.startupQueryCount = IfDp->conf->qry.robustness;
        sendGeneralMemberQuery(IfDp);
    }
}

/**
*   Processes a received general membership query and updates igmp timers for the interface.
*/
static void acceptGeneralMemberQuery(struct IfDesc *IfDp, uint32_t src, struct igmpv3_query *igmpv3, int ipdatalen) {
    int       ver = ipdatalen >= IGMPV3_MINLEN ? 3 : igmpv3->igmp_code == 0 ? 1 : 2,
              timeout = IfDp->querier.ver == 3 ? (((getIgmpExp(igmpv3->igmp_qqi, 1) * (igmpv3->igmp_misc & 0x07)) * 10) + getIgmpExp(igmpv3->igmp_code, 1) / 2) : ver == 2 ? (((IfDp->conf->qry.interval * IfDp->conf->qry.robustness) * 10) + igmpv3->igmp_code / 2) : ((100 * IfDp->conf->qry.robustness) + 5);

    // Set ageing and other querier timer.
    if (ver < IfDp->querier.ver || (ver == IfDp->querier.ver && (htonl(src) <= htonl(IfDp->querier.ip)))) {
        IfDp->querier = (struct querier){ src, ver, ver == 3 ? (igmpv3->igmp_qqi > 0 ? igmpv3->igmp_qqi : DEFAULT_INTERVAL_QUERY) : IfDp->conf->qry.interval, ver == 3 ? ((igmpv3->igmp_misc & 0x7) > 0 ? igmpv3->igmp_misc & 0x7 : DEFAULT_ROBUSTNESS) : IfDp->conf->qry.robustness, ver != 1 ? igmpv3->igmp_code : 10, IfDp->querier.Timer, IfDp->querier.ageTimer };
        if (IS_DOWNSTREAM(IfDp->state)) IfDp->querier.ageTimer = timer_setTimer(IfDp->querier.ageTimer, TDELAY(ver == 3 ? getIgmpExp(igmpv3->igmp_code, 1) : ver ==  2 ? igmpv3->igmp_code : 10), strcat(strcpy(msg, "Age Active Routes: "), IfDp->Name), (timer_f)ageRoutes, IfDp);
        sprintf(msg, "%sv%1d Querier Timer: ", IS_DOWNSTREAM(IfDp->state) ? "Other " : "", ver);
        IfDp->querier.Timer = timer_setTimer(IfDp->querier.Timer, TDELAY(timeout), strcat(msg, IfDp->Name), (timer_f)expireQuerierTimer, IfDp);
        myLog(LOG_INFO, 0, "Detected %sv%d IGMP querier %s (%d:%d:%d) on %s. Setting Timer for %ds.", IS_DOWNSTREAM(IfDp->state) ? "other " : "", ver, inetFmt(src, 1), IfDp->querier.qqi, IfDp->querier.mrc, IfDp->querier.qrv, IfDp->Name, timeout / 10);
    } else myLog(LOG_DEBUG, 0, "Received IGMP v%d general membership query from %s on %s, but it does not have priority over %s. Ignoring", ver, inetFmt(src, 1), IfDp->Name, IfDp->querier.ip == IfDp->conf->qry.ip ? "us" : inetFmt(IfDp->querier.ip, 2));
}

/**
*   Sends a group specific member report query until the group times out.
*/
void sendGSQ(void *query) {
    struct igmpv3_grec *grec = query;
    struct IfDesc      *IfDp = getIfByName((char *)&grec->grec_src[grec->grec_nsrcs]);
    if (! IfDp) {
        myLog(LOG_WARNING, 0, "Requested to send GSQ for %s with %d sources, but interface %s not found.", inetFmt(grec->grec_mca.s_addr, 1), grec->grec_nsrcs, &grec->grec_src[grec->grec_nsrcs]);
        return;
    }

    // Send GSQ for all active sources and return.
    if (grec->grec_type == 1) {
        sendIgmp(IfDp, grec);
        free(grec);   // Alloced by updateRoute()
        return;
    }

    // Do aging upon reentry.
    if (grec->grec_auxwords > 0)
        ageRoutes(IfDp, 0);

    // Send query and set timeout for next round...
    if (grec->grec_auxwords++ < IfDp->conf->qry.lmCount) {
        sendIgmp(IfDp, grec);
        sprintf(msg, "GSQ: %s - %s", inetFmt(grec->grec_mca.s_addr, 1), IfDp->Name);
        timer_setTimer(0, TDELAY(IfDp->querier.ver == 3 ? getIgmpExp(IfDp->conf->qry.lmInterval, 0) : IfDp->conf->qry.lmInterval), msg, (timer_f)sendGSQ, grec);
    } else
        free(grec);   // Alloced by updateRoute()
}

/**
*   Sends a general membership query on downstream VIFs
*/
void sendGeneralMemberQuery(struct IfDesc *IfDp) {
    // Only query interface if set regardless of querier status. If it is downstream of course.
    if (!IS_DOWNSTREAM(IfDp->state)) {
        myLog(LOG_INFO, 0, "Requested to send a query on %s, but it is %s. Query not sent.", IfDp->Name, IS_UPSTREAM(IfDp->state) ? "upstream" : "disabled");
    } else {
        IfDp->querier = (struct querier){ IfDp->conf->qry.ip, IfDp->conf->qry.ver, IfDp->conf->qry.interval, IfDp->conf->qry.robustness, IfDp->conf->qry.responseInterval, 0, 0 };
        sendIgmp(IfDp, NULL);
        IfDp->conf->qry.startupQueryCount = IfDp->conf->qry.startupQueryCount > 0 ? IfDp->conf->qry.startupQueryCount - 1 : 0;
        int timeout = IfDp->querier.ver == 3 ? (getIgmpExp(IfDp->conf->qry.startupQueryCount > 0 ? IfDp->conf->qry.startupQueryInterval : IfDp->querier.qqi, 0)) : (IfDp->conf->qry.startupQueryCount > 0 ? IfDp->conf->qry.startupQueryInterval : IfDp->querier.qqi);
        IfDp->querier.Timer = timer_setTimer(0, TDELAY(timeout * 10), strcat(strcpy(msg, "General Query: "), IfDp->Name), (timer_f)sendGeneralMemberQuery, IfDp);
        timeout = IfDp->querier.ver != 3 ? IfDp->querier.mrc : getIgmpExp(IfDp->querier.mrc, 0);
        IfDp->querier.ageTimer = timer_setTimer(0, TDELAY(timeout), strcat(strcpy(msg, "Age Active Routes: "), IfDp->Name), (timer_f)ageRoutes, IfDp);
        myLog(LOG_DEBUG, 0, "Sent membership query from %s to %s on %s. Delay: %d", inetFmt(IfDp->querier.ip, 1), inetFmt(allhosts_group, 2), IfDp->Name, IfDp->conf->qry.responseInterval);
    }
}

/**
*   Other Querier Timer expired, take over.
*/
static void expireQuerierTimer(struct IfDesc *IfDp) {
    myLog(LOG_NOTICE, 0, "Querier %s on %s expired.", inetFmt(IfDp->querier.ip, 1), IfDp->Name);
    if (IS_DOWNSTREAM(IfDp->state)) {
        timer_clearTimer(IfDp->querier.ageTimer);
        sendGeneralMemberQuery(IfDp);
    } else {
        IfDp->querier.ip = (uint32_t)-1;
        IfDp->querier.Timer = 0;
    }
}
