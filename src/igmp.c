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
*   igmp.c - Functions for sending and receiving IGMP packets.
*/

#include "igmpv3proxy.h"

// Local prototypes.
static bool checkIgmp(struct IfDesc *IfDp, register uint32_t src, register uint32_t group, register uint8_t ifstate);
static void expireQuerierTimer(struct IfDesc *IfDp);
static void acceptMemberQuery(struct IfDesc *IfDp, uint32_t src, uint32_t dst, struct igmpv3_query *igmpv3, int ipdatalen);

// Global statics for common IGMP groups.
uint32_t    allhosts_group;            // All hosts addr in net order
uint32_t    allrouters_group;          // All hosts addr in net order
uint32_t    alligmp3_group;            // IGMPv3 addr in net order

// Buffers for sending and receiving IGMP packets.
extern char *rcv_buf;           // Input packet buffer (from igmpv3proxy.c)
static char *snd_buf = NULL;    // Output Packet buffer

/**
*   Open and initialize the igmp socket, and fill in the non-changing IP header fields in the output packet buffer.
*   Returns pointer to the receive buffer.
*/
int initIgmp(int mode) {
    static int fd = -1;

    if (mode == 2 && fd < 0)
        return fd;
    // Close socket and free buffers.
    if (mode != 1 && fd >= 0) {
        if (memuse.rcv > 0) {
            _free(rcv_buf, rcv, memuse.rcv);  // Alloced by Self
            _free(snd_buf, snd, memuse.snd);  // Alloced by Self
        }
        if (!RESTART && !SHUP && !CONFRELOAD)
            fd = k_disableMRouter();
    }
    // Open socket.
    if (mode > 0 && fd == -1)
        fd = k_enableMRouter();
    // Allocate and initialize send and receive packet buffers.
    if (mode > 0 && mrt_tbl >= 0 && fd >=0) {
        _calloc(rcv_buf, 1, rcv, CONF->pBufsz);  // Freed by Self
        _calloc(snd_buf, 1, snd, CONF->pBufsz);  // Freed by Self
        struct ip *ip = (struct ip *)snd_buf;
        k_set_rcvbuf(CONF->kBufsz*1024);  // Set kernel ring buffer size
        k_set_ttl(1);                     // Restrict multicasts to one hop
        k_set_loop(false);                // Disable multicast loopback
        /*
        * Fields zeroed that aren't filled in later:
        * - IP ID (let the kernel fill it in)
        * - Offset (we don't send fragments)
        * - Checksum (let the kernel fill it in)
        */
        ip->ip_v   = IPVERSION;
        ip->ip_hl  = (sizeof(struct ip) + 4) >> 2; // +4 for Router Alert option
        ip->ip_tos = 0xc0;                         // Internet Control
        ip->ip_ttl = 1;                            // IGMP TTL = 1
        ip->ip_p   = IPPROTO_IGMP;
        /* Add Router Alert option */
        ((unsigned char*)snd_buf + MIN_IP_HEADER_LEN)[0] = IPOPT_RA;
        ((unsigned char*)snd_buf + MIN_IP_HEADER_LEN)[1] = 0x04;
        ((unsigned char*)snd_buf + MIN_IP_HEADER_LEN)[2] = 0x00;
        ((unsigned char*)snd_buf + MIN_IP_HEADER_LEN)[3] = 0x00;
        allhosts_group   = htonl(INADDR_ALLHOSTS_GROUP);
        allrouters_group = htonl(INADDR_ALLRTRS_GROUP);
        alligmp3_group   = htonl(INADDR_ALLIGMPV3_GROUP);
    }

    LOG(LOG_DEBUG, 0, "Memory Stats: %lldb total buffers, %lld kernel, %lldb receive, %lldb send, %lld allocs, %lld frees.",
        memuse.rcv + memuse.snd, memuse.rcv - memuse.snd, memuse.rcv - (memuse.rcv - memuse.snd), memuse.snd,
        memalloc.rcv + memalloc.snd, memfree.rcv + memfree.snd);
    return fd;
}

/**
*  Checks if request is valid.
*/
static bool checkIgmp(struct IfDesc *IfDp, register uint32_t src, register uint32_t group, register uint8_t ifstate) {
    if (! IN_MULTICAST(ntohl(group)))
        // Sanitycheck the group adress.
        LOG(LOG_NOTICE, 0, "%s on %s is not a valid Multicast group. Ignoring", inetFmt(group, 0), IfDp->Name);
    else if (src == 0xFFFFFFFF)
        LOG(LOG_INFO, 0, "The request from: %s for: %s on: %s is invalid. Ignoring.",
            inetFmt(src, 0), inetFmt(group, 0), IfDp->Name);
    else if (! IfDp->conf->proxyLocalMc && IGMP_LOCAL(group))
        // Filter local multicast 224.0.0.0/24
        LOG(LOG_DEBUG, 0, "Local multicast (%s) on %s from %s and proxylocalmc is not set. Ignoring.",
            inetFmt(group, 0), IfDp->Name, inetFmt(src, 0));
    else if (src == IfDp->InAdr.s_addr || (IfDp->querier.ip == IfDp->conf->qry.ip && src == IfDp->querier.ip))
        LOG(LOG_DEBUG, 0, "The request from %s on %s is from myself. Ignoring.", inetFmt(src, 0), IfDp->Name);
    else if ((IfDp->state & ifstate) == 0 || IfDp->conf->tbl != mrt_tbl)
        LOG(LOG_INFO, 0, "Message for %s from %s was received on %s interface %s. Ignoring.",
            inetFmt(group, 0), inetFmt(src, 0), IS_UPSTREAM(IfDp->state) ? "upstream" : IS_DOWNSTREAM(IfDp->state) ? "downstream" :
            "disabled", IfDp->Name);
    else
        return true;

    return false;
}

/**
*   Process a newly received IGMP packet that is sitting in the input packet buffer.
*/
void acceptIgmp(int fd) {
    struct iovec       ioVec[1] = { { rcv_buf, CONF->pBufsz } };
    union  cmsg        cmsg;
    struct msghdr      msgHdr = (struct msghdr){ NULL, 0, ioVec, 1, &cmsg, sizeof(cmsg), MSG_DONTWAIT };
    struct cmsghdr    *cmsgPtr;
    struct IfDesc     *IfDp = NULL;

    // Receive the IGMP packet.
    int recvlen = recvmsg(fd, &msgHdr, 0);
    if (recvlen < (int)sizeof(struct ip) || (msgHdr.msg_flags & MSG_TRUNC)) {
        LOG(LOG_ERR, 1, "recvmsg() truncated datagram received.");
        return;
    } else if ((msgHdr.msg_flags & MSG_CTRUNC)) {
        LOG(LOG_ERR, 1, "recvmsg() truncated control message received.");
        return;
    }
    struct ip         *ip = (struct ip *)rcv_buf;
    register uint32_t  src = ip->ip_src.s_addr, dst = ip->ip_dst.s_addr;
    register int       ipdatalen = IPDATALEN, iphdrlen = ip->ip_hl << 2, ifindex = 0;
    struct igmp       *igmp = (struct igmp *)(rcv_buf + iphdrlen);

    // Handle kernel upcall messages first.
    if (ip->ip_p == 0) {
        struct igmpmsg *igmpMsg = (struct igmpmsg *)(rcv_buf);
        if (! (IfDp = getIf(igmpMsg->im_vif, NULL, FINDIX | SRCHVIFL)))
            return;
        LOG(LOG_DEBUG, 0, "Upcall from %s to %s on %s.", inetFmt(src, 0), inetFmt(dst, 0), IfDp->Name);
        switch (igmpMsg->im_msgtype) {
        case IGMPMSG_NOCACHE:
            if (checkIgmp(IfDp, src, dst, IF_STATE_UPDOWNSTREAM))
                activateRoute(IfDp, NULL, src, dst, true);
            return;
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        case IGMPMSG_BW_UPCALL:
            if (IfDp->conf->bwControl > 0)
                processBwUpcall((struct bw_upcall *)(rcv_buf + sizeof(struct igmpmsg)),
                               ((recvlen - sizeof(struct igmpmsg)) / sizeof(struct bw_upcall)));
            return;
#endif
#ifdef IGMPMSG_WRONGVIF
        case IGMPMSG_WRONGVIF:
            LOG(LOG_NOTICE, 0, "WRONGVIF Upcall for Src %s Dst %s on %s.",
                inetFmt(igmpMsg->im_src.s_addr, 0), inetFmt(igmpMsg->im_dst.s_addr, 0), IfDp->Name);
            return;
#endif
        default:
            LOG(LOG_WARNING, 0, "Unsupported upcall %d.", igmpMsg->im_msgtype);
            return;
        }
    } else for (cmsgPtr = CMSG_FIRSTHDR(&msgHdr); cmsgPtr; cmsgPtr = CMSG_NXTHDR(&msgHdr, cmsgPtr))
        //  Get the source interface from the control message.
        if (cmsgPtr->cmsg_level == IPPROTO_IP && cmsgPtr->cmsg_type == IFINFO) {
#ifdef IP_PKTINFO
            struct in_pktinfo *inp = (struct in_pktinfo *)CMSG_DATA(cmsgPtr);
            ifindex = inp->ipi_ifindex;
#elif IP_RECVIF
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)CMSG_DATA(cmsgPtr);
            ifindex = sdl->sdl_index;
#endif
            if (! (IfDp = getIf(ifindex, NULL, FINDSYSIX | SRCHVIFL))) {
                char ifName[IF_NAMESIZE];
                LOG(LOG_INFO, 0, "No valid interface found for src: %s dst: %s on %s.",
                    inetFmt(src, 0), inetFmt(dst, 0), ifindex ? if_indextoname(ifindex, ifName) : "unk");
                return;
            }
            break;
        }

    // Sanity check the request, only allow requests for valid interface, valid src & dst and no corrupt packets.
    register uint16_t cksum = igmp->igmp_cksum;
    igmp->igmp_cksum = 0;
    if (iphdrlen + ipdatalen != recvlen)
        LOG(LOG_WARNING, 0, "Packet from %s shorter (%u bytes) than hdr+data length (%u+%u).",
            inetFmt(src, 0), recvlen, iphdrlen, ipdatalen);
    else if ((ipdatalen < IGMP_MINLEN) || (igmp->igmp_type == IGMP_V3_MEMBERSHIP_REPORT && ipdatalen <= IGMPV3_MINLEN))
        LOG(LOG_WARNING, 0, "IP data field too short (%u bytes) for IGMP, from %s.", ipdatalen, inetFmt(src, 0));
    else if (IfDp->conf->cksumVerify && cksum != inetChksum((uint16_t *)igmp, ipdatalen))
        LOG(LOG_WARNING, 0, "Packet from: %s for: %s on: %s checksum incorrect.", inetFmt(src, 0), inetFmt(dst, 0), IfDp->Name);
    else {
        struct igmpv3_query  *igmpv3   = (struct igmpv3_query *)(rcv_buf + iphdrlen);
        struct igmpv3_report *igmpv3gr = (struct igmpv3_report *)(rcv_buf + iphdrlen);
        struct igmpv3_grec   *grec     = &igmpv3gr->igmp_grec[0];
        LOG(LOG_DEBUG, 0, "RECV %s from %s to %s on %s%s.", igmpPacketKind(igmp->igmp_type, igmp->igmp_code),
            inetFmt(src, 0), inetFmt(dst, 0), IfDp->Name, IfDp->conf->cksumVerify ? " (checksum correct)" : "");

        switch (igmp->igmp_type) {
        case IGMP_V1_MEMBERSHIP_REPORT:
        case IGMP_V2_LEAVE_GROUP:
        case IGMP_V2_MEMBERSHIP_REPORT:
            if (checkIgmp(IfDp, src, igmp->igmp_group.s_addr, IF_STATE_DOWNSTREAM))
                updateGroup(IfDp, src, (void *)igmp);
            return;

        case IGMP_V3_MEMBERSHIP_REPORT: {
            int ngrec = ntohs(igmpv3gr->igmp_ngrec);
            LOG(LOG_INFO, 0, "Processing %d group records for %s.", ngrec, inetFmt(src, 0));
            if (ngrec > 0) do {
                int nsrcs = ntohs(grec->grec_nsrcs);
                if (grec->grec_type < 1 || grec->grec_type > 6)
                    LOG(LOG_NOTICE, 0, "Ignoring unknown IGMPv3 group record type %x from %s to %s for %s.",
                        grec->grec_type, inetFmt(src, 0), inetFmt(dst, 0), inetFmt(grec->grec_mca.s_addr, 0));
                else if (checkIgmp(IfDp, src, grec->grec_mca.s_addr, IF_STATE_DOWNSTREAM))
                    updateGroup(IfDp, src, grec);
                grec = (struct igmpv3_grec *)(&grec->grec_src[nsrcs] + grec->grec_auxwords * 4);
            } while (--ngrec && (char *)igmpv3gr + ipdatalen >= (char *)grec + sizeof(*grec));
            return;
        }

        case IGMP_MEMBERSHIP_QUERY:
            IfDp->stats.rqCnt++;
            if (IfDp->conf->qry.election && checkIgmp(IfDp, src, htonl(0xE0FFFFFF), IF_STATE_UPDOWNSTREAM))
                acceptMemberQuery(IfDp, src, dst, igmpv3, ipdatalen);
            return;

        default:
            LOG(LOG_NOTICE, 0, "Ignoring unknown IGMP message type %x from %s to %s.",
                igmp->igmp_type, inetFmt(src, 0), inetFmt(dst, 0));
            return;
        }
    }
}

/**
*   Construct an IGMP query message in the output packet buffer and send it.
*/
void sendIgmp(struct IfDesc *IfDp, struct igmpv3_query *query) {
    struct ip           *ip     = (struct ip *)snd_buf;
    struct igmpv3_query *igmpv3 = (struct igmpv3_query *)(snd_buf + IP_HEADER_RAOPT_LEN);
    int                  len    = 0;
    struct sockaddr_in   sdst;

    if (IfDp->conf->tbl != mrt_tbl) {
        LOG(LOG_ERR, eABNRML, "Requested to send packet on table %d interface %s.", IfDp->conf->tbl, IfDp->Name);
        return;
    } else if (IS_DISABLED(IfDp->state) || !IQUERY) {
        LOG(LOG_WARNING, 0, "Not sending query for %s on %s interface %s.", inetFmt(query->igmp_group.s_addr, 0),
            IS_DISABLED(IfDp->state) ? "disabled" : "non querier", IfDp->Name);
        return;
    } else if (query && (IfDp->querier.ver == 1 || (IfDp->querier.ver == 2 && query->igmp_nsrcs > 0))) {
        LOG(LOG_WARNING, 0, "Not sending group and source specific query on %s while in v%d mode.", IfDp->Name, IfDp->querier.ver);
        return;
    }
    IfDp->stats.sqCnt++;

    memset(igmpv3, 0, sizeof(struct igmpv3_query));
    memset(&sdst, 0, sizeof(struct sockaddr_in));
    sdst.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sdst.sin_len = sizeof(sdst);
#endif

    // Set IP / IGMP packet data.
    k_set_if(IfDp);
    ip->ip_src.s_addr  = IfDp->querier.ip;
    ip->ip_dst.s_addr  = sdst.sin_addr.s_addr = query ? query->igmp_group.s_addr : allhosts_group;
    igmpv3->igmp_type         = IGMP_MEMBERSHIP_QUERY;
    igmpv3->igmp_code         = IfDp->querier.ver == 1 ? 0
                                                       : query && query->igmp_code != 0 ? query->igmp_code
                                                       : query ? IfDp->conf->qry.lmInterval
                                                       : IfDp->querier.mrc;
    igmpv3->igmp_group.s_addr = query ? query->igmp_group.s_addr : 0;
    igmpv3->igmp_misc         = (query && query->igmp_type & 0x1 ? 0x8 : 0) + IfDp->querier.qrv;    // set router suppress flag.
    igmpv3->igmp_qqi          = query ? IfDp->conf->qry.lmInterval : IfDp->querier.qqi;

    uint32_t nsrcs = query ? query->igmp_nsrcs : 0,
                 i = 0, j = 0,
                 n = (IfDp->mtu - IP_HEADER_RAOPT_LEN) / 4;  // max sources to send per packet.
    do {
        char msg[90 + IF_NAMESIZE];
        for (j = 0; j < n && i < nsrcs; igmpv3->igmp_src[j] = query->igmp_src[i], j++, i++);
        igmpv3->igmp_nsrcs = htons(j);

        // Set packet length and calculate checksum.
        len = IfDp->querier.ver == 3 ? IGMPV3_MINLEN + j * sizeof(struct in_addr) : 8;
        igmpv3->igmp_cksum = 0;
        igmpv3->igmp_cksum = inetChksum((uint16_t *)igmpv3, len);
        len += IP_HEADER_RAOPT_LEN;
        IPSETLEN;
        // Send packet.
        sprintf(msg, "%s from %s to %s (%d:%d:%d) on %s.", igmpPacketKind(igmpv3->igmp_type, igmpv3->igmp_code),
                IfDp->querier.ip == INADDR_ANY ? "INADDR_ANY" : inetFmt(IfDp->querier.ip, 0),
                inetFmt(ip->ip_dst.s_addr, 0), igmpv3->igmp_code, igmpv3->igmp_misc, igmpv3->igmp_qqi, IfDp->Name);
        if (sendto(MROUTERFD, snd_buf, len, MSG_DONTWAIT, (struct sockaddr *)&sdst, sizeof(sdst)) < 0)
            LOG(LOG_WARNING, 1, msg);
        else
            LOG(LOG_DEBUG, 0, msg);
    } while (i < nsrcs);
}

/**
*   Processes a received general membership query and updates igmp timers for the interface.
*/
static void acceptMemberQuery(struct IfDesc *IfDp, uint32_t src, uint32_t dst, struct igmpv3_query *igmpv3, int ipdatalen) {
    uint8_t  ver = ipdatalen >= IGMPV3_MINLEN ? 3 : igmpv3->igmp_code == 0 ? 1 : 2;
    uint32_t timeout;

    if (ver < IfDp->querier.ver || (ver == IfDp->querier.ver && (htonl(src) <= htonl(IfDp->querier.ip)))) {
        if (dst == allhosts_group || src != IfDp->querier.ip) {
            // Clear running query and age timers.
            IfDp->querier.Timer = timerClear(IfDp->querier.Timer, false);
            IfDp->querier.ageTimer = timerClear(IfDp->querier.ageTimer, false);
            // Set querier parameters for interface, use configured values in case querier detected because of gsq.
            IfDp->querier = OTHER_QUERIER;
            if (dst != allhosts_group) {
                IfDp->querier.qqi = IfDp->conf->qry.interval;
                IfDp->querier.qrv = IfDp->conf->qry.robustness;
                IfDp->querier.mrc = IfDp->conf->qry.responseInterval;
            }
            // For downstream interface and general query set the age timer.
            if (IS_DOWNSTREAM(IfDp->state) && dst == allhosts_group) {
                timeout = (ver == 3 ? getIgmpExp(igmpv3->igmp_code, 1) : ver == 2 ? igmpv3->igmp_code : 10) + 1;
                IfDp->querier.ageTimer = timerSet(timeout, strcat(strcpy(strBuf, "Age Active Groups: "), IfDp->Name),
                                                  ageGroups, IfDp);
            }
            // Determine timeout for other querier, in case of gsq, use configured values.
            if (ver == 3)
                timeout = dst == allhosts_group ? ((getIgmpExp(igmpv3->igmp_qqi, 1) * (igmpv3->igmp_misc & 0x07)) * 10)
                                                  + getIgmpExp(igmpv3->igmp_code, 1) / 2
                                                : ((getIgmpExp(IfDp->querier.qqi, 1) * IfDp->querier.qrv) * 10)
                                                  + getIgmpExp(IfDp->querier.mrc, 1) / 2;
            else if (ver == 2)
                timeout = dst == allhosts_group ? (IfDp->conf->qry.interval*IfDp->conf->qry.robustness*10) + igmpv3->igmp_code / 2
                                                : ((IfDp->querier.qqi*IfDp->querier.qrv*10) * 10) + IfDp->querier.mrc / 2;
            else
                timeout = (100 * IfDp->conf->qry.robustness) + 5;
            // Set timeout for other querier.
            sprintf(strBuf, "%sv%1d Querier: ", IS_DOWNSTREAM(IfDp->state) ? "Other " : "", ver);
            IfDp->querier.Timer = timerSet(timeout, strcat(strBuf, IfDp->Name), expireQuerierTimer, IfDp);

            LOG(LOG_NOTICE, 0, "%sv%d IGMP querier %s (%d:%d:%d) on %s. Setting Timer for %ds.",
                IS_DOWNSTREAM(IfDp->state) ? "Other " : "", ver, inetFmt(src, 0),
                IfDp->querier.qqi, IfDp->querier.mrc, IfDp->querier.qrv, IfDp->Name, timeout / 10);
        }
        if (IS_DOWNSTREAM(IfDp->state) && dst != allhosts_group && !(igmpv3->igmp_misc & 0x8))
            // Process GSQ from other querier if Router Supress flag is not set.
            processGroupQuery(IfDp, igmpv3, ver == 3 ? ntohs(igmpv3->igmp_nsrcs) : 0, ver);
    } else
        LOG(LOG_NOTICE, 0, "v%d query from %s on %s, but it does not have priority over %s. Ignoring",
            ver, inetFmt(src, 0), IfDp->Name, IfDp->querier.ip == IfDp->conf->qry.ip ? "us" : inetFmt(IfDp->querier.ip, 0));
}

/**
*   Sends a general membership query on downstream VIFs
*/
void sendGeneralMemberQuery(struct IfDesc *IfDp) {
    uint32_t timeout;
    // Only query interface if set regardless of querier status. If it is downstream of course.
    if (!IS_DOWNSTREAM(IfDp->state)) {
        LOG(LOG_WARNING, 0, "Requested to send a query on %s, but it is %s. Query not sent.",
            IfDp->Name, IS_UPSTREAM(IfDp->state) ? "upstream" : "disabled");
    } else {
        // Send query.
        IfDp->querier = DEFAULT_QUERIER;
        sendIgmp(IfDp, NULL);

        // Set timer for next query.
        if (IfDp->conf->qry.startupQueryCount > 0)
            IfDp->conf->qry.startupQueryCount--;
        if (IfDp->querier.ver == 3)
            timeout = getIgmpExp(IfDp->conf->qry.startupQueryCount > 0 ? IfDp->conf->qry.startupQueryInterval
                                                                       : IfDp->querier.qqi, 0);
        else
            timeout = IfDp->conf->qry.startupQueryCount > 0 ? IfDp->conf->qry.startupQueryInterval : IfDp->querier.qqi;
        IfDp->querier.Timer = timerSet((timeout * 10) + ((uint8_t)IfDp->Name[0] % 4),
                                        strcat(strcpy(strBuf, "General Query: "), IfDp->Name),
                                        sendGeneralMemberQuery, IfDp);
        // Set timer for route aging.
        timeout = IfDp->querier.ver == 3 ? getIgmpExp(IfDp->querier.mrc, 0) : IfDp->querier.mrc;
        IfDp->querier.ageTimer = timerSet(timeout, strcat(strcpy(strBuf, "Age Active Groups: "), IfDp->Name), ageGroups, IfDp);
        LOG(LOG_INFO, 0, "From %s to %s on %s. Delay: %d", inetFmt(IfDp->querier.ip, 0),
            inetFmt(allhosts_group, 0), IfDp->Name, IfDp->conf->qry.responseInterval);
    }
}

/**
*   Other Querier Timer expired, take over.
*/
static void expireQuerierTimer(struct IfDesc *IfDp) {
    LOG(LOG_NOTICE, 0, "Other querier %s on %s expired.", inetFmt(IfDp->querier.ip, 0), IfDp->Name);
    if (IS_DOWNSTREAM(IfDp->state)) {
        IfDp->querier.Timer = timerClear(IfDp->querier.ageTimer, false);
        sendGeneralMemberQuery(IfDp);
    } else {
        IfDp->querier.ip = (uint32_t)-1;
        IfDp->querier.Timer = (intptr_t)NULL;
    }
}
