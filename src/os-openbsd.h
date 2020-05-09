#define __BSD_VISIBLE 1
#include <netinet/in.h>
#include <net/if_dl.h>
#include <netinet/ip_mroute.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>

/*
 * Structure used to communicate from kernel to multicast router.
 * (Note the convenient similarity to an IP packet.)
 */
struct igmpmsg {
        u_int32_t unused1;
        u_int32_t unused2;
        u_int8_t  im_msgtype;           /* what type of message */
#define IGMPMSG_NOCACHE         1       /* no MFC in the kernel             */
#define IGMPMSG_WRONGVIF        2       /* packet came from wrong interface */
#define IGMPMSG_BW_UPCALL       4       /* BW monitoring upcall             */
        u_int8_t  im_mbz;               /* must be zero */
        u_int8_t  im_vif;               /* vif rec'd on */
        u_int8_t  unused3;
        struct    in_addr im_src, im_dst;
};

#define MCAST_JOIN_GROUP IP_ADD_MEMBERSHIP
#define MCAST_LEAVE_GROUP IP_DROP_MEMBERSHIP

#define IGMP_MEMBERSHIP_QUERY IGMP_HOST_MEMBERSHIP_QUERY
#define IGMP_V1_MEMBERSHIP_REPORT IGMP_v1_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT IGMP_v2_HOST_MEMBERSHIP_REPORT
#define IGMP_V3_MEMBERSHIP_REPORT 0x22
#define IGMP_V2_LEAVE_GROUP IGMP_HOST_LEAVE_MESSAGE

#define INADDR_ALLRTRS_GROUP INADDR_ALLROUTERS_GROUP
#define INADDR_ALLIGMPV3_GROUP ((in_addr_t) 0xe0000016)

#define IPDATALEN ntohs(ip->ip_len) - (ip->ip_hl << 2)

#define IPSETLEN ip->ip_len = htons(len);
