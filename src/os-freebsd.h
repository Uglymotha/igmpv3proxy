#include <sys/param.h>
#include <sys/socket.h>
#include <libgen.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in_systm.h>
#include <netinet/ip_mroute.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#ifdef HAVE_NETLINK_NETLINK_ROUTE_H
#include <netlink/netlink_route.h>
#define HAVE_NETLINK 1
#endif

#if __FreeBSD_version >= 800069 && defined BURN_BRIDGES || __FreeBSD_version >= 800098
#define IGMP_MEMBERSHIP_QUERY IGMP_HOST_MEMBERSHIP_QUERY
#define IGMP_V1_MEMBERSHIP_REPORT IGMP_v1_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT IGMP_v2_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_LEAVE_GROUP IGMP_HOST_LEAVE_MESSAGE
#endif
#define IGMP_V3_MEMBERSHIP_REPORT 0x22

#define INADDR_ALLIGMPV3_GROUP ((in_addr_t) 0xe0000016)

#if __FreeBSD_version >= 1100030
#define IPDATALEN ntohs(ip->ip_len) - (ip->ip_hl << 2)
#elif __FreeBSD_version >= 900044
#define IPDATALEN ip->ip_len - (ip->ip_hl << 2)
#else
#define IPDATALEN ip->ip_len
#endif

#if __FreeBSD_version >= 1100030
#define IPSETLEN ip->ip_len = htons(len)
#else
#define IPSETLEN ip->ip_len = len
#endif
