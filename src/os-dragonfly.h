#include <sys/param.h>
#include <netinet/ip.h>
#include <net/route.h>
#include <netinet/igmp.h>
#include <net/ip_mroute/ip_mroute.h>
#include <net/if_dl.h>

#define IGMP_V3_MEMBERSHIP_REPORT 0x22
#define MCAST_JOIN_GROUP IP_ADD_MEMBERSHIP
#define MCAST_LEAVE_GROUP IP_DROP_MEMBERSHIP

#define INADDR_ALLIGMPV3_GROUP ((in_addr_t) 0xe0000016)

#define IPDATALEN ip->ip_len

#define IPSETLEN ip->ip_len = len
