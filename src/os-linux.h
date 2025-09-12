#ifndef _LINUX_IN_H
#define _LINUX_IN_H 1
#define __Linux__ 1
#define _GNU_SOURCE
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/mroute.h>
#ifdef HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>
#define HAVE_NETLINK 1
#endif
#define IGMP_V3_MEMBERSHIP_REPORT 0x22
#define INADDR_ALLIGMPV3_GROUP ((in_addr_t) 0xe0000016)
#define IPDATALEN ntohs(ip->ip_len) - (ip->ip_hl << 2)
#define IPSETLEN ip->ip_len = htons(len);
#endif // _LINUX_IN_H
