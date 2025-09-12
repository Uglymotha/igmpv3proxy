#ifndef _IN_OS_SOLARIS
#define _IN_OS_SOLARIS 1
#define __Solaris 1
#define _XOPEN_SOURCE_EXTENDED 1
#define _XOPEN_SOURCE 1
#define __EXTENSIONS__ 1
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/procset.h>
#include <sys/types.h>
#include <sys/cred.h>
#include <poll.h>
#include <libgen.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in_systm.h>
#include <netinet/ip_mroute.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#define INADDR_ALLIGMPV3_GROUP ((in_addr_t) 0xe0000016)
#define IPDATALEN (ntohs(ip->ip_len))
#define IPSETLEN (ip->ip_len = htons(len))
#define setresuid(x, y, z) setreuid(x, y)
#define setresgid(x, y, z) setregid(x, y)
#endif  // _IN_OS_SOLARIS
