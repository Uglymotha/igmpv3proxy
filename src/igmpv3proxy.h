/*
**  igmpv3proxy - IGMP proxy based multicast router
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
*/

/**
*   igmpv3proxy.h - Header file for common includes.
*/
#include "config.h"
#include "os.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <time.h>
#include <grp.h>
#include <ifaddrs.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>

#include <net/if.h>
#include <arpa/inet.h>

#include "igmpv3.h"

//#################################################################################
//  Global definitions and declarations.
//#################################################################################

// Bit manipulation macros.
#define BIT_SET(X,n)     ((X) |= 1 << (n))
#define BIT_CLR(X,n)     ((X) &= ~(1 << (n)))
#define BIT_TST(X,n)     (((X) >> (n)) & 1)

// Set type of control message structure for received socket data.
#ifdef IP_PKTINFO
#define IFINFO IP_PKTINFO
#elif IP_RECVIF
#define IFINFO IP_RECVIF
#endif

// In / output buffering (Jumbo MTU).
#define BUF_SIZE   9216
#define K_BUF_SIZE 512
#define REQQSZ     16
#define TMQSZ      4

// Limit of configuration token.
#define READ_BUFFER_SIZE    2048
#define MAX_TOKEN_LENGTH    128
#define MAX_GROUPNAME_SIZE  32

// Keeps common configuration settings.
#define CFG_PATHS "/etc/ /usr/local/etc/ /var/etc/ /usr/local/var/etc/"
struct Config {
    // Daemon parameters.
    bool                notAsDaemon;
    char               *configFilePath;
    char               *runPath;
    uint16_t            reqQsz;
    uint16_t            tmQsz;
    uint32_t            kBufsz;
    uint16_t            pBufsz;
    // Default interface igmp parameters.
    uint32_t            querierIp;
    uint8_t             querierVer;
    uint8_t             robustnessValue;
    uint8_t             queryInterval;
    uint8_t             queryResponseInterval;
    uint32_t            bwControlInterval;
    // Last member probe.
    uint8_t             lastMemberQueryInterval;
    uint8_t             lastMemberQueryCount;
    // Set if upstream leave messages should be sent instantly..
    bool                fastUpstreamLeave;
    // Size in bytes of hash table of downstream hosts used for fast leave
    uint32_t            dHostsHTSize;
    uint32_t            hashSeed;
    uint16_t            mcTables;
    // Max origins for route when bw control is disabled.
    uint16_t            maxOrigins;
    // Set default interface status and parameters.
    uint8_t             defaultInterfaceState;
    uint8_t             defaultThreshold;
    uint64_t            defaultRatelimit;
    struct filters     *defaultFilters, *defaultRates;
    // Logging Parameters.
    uint8_t             logLevel;
    char               *logFilePath;
    bool                log2Stderr;              // Log to stderr instead of to syslog / file
    // Set if nneed to detect new interface.
    uint32_t            rescanVif;
    // Set if nneed to detect config change.
    uint32_t            rescanConf;
    // Set if need to proxy IANA local multicast range 224.0.0.0/8.
    bool                proxyLocalMc;
    // Set if must not participate in IGMP querier election.
    bool                querierElection;
    // Group for CLI access.
    struct group        socketGroup;
};

// Linked list of filters.
#define ALLOW 1
#define BLOCK 0
struct subnet {
    uint32_t  ip;
    uint32_t  mask;
};

#define FILTERANY (struct filters){ {INADDR_ANY, INADDR_ANY}, {INADDR_ANY, INADDR_ANY}, ALLOW, 3, NULL }
struct filters {
    struct subnet         src, dst;
    uint64_t              action;
    uint8_t               dir;
    struct filters       *next;
};

// Keeps configured Querier parameters.
struct queryParam {
    uint32_t            ip;                     // Configured querier IP
    uint8_t             ver;                    // Configured querier version
    bool                election;               // Configured querier election mode
    uint8_t             robustness;             // Configured robustness value
    uint8_t             interval;               // Configured query interval
    uint8_t             responseInterval;       // Configured query response interval
    uint8_t             lmInterval;             // Configured lastmember query interval value
    uint8_t             lmCount;                // Configured lastmember count value
    uint8_t             startupQueryInterval;   // Configured startup query interval
    uint8_t             startupQueryCount;      // Configured startup query count
};

// Structure to keep configuration for VIFs.
struct vifConfig {
    char                name[IF_NAMESIZE];
    uint8_t             state;                   // Configured interface state
    uint8_t             threshold;               // Interface MC TTL
    uint64_t            ratelimit;               // Interface ratelimit
    struct queryParam   qry;                     // Configured query parameters
    bool                noDefaultFilter;         // Do not add default filters to interface
    struct filters     *filters, *rates;         // ACL and ratelimiters for interface
    struct vifConfig   *next;
};
#define DEFAULT_VIFCONF (struct vifConfig){ "", commonConfig.defaultInterfaceState, commonConfig.defaultThreshold, commonConfig.defaultRatelimit, {commonConfig.querierIp, commonConfig.querierVer, commonConfig.querierElection, commonConfig.robustnessValue, commonConfig.queryInterval, commonConfig.queryResponseInterval, commonConfig.lastMemberQueryInterval, commonConfig.lastMemberQueryCount, 0, 0}, false, false, NULL, NULL }

// Running querier status for interface.
struct querier {                                        // igmp querier status for interface
    uint32_t       ip;                                  // Querier IP
    uint8_t        ver;                                 // Querier version
    uint8_t        qqi;                                 // Queriers query interval
    uint8_t        qrv;                                 // Queriers robustness value
    uint8_t        mrc;                                 // Queriers max response code
    uint64_t       Timer;                               // Self / Other Querier timer
    uint64_t       ageTimer;                            // Route aging timer
};
#define DEFAULT_QUERIER (struct querier){ IfDp->conf->qry.ip, IfDp->conf->qry.ver, IfDp->conf->qry.interval, IfDp->conf->qry.robustness, IfDp->conf->qry.responseInterval, 0, 0 }
#define OTHER_QUERIER (struct querier){ src, ver, ver == 3 ? (igmpv3->igmp_qqi > 0 ? igmpv3->igmp_qqi : DEFAULT_INTERVAL_QUERY) : IfDp->conf->qry.interval, ver == 3 ? ((igmpv3->igmp_misc & 0x7) > 0 ? igmpv3->igmp_misc & 0x7 : DEFAULT_ROBUSTNESS) : IfDp->conf->qry.robustness, ver != 1 ? igmpv3->igmp_code : 10, IfDp->querier.Timer, IfDp->querier.ageTimer }

// Interfaces configuration.
struct IfDesc {
    char                          Name[IF_NAMESIZE];
    struct in_addr                InAdr;                 // Primary IP
    uint32_t                      Flags;                 // Operational flags
    uint32_t                      mtu;                   // Interface MTU
    uint8_t                       state;                 // Operational state
    struct vifConfig             *conf;                  // Pointer to interface configuraion
    bool                          filCh;                 // Flag for filter change during config reload
    struct querier                querier;               // igmp querier for interface
    uint64_t                      bytes, rate;           // Counters for bandwith control
    unsigned int                  sysidx;                // Interface system index
    uint8_t                       index;                 // MCast vif index
    void                         *dMct;                  // Pointers to active downstream groups for vif
    void                         *uMct;                  // Pointers to active upstream groups for vif
    struct IfDesc                *next;
};
#define DEFAULT_IFDESC (struct IfDesc){ "", {0}, 0, 0, 0x80, NULL, false, {(uint32_t)-1, 3, 0, 0, 0, 0, 0}, 0, 0, 0, (uint8_t)-1, NULL, NULL, IfDescL }

union cmsgU {
    struct cmsghdr cmsgHdr;
#ifdef IP_PKTINFO
    char cmsgData[sizeof(struct msghdr) + sizeof(struct in_pktinfo)];
#elif IP_RECVIF
    char cmsgData[sizeof(struct msghdr) + sizeof(struct sockaddr_dl)];
#endif
};

// Interface states
#define IF_STATE_DISABLED      0                              // Interface should be ignored.
#define IS_DISABLED(x)         ((x & 0x3) == 0)
#define IF_STATE_UPSTREAM      1                              // Interface is upstream
#define IS_UPSTREAM(x)         (x & 0x1)
#define IF_STATE_DOWNSTREAM    2                              // Interface is downstream
#define IS_DOWNSTREAM(x)       (x & 0x2)
#define IF_STATE_UPDOWNSTREAM  3                              // Interface is both up and downstream
#define IS_UPDOWNSTREAM(x)     ((x & 0x3) == 3)
#define IF_OLDSTATE(x)         ((x->state >> 2) & 0x3)
#define IF_NEWSTATE(x)         (x->state & 0x3)

// Multicast default values.
#define DEFAULT_ROBUSTNESS  2
#define DEFAULT_THRESHOLD   1
#define DEFAULT_RATELIMIT   0

// Query default values.
#define DEFAULT_INTERVAL_QUERY          125
#define DEFAULT_INTERVAL_QUERY_RESPONSE 100

// IGMP Global Values.
#define MIN_IP_HEADER_LEN	20
#define MAX_IP_HEADER_LEN	60
#define IP_HEADER_RAOPT_LEN	24

// Route parameters.
#define DEFAULT_MAX_ORIGINS     64  // Maximun nr of route sources, controlable by maxorigins config paramter, in which case this also acts as mimimun.
#define DEFAULT_HASHTABLE_SIZE  32  // Default host tracking hashtable size.
#define DEFAULT_ROUTE_TABLES    32  // Default hash table size for route table.

// Signal Handling. 0 = no signal, 2 = SIGHUP, 4 = SIGUSR1, 8 = SIGUSR2, 5 = Timed Reload, 9 = Timed Rebuild, 32 = SHUTDOWN
#define GOT_SIGHUP  0x02
#define GOT_SIGUSR1 0x04
#define GOT_CONFREL 0x05
#define GOT_SIGUSR2 0x08
#define GOT_IFREB   0x09
#define GOT_SIGURG  0x10
#define CONFRELOAD (sigstatus & GOT_SIGUSR1)
#define IFREBUILD  (sigstatus & GOT_SIGUSR2)
#define SSIGHUP    (sigstatus & GOT_SIGHUP)
#define NOSIG      (sigstatus == 0)
#define STARTUP    (sigstatus == 1)
#define SHUTDOWN   (sigstatus == 32)

// CLI Defines.
#define CLI_CMD_BUF    256
#define CLI_SOCK_PATHS "/run /var/run /tmp /var/tmp"

//#################################################################################
//  Global Variables.
//############A#####################################################################
// Help string.
extern const char *fileName, Usage[];

// Timekeeping.
extern struct   timespec curtime, utcoff;

// Process Signaling.
extern uint8_t  sighandled, sigstatus;

// Upstream vif mask.
extern uint32_t uVifs;

// Global IGMP groups.
extern uint32_t allhosts_group;            /* All hosts addr in net order */
extern uint32_t allrouters_group;          /* All hosts addr in net order */
extern uint32_t alligmp3_group;            /* IGMPv3 addr in net order */

//#################################################################################
//  Lib function prototypes.
//#################################################################################

/**
*   config.c
*/
#define CONFIG getConfig()
struct Config *getConfig(void);
void           freeConfig(int old);
void           reloadConfig(uint64_t *tid);
bool           loadConfig(void);
void           configureVifs(void);

/**
*   cli.c
*/
int  openCliSock(void);
int  cliSetGroup(int gid);
void processCliCon(int fd);
void cliCmd(char *cmd);

/**
*   ifvc.c
*/
#define IFL(x)               x = getIfL(); x; x = x->next
#define GETIFL(x)            for (IFL(x))
#define IFGETIFL(y, x)       if (y) GETIFL(x)
#define GETIFLIF(x, y)       GETIFL(x) if (y)
#define IFGETIFLIF(x, y, z)  if (x) GETIFLIF(y, z)
void           rebuildIfVc(uint64_t *tid);
void           buildIfVc(void);
struct IfDesc *getIfL(void);
struct IfDesc *getIf(unsigned int ix, int sys);
void           getIfStats(int h, struct sockaddr_un *cliSockAddr, int fd);
void           getIfFilters(int h, struct sockaddr_un *cliSockAddr, int fd);

/**
*   igmp.c
*/
char *initIgmp(void);
void  acceptIgmp(int recvlen, struct msghdr msgHdr);
void  ctrlQuerier(int start, struct IfDesc *IfDp);
void  sendIgmp(struct IfDesc *IfDp, struct igmpv3_query *query);
void  sendGeneralMemberQuery(struct IfDesc *IfDp);

/**
*   lib.c
*/
#define LOG(x, ...) x <= CONFIG->logLevel ? myLog(x, __VA_ARGS__) : (void)0
const char     *inetFmt(uint32_t addr, int pos);
const char     *inetFmts(uint32_t addr, uint32_t mask, int pos);
uint16_t        inetChksum(uint16_t *addr, int len);
struct timespec timeDiff(struct timespec t1, struct timespec t2);
uint32_t        s_addr_from_sockaddr(const struct sockaddr *addr);
bool            parseSubnetAddress(const char * const str, uint32_t *addr, uint32_t *mask);
uint32_t        murmurhash3(register uint32_t x);
void            setHash(register uint64_t *table, register uint32_t hash);
void            clearHash(register uint64_t *table, register uint32_t hash);
bool            testHash(register uint64_t *table, register uint32_t hash);
bool            noHash(register uint64_t *table);
uint16_t        sortArr(register uint32_t *arr, register uint16_t nr);
const char     *igmpPacketKind(unsigned int type, unsigned int code);
const char     *grecKind(unsigned int type);
uint16_t        grecType(struct igmpv3_grec *grec);
uint16_t        grecNscrs(struct igmpv3_grec *grec);
uint16_t        getIgmpExp(register int val, register int d);
void            myLog(int Serverity, int Errno, const char *FmtSt, ...);

/**
*   kern.c
*/
#define MROUTERFD k_getMrouterFD()
void k_set_rcvbuf(int bufsize);
void k_set_ttl(uint8_t ttl);
void k_set_loop(bool l);
void k_set_if(struct IfDesc *IfDp);
bool k_updateGroup(struct IfDesc *IfDp, bool join, uint32_t group, int mode, uint32_t src);
int  k_setSourceFilter(struct IfDesc *IfDp, uint32_t group, uint32_t fmode, uint32_t nsrcs, uint32_t *slist);
int  k_getMrouterFD(void);
int  k_enableMRouter(void);
void k_disableMRouter(void);
bool k_addVIF(struct IfDesc *IfDp);
void k_delVIF(struct IfDesc *IfDp);
void k_addMRoute(uint32_t src, uint32_t group, int vif, uint8_t ttlVc[MAXVIFS]);
void k_delMRoute(uint32_t src, uint32_t group, int vif);
void k_deleteUpcalls(uint32_t src, uint32_t group);

/**
*   mctable.c
*/
#define IQUERY (IfDp->querier.ip == IfDp->conf->qry.ip && IfDp->conf->qry.lmCount > 0)
#define GETMRT(x) uint16_t iz; if (MCT) for (iz = 0; iz < CONFIG->mcTables; iz++) \
                                        for (x = MCT[iz]; x; x = ! x ? MCT[iz] : x->next)
#define IS_EX(x, y)       BIT_TST(x->mode, y->index)
#define IS_IN(x, y)      !BIT_TST(x->mode, y->index)
#define IS_SET(x, y, z)   BIT_TST(x->vifB.y, z->index)
#define NOT_SET(x, y, z) !BIT_TST(x->vifB.y, z->index)
void     bwControl(uint64_t *tid);
void     clearGroups(void *Dp);
void     updateGroup(struct IfDesc *IfDp, register uint32_t src, struct igmpv3_grec *grec);
void     activateRoute(struct IfDesc *IfDp, void *_src, register uint32_t ip, register uint32_t group, bool activate);
void     ageGroups(struct IfDesc *IfDp);
void     logRouteTable(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd);
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
void     processBwUpcall(struct bw_upcall *bwUpc, int nr);
#endif

/**
*   querier.c
*/
void     processGroupQuery(struct IfDesc *IfDp, struct igmpv3_query *query, uint32_t nsrcs, uint8_t ver);
void     delQuery(struct IfDesc *IfDP, void *qry, void *route, void *_src, uint8_t type);

/**
*   timers.c
*/
#define TMNAMESZ 48
#define TDELAY(x) (struct timespec){ -1, x }
#define DEBUGQUEUE(...) if (CONFIG->logLevel == LOG_DEBUG) debugQueue(__VA_ARGS__)
typedef void  (*timer_f)();
struct timespec timer_ageQueue();
uint64_t        timer_setTimer(struct timespec delay, const char *name, timer_f action, void *);
void           *timer_clearTimer(uint64_t timer_id);
void            debugQueue(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd);
