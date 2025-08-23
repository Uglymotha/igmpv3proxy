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
*   igmpv3proxy.h - Header file for common includes.
*/
#ifndef IGMPV3PROXY_H
#define IGMPV3PROXY_H

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
#include <pwd.h>
#include <ifaddrs.h>
#include <ctype.h>
#include <dirent.h>
#include <libgen.h>

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/resource.h>

#include <net/if.h>
#include <arpa/inet.h>

//#################################################################################
//  Global definitions and declarations.
//#################################################################################

// Keeps common configuration settings.
static char RUN_PATHS[]="/run /var/run /tmp /var/tmp";
static char CFG_PATHS[]="/etc/ /usr/local/etc/ /var/etc/ /usr/local/var/etc/";
struct Config {
    uint8_t             cnt;
    // Daemon parameters.
    bool                notAsDaemon;
    char               *configFilePath;
    char               *runPath;
    struct passwd      *user;
    struct group       *group;
    char               *chroot;
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
    // Last member probe.
    uint8_t             lastMemberQueryInterval;
    uint8_t             lastMemberQueryCount;
    // Set if upstream leave messages should be sent instantly..
    bool                quickLeave;
    // Size in bytes of hash table of downstream hosts used for fast leave
    uint32_t            dHostsHTSize;
    uint32_t            hashSeed;
    uint16_t            mcTables;
    // Mroute tables only supported on linux
    int                 defaultTable;
    bool                disableIpMrules;
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
    bool                log2Stderr;                     // Log to stderr instead of to syslog / file
    // Set if nneed to detect new interface.
    uint32_t            rescanVif;
    // Set if nneed to detect config change.
    uint32_t            rescanConf;
    // Default BW Control interval.
    uint32_t            bwControl;
    // Set if need to proxy IANA local multicast range 224.0.0.0/8.
    bool                proxyLocalMc;
    // Set if must not participate in IGMP querier election.
    bool                querierElection;
    // Set if must not validate igmp checksum.
    bool                cksumVerify;
};

// Memory statistics.
struct memstats {
    int64_t mct, src, mfc, ifm;       // Multicast Forwarding Table
    int64_t ifd, fil, vif;            // Interfaces
    int64_t rcv, snd;                 // Buffers
    int64_t qry, tmr, var;            // Queries, Timers, various.
};

// Forked child processes.
struct pt {
    pid_t   pid;
    int     tbl;
    int8_t  st;
};
struct chld {
    int        onr;
    int        nr;
    struct pt *c;
};

// Timers for proxy control.
struct timers {
    intptr_t rescanConf;
    intptr_t rescanVif;
};

// Linked list of filters.
struct subnet {
    uint32_t  ip;
    uint32_t  mask;
};
struct filters {
    struct subnet         src;                          // Source / Sender) address
    struct subnet         dst;                          // Destination multicast group
    uint8_t               dir;                          // Filter direction (up/downstream)
    uint8_t               mode;                         // Mode for group (include / exclude)
    uint64_t              action;                       // Action (aalow / block / ratelimit)
    struct filters       *next;
};
#define FILSZ (sizeof(struct filters))
#define ALLOW 1
#define BLOCK 0
#define FILTERANY (struct filters){ {INADDR_ANY, INADDR_ANY}, {INADDR_ANY, INADDR_ANY}, 3, 3, ALLOW, NULL }

// Keeps configured Querier parameters.
struct queryParam {
    uint32_t            ip;                             // Configured querier IP
    uint8_t             ver;                            // Configured querier version
    bool                election;                       // Configured querier election mode
    uint8_t             robustness;                     // Configured robustness value
    uint8_t             interval;                       // Configured query interval
    uint8_t             responseInterval;               // Configured query response interval
    uint8_t             lmInterval;                     // Configured lastmember query interval value
    uint8_t             lmCount;                        // Configured lastmember count value
    uint8_t             startupQueryInterval;           // Configured startup query interval
    uint8_t             startupQueryCount;              // Configured startup query count
};

// Structure to keep configuration for VIFs.
struct vifConfig {
    char                name[IF_NAMESIZE];
    int                 tbl;                            // Mroute Table for Interface
    uint8_t             state;                          // Configured interface state
    uint8_t             threshold;                      // Interface MC TTL
    uint64_t            ratelimit;                      // Interface ratelimit
    struct queryParam   qry;                            // Configured query parameters
    uint32_t            bwControl;                      // BW Control interval
    bool                disableIpMrules;                // Disable ip mrules actions for interface
    bool                noDefaultFilter;                // Do not add default filters to interface
    bool                cksumVerify;                    // Do not validate igmp checksums on interface
    bool                quickLeave;                     // Fast upstream leave
    bool                proxyLocalMc;                   // Forward local multicast
    struct filters     *filters;                        // ACL for interface
    struct filters     *rates;                          // Ratelimiters for interface
    struct vifConfig   *next;
};
#define VIFSZ (sizeof(struct vifConfig))
#define DEFAULT_VIFCONF (struct vifConfig){ "", CONF->defaultTable, CONF->defaultInterfaceState, CONF->defaultThreshold,           \
                                            CONF->defaultRatelimit, {CONF->querierIp, CONF->querierVer, CONF->querierElection,     \
                                            CONF->robustnessValue, CONF->queryInterval, CONF->queryResponseInterval,               \
                                            CONF->lastMemberQueryInterval, CONF->lastMemberQueryCount, 0, 0}, CONF->bwControl,     \
                                            CONF->disableIpMrules, false, CONF->cksumVerify, CONF->quickLeave, CONF->proxyLocalMc, \
                                            NULL, NULL, *VIFCONF }

// Running querier status for interface.
struct querier {                                        // igmp querier status for interface
    uint32_t       ip;                                  // Querier IP
    uint8_t        ver;                                 // Querier version
    uint8_t        qqi;                                 // Queriers query interval
    uint8_t        qrv;                                 // Queriers robustness value
    uint8_t        mrc;                                 // Queriers max response code
    intptr_t       Timer;                               // Self / Other Querier timer
    intptr_t       ageTimer;                            // Route aging timer
};
#define DEFAULT_QUERIER (struct querier){ IfDp->conf->qry.ip, IfDp->conf->qry.ver, IfDp->conf->qry.interval,   \
                                          IfDp->conf->qry.robustness, IfDp->conf->qry.responseInterval, (intptr_t)NULL,  \
                                          (intptr_t)NULL }
#define OTHER_QUERIER (struct querier){ src, ver, \
                                        ver == 3 ? (igmpv3->igmp_qqi > 0 ? igmpv3->igmp_qqi : DEFAULT_INTERVAL_QUERY)             \
                                                 : IfDp->conf->qry.interval,                                                      \
                                        ver == 3 ? ((igmpv3->igmp_misc & 0x7) > 0 ? igmpv3->igmp_misc & 0x7 : DEFAULT_ROBUSTNESS) \
                                                 : IfDp->conf->qry.robustness, ver != 1 ? igmpv3->igmp_code : 10,                 \
                                        IfDp->querier.Timer, IfDp->querier.ageTimer }

// Interfaces configuration.
struct ifStats {
    uint64_t                      iBytes, oBytes;        // Total bytes sent/received on interface
    uint64_t                      iRate,  oRate;         // Rate in bytes / s
    uint64_t                      rqCnt;                 // IGMP Received Query Count
    uint64_t                      sqCnt;                 // IGMP Sent Query Count
};
struct IfDesc {
    char                          Name[IF_NAMESIZE];
    struct in_addr                InAdr;                 // Primary IP
    uint32_t                      Flags;                 // Operational flags
    uint32_t                      mtu;                   // Interface MTU
    uint8_t                       state;                 // Operational state
    struct vifConfig             *conf;                  // Pointer to interface configuraion
    bool                          filCh;                 // Flag for filter change during config reload
    struct querier                querier;               // igmp querier for interface
    struct ifStats                stats;                 // Interface statisticas and counters
    unsigned int                  sysidx;                // Interface system index
    uint8_t                       index;                 // MCast vif index
    intptr_t                      bwTimer;               // BW Control timerd id
    void                         *dMct;                  // Pointers to active downstream groups for vif
    void                         *uMct;                  // Pointers to active upstream groups for vif
    void                         *qLst;                  // List of active queries on interface
    struct IfDesc                *nextvif;               // List of active multicast routing vifs.
    struct IfDesc                *next;
};
#define IFSZ (sizeof(struct IfDesc))
#define DEFAULT_IFDESC (struct IfDesc){ "", {0}, 0, 0, 0x80, NULL, false, {(uint32_t)-1, 3, 0, 0, 0, 0, 0}, \
                                        {0, 0, 0, 0}, 0, (uint8_t)-1, 0, NULL, NULL, NULL, NULL, IfDescL }

/// Interface states.
#define IF_STATE_DISABLED      0                         // Interface should be ignored.
#define IS_DISABLED(x)         ((x & 0x3) == 0)
#define IF_STATE_UPSTREAM      1                         // Interface is upstream
#define IS_UPSTREAM(x)         (x & 0x1)
#define IF_STATE_DOWNSTREAM    2                         // Interface is downstream
#define IS_DOWNSTREAM(x)       (x & 0x2)
#define IF_STATE_UPDOWNSTREAM  3                         // Interface is both up and downstream
#define IS_UPDOWNSTREAM(x)     ((x & 0x3) == 3)
#define IF_OLDSTATE(x)         ((x->state >> 2) & 0x3)
#define IF_NEWSTATE(x)         (x->state & 0x3)

// In / output buffering.
#define BUF_SIZE   9216                                 // Jumbo MTU
#define K_BUF_SIZE  512                                 // Default kernel ring buffer size in KB
#define REQQSZ       16                                 // Default request queue size
#define TMQSZ         4                                 // Default timer queue size

// Limits of configuration / token.
#define READ_BUFFER_SIZE      512
#define MAX_TOKEN_LENGTH      128
#define MAX_GROUPNAME_SIZE     32

// Multicast default values.
#define DEFAULT_ROBUSTNESS  2
#define DEFAULT_THRESHOLD   1
#define DEFAULT_RATELIMIT   0

// Query default values.
#define DEFAULT_INTERVAL_QUERY          125
#define DEFAULT_INTERVAL_QUERY_RESPONSE 100

// IGMP Global Values.
#define MIN_IP_HEADER_LEN   20
#define MAX_IP_HEADER_LEN   60
#define IP_HEADER_RAOPT_LEN 24

// Route parameters.
#define DEFAULT_MAX_ORIGINS    64                       // Maximun nr of group sources.
#define DEFAULT_HASHTABLE_SIZE 32                       // Default host tracking hashtable size.
#define DEFAULT_ROUTE_TABLES   32                       // Default hash table size for route table.

// Signal Handling.
#define GOT_SIGINT  0x01
#define GOT_SIGHUP  0x02
#define GOT_SIGUSR1 0x04
#define GOT_SIGUSR2 0x08
#define GOT_SIGURG  0x10
#define GOT_SIGCHLD 0x20
#define GOT_SIGPIPE 0x40
#define GOT_SIGTERM 0x80
#define NOSIG      (sigstatus == 0)
#define STARTUP    (sigstatus & 0x01)
#define CONFRELOAD (sigstatus & GOT_SIGUSR1)
#define IFREBUILD  (sigstatus & GOT_SIGUSR2)
#define SHUP       (sigstatus & GOT_SIGHUP)
#define RESTART    (sigstatus & GOT_SIGURG)
#define SCHLD      (sigstatus & GOT_SIGCHLD)
#define SPIPE      (sigstatus & GOT_SIGPIPE)
#define SHUTDOWN   (sigstatus & GOT_SIGTERM)

static const char *SIGS[32] = { "", "SIGHUP", "SIGINT", "", "", "", "SIGABRT", "", "", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2",
                                "SIGPIPE", "", "SIGTERM", "SIGURG", "SIGCHLD", "", "", "SIGCHLD", "", "", "SIGURG", "", "", "",
                                "", "", "", "SIGUSR1", "SIGUSR2" };
static const char *exitmsg[16] = { "exited", "failed", "was terminated", "failed to initialize", "failed to fork",
                                   "ran out of memory", "aborted", "failed to load config", "failed to execute", "was murdered",
                                   "", "segfaulted", "", "", "" , "was terminated" };

#define SETSIGS     struct sigaction sa = { 0 };              \
                    sa.sa_sigaction = signalHandler;          \
                    sa.sa_flags = SA_SIGINFO;                 \
                    sigemptyset(&sa.sa_mask);                 \
                    sigaction(SIGTERM, &sa, NULL);            \
                    sigaction(SIGINT,  &sa, NULL);            \
                    sigaction(SIGHUP,  &sa, NULL);            \
                    sigaction(SIGUSR1, &sa, NULL);            \
                    sigaction(SIGUSR2, &sa, NULL);            \
                    sigaction(SIGURG,  &sa, NULL);            \
                    sigaction(SIGPIPE, &sa, NULL);            \
                    sigaction(SIGCHLD, &sa, NULL)
#define BLOCKSIGS   signal(SIGUSR1, SIG_IGN);  \
                    signal(SIGUSR2, SIG_IGN);  \
                    signal(SIGHUP, SIG_IGN);   \
                    signal(SIGCHLD, SIG_DFL);  \
                    signal(SIGURG, SIG_IGN);   \
                    signal(SIGPIPE, SIG_IGN)

// Some private errnos to use for logging and error exiting.
#define  eABNRML -1
#define  eNOINIT  3
#define  eNOFORK  4
#define  eNOMEM   5
#define  eNOCONF -7

// CLI Defines.
#define CLI_CMD_BUF 256

// Memory (de)allocation macro's, which check for valid size and counts.
#define _malloc(p,m,s)      if ((errno = 0) || ! (p = malloc(s)) || (memuse.m += (s)) <= 0 || (++memalloc.m) <= 0) {       \
                                getMemStats(0, -1);                                                                        \
                                LOG(LOG_CRIT, SIGABRT, "Invalid malloc() in %s() (%s:%d)",  __func__, __FILE__, __LINE__); }
#define _calloc(p,n,m,s)    if ((errno = 0) || ! (p = calloc(n, s)) || (memuse.m += (n * (s))) <= 0 || (++memalloc.m) <= 0) {  \
                                getMemStats(0, -1);                                                                            \
                                LOG(LOG_CRIT, SIGABRT, "Invalid calloc() in %s() (%s:%d)", __func__, __FILE__, __LINE__); }
#define _realloc(p,m,sp,sm) if ((errno = 0) || (p && (++memfree.m) <= 0) || ! (p = realloc(p, sp))                         \
                                || (memuse.m += (-(sm) + (sp))) <= 0 || (++memalloc.m) <= 0) {                             \
                                getMemStats(0, -1);                                                                        \
                                LOG(LOG_CRIT, SIGABRT, "Invalid realloc() in %s() (%s:%d)", __func__, __FILE__, __LINE__); }
#define _recalloc(p,m,sp,sm) if((errno = 0) || (p && (++memfree.m) <= 0) || ! (p = realloc(p, sp))                          \
                                || (sp > sm && ! memset((char *)p + (sm), 0, (sp) - (sm)))                                  \
                                || (memuse.m += (-(sm) + (sp))) <= 0 || (++memalloc.m) <= 0) {                              \
                                getMemStats(0,-1);                                                                          \
                                LOG(LOG_CRIT, SIGABRT, "Invalid recalloc() in %s() (%s:%d)", __func__, __FILE__, __LINE__); }
#define _free(p, m, s)     {if ((p) && ((errno = 0) || s <= 0 || (memuse.m -=s) < 0 || (++memfree.m) <= 0)) {                 \
                                getMemStats(0, -1);                                                                           \
                                LOG(LOG_CRIT, SIGABRT, "Invalid free() in %s() (%s:%d)", __func__, __FILE__, __LINE__); }     \
                            if (p) { free(p); p = NULL; }                                                                     \
                            else LOG(LOG_ERR, 0, "nullptr free of size %d in %s() (%s:%d)", s, __func__, __FILE__, __LINE__); }

// Bit manipulation macros.
#define BIT_SET(X,n)     ((X) |= 1 << (n))
#define BIT_CLR(X,n)     ((X) &= ~(1 << (n)))
#define BIT_TST(X,n)     (((X) >> (n)) & 1)

// Conditional loop macro's.
#define IF_FOR(x, y)       if  (x) for y
#define FOR_IF(x, y)       for x if  (y)
#define IF_FOR_IF(x, y, z) if  (x) for y if (z)

//#################################################################################
// Common IGMPv3 includes. Various OS dont provide common structs, so we just use our own.
//#################################################################################

// Set type of control message structure for received socket data.
#ifdef IP_PKTINFO
    #define IFINFO IP_PKTINFO
#elif IP_RECVIF
    #define IFINFO IP_RECVIF
#endif
//  Socket control message union.
union cmsg {
struct cmsghdr cmsgHdr;
#ifdef IP_PKTINFO
    char cmsgData[sizeof(struct msghdr) + sizeof(struct in_pktinfo)];
#elif IP_RECVIF
    char cmsgData[sizeof(struct msghdr) + sizeof(struct sockaddr_dl)];
#endif
};

// IGMP Query Definition.
struct igmpv3_query {
    u_char          igmp_type;                         // version & type of IGMP message
    u_char          igmp_code;                         // subtype for routing msgs
    u_short         igmp_cksum;                        // IP-style checksum
    struct in_addr  igmp_group;                        // group address being reported
    u_char          igmp_misc;                         // reserved/suppress/robustness
    u_char          igmp_qqi;                          // querier's query interval
    u_short         igmp_nsrcs;                        // number of sources
    struct in_addr  igmp_src[];                        // source addresses
};

// IGMP v3 Group Record Definition.
struct igmpv3_grec {
    u_int8_t grec_type;                                // Group record type
    u_int8_t grec_auxwords;                            // Nr of auxwords data after sources
    u_int16_t grec_nsrcs;                              // Nr of sources in group report
    struct in_addr grec_mca;                           // Group multicast address
    struct in_addr grec_src[];                         // Array of source addresses
};

// IGMP Report Definition.
struct igmpv3_report {
    u_int8_t igmp_type;                                // IGMP Report type
    u_int8_t igmp_resv1;
    u_int16_t igmp_cksum;                              // IGMP checksum
    u_int16_t igmp_resv2;
    u_int16_t igmp_ngrec;                              // Nr. of group records in report
    struct igmpv3_grec igmp_grec[];                    // Array of group records
};

// IGMP Defines.
#define IGMPV3_MODE_IS_INCLUDE    1
#define IGMPV3_MODE_IS_EXCLUDE    2
#define IGMPV3_CHANGE_TO_INCLUDE  3
#define IGMPV3_CHANGE_TO_EXCLUDE  4
#define IGMPV3_ALLOW_NEW_SOURCES  5
#define IGMPV3_BLOCK_OLD_SOURCES  6
#define IGMPV3_MINLEN            12
#define IGMP_LOCAL(x)            ((ntohl(x) & 0xFFFFFF00) == 0xE0000000)

//##################################################################################
//  Global Variables.
//############A#####################################################################

// Memory Statistics.
extern struct memstats  memuse, memalloc, memfree;

// Filename, Help string.
extern char            *fileName, Usage[], tS[32];

// Timekeeping.
extern struct timespec  starttime, curtime, utcoff;

// Process Signaling.
extern uint8_t          sigstatus, logwarning;

// MRT route table id. Linux only, not supported on FreeBSD.
extern struct chld      chld;
extern int              mrt_tbl;

// Upstream vif mask.
extern uint32_t         uVifs;

// Global IGMP groups.
extern uint32_t         allhosts_group;                // All hosts addr in net order
extern uint32_t         allrouters_group;              // All hosts addr in net order
extern uint32_t         alligmp3_group;                // IGMPv3 addr in net order
static char             strBuf[64];                    // Temp string buffer.

//#################################################################################
//  Lib function prototypes.
//#################################################################################
/**
*   igmpproxy.c
*/
#define       TIME_STR(x,y) clock_gettime(CLOCK_REALTIME, &y); \
                            strcpy(x, asctime(localtime(&y.tv_sec))); \
                            x[strlen(x) - 1] = '\0'
int  igmpProxyFork(int tbl);
void igmpProxyCleanUp(int code);

/**
*   config.c
*/
#define            VIFCONF getVifConf()
#define            CONF getConfig(false)
#define            OLDCONF getConfig(true)
struct Config     *getConfig(bool old);
struct vifConfig **getVifConf(void);
void               freeConfig(bool old);
void               reloadConfig(intptr_t *tid);
bool               loadConfig(char *cfgFile);

/**
*   cli.c
*/
int  initCli(int mode);
int  closeCliFd(void);
void acceptCli(void);
void cliCmd(char *cmd, int tbl);

/**
*   ifvc.c
*/
#define        IFL(x)                 x = getIfL(); x; x = x->next
#define        GETIFL(x)              for (IFL(x))
#define        GETIFL_IF(x, y)        GETIFL(x) if (y)
#define        VIFL(x)                x = getVifL(); x; x = x->nextvif
#define        GETVIFL(x)             for (VIFL(x))
#define        IF_GETVIFL(y, x)       if (y) GETVIFL(x)
#define        GETVIFL_IF(x, y)       GETVIFL(x) if (y)
#define        IF_GETVIFL_IF(x, y, z) if (x) GETVIFL_IF(y, z)
void           freeIfDescL(void);
void           rebuildIfVc(intptr_t *tid);
void           buildIfVc(void);
struct IfDesc *getIfL(void);
struct IfDesc *getVifL(void);
struct IfDesc *getIf(unsigned int ix, char name[IF_NAMESIZE], int mode);
void           getIfStats(struct IfDesc *IfDp, int h, int fd);
void           getIfFilters(struct IfDesc *IfDp, int h, int fd);

/**
*   igmp.c
*/
int    initIgmp(int mode);
void   acceptIgmp(int fd);
void   sendIgmp(struct IfDesc *IfDp, struct igmpv3_query *query);
void   sendGeneralMemberQuery(struct IfDesc *IfDp);

/**
*   lib.c
*/
#define         LOG(x, ...) (   ((logwarning |= ((x) <= LOG_WARNING)) || true)                \
                             && !((x) <= CONF->logLevel) ?: myLog((x), __func__, __VA_ARGS__) \
                             && !(errno = 0))
#define         setHash(t, h)   if (h != (uint32_t)-1) BIT_SET(t[h / 64], h % 64)
#define         clearHash(t, h) if (h != (uint32_t)-1) BIT_CLR(t[h / 64], h % 64)
#define         testHash(t, h)  (BIT_TST(t[h / 64], h % 64))
inline bool     noHash(register uint64_t *t) { register uint64_t i = 0, n = CONF->dHostsHTSize >> 3;
                                               while(i < n && t[i] == 0) i++; return (i >= n); }
const char     *inetFmt(uint32_t addr, uint32_t mask);
uint16_t        inetChksum(uint16_t *addr, int len);
int             confFilter(const struct dirent *d);
struct timespec timeDiff(struct timespec t1, struct timespec t2);
struct timespec timeDelay(int delay);
uint32_t        s_addr_from_sockaddr(const struct sockaddr *addr);
bool            parseSubnetAddress(const char *str, uint32_t *addr, uint32_t *mask);
uint32_t        murmurhash3(register uint32_t x);
uint16_t        sortArr(register uint32_t *arr, register uint16_t nr);
const char     *igmpPacketKind(unsigned int type, unsigned int code);
const char     *grecKind(unsigned int type);
uint16_t        grecType(struct igmpv3_grec *grec);
uint16_t        grecNscrs(struct igmpv3_grec *grec);
uint16_t        getIgmpExp(register int val, register int d);
bool            myLog(int Serverity, const char *func, int Errno, const char *FmtSt, ...);
void            getMemStats(int h, int cli_fd);
void            ipRules(int tbl, bool activate);

/**
*   kern.c
*/
#define MROUTERFD k_getMrouterFD()
void    k_set_rcvbuf(int bufsize);
void    k_set_ttl(uint8_t ttl);
void    k_set_loop(bool l);
void    k_set_if(struct IfDesc *IfDp);
bool    k_updateGroup(struct IfDesc *IfDp, bool join, uint32_t group, int mode, uint32_t source);
int     k_setSourceFilter(struct IfDesc *IfDp, uint32_t group, uint32_t fmode, uint32_t nsrcs, uint32_t *slist);
int     k_getMrouterFD(void);
int     k_enableMRouter(void);
int     k_disableMRouter(void);
bool    k_addVIF(struct IfDesc *IfDp);
void    k_delVIF(struct IfDesc *IfDp);
void    k_addMRoute(uint32_t src, uint32_t group, struct IfDesc *IfDp, uint8_t ttlVc[MAXVIFS]);
void    k_delMRoute(uint32_t src, uint32_t group, int vif);
void    k_deleteUpcalls(uint32_t src, uint32_t group);

/**
*   mctable.c
*/
void     bwControl(struct IfDesc *IfDp);
void     clearGroups(void *Dp);
void     updateGroup(struct IfDesc *IfDp, register uint32_t src, struct igmpv3_grec *grec);
void     activateRoute(struct IfDesc *IfDp, void *_src, register uint32_t ip, register uint32_t group, bool activate);
void     ageGroups(struct IfDesc *IfDp);
void     logRouteTable(const char *header, int h, int fd, uint32_t addr, uint32_t mask, struct IfDesc *IfDp);
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
void     processBwUpcall(struct bw_upcall *bwUpc, int nr);
#endif

/**
*   querier.c
*/
#define  IQUERY (IfDp->querier.ip == IfDp->conf->qry.ip && IfDp->conf->qry.lmCount > 0)
void     ctrlQuerier(int start, struct IfDesc *IfDp);
void     processGroupQuery(struct IfDesc *IfDp, struct igmpv3_query *query, uint32_t nsrcs, uint8_t ver);

/**
*   timers.c
*/
#define         DEBUGQUEUE(x, y, z) if (CONF->logLevel == LOG_DEBUG || z >= 0) timerDebugQueue(x, y, z)
struct timespec timerAgeQueue(void);
intptr_t        timerSet(int delay, const char *name, void (*func)(), void *);
intptr_t        timerClear(intptr_t timer_id);
void            timerDebugQueue(const char *header, int h, int fd);

#endif // IGMPV3PROXY_H_INCLUDED
