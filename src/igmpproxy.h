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
*   igmpproxy.h - Header file for common includes.
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

//#################################################################################
//  Global definitions and declarations.
//#################################################################################

// Bit manipulation macros.
#define BIT_ZERO(X)      ((X) = 0)
#define BIT_SET(X,n)     ((X) |= 1 << (n))
#define BIT_CLR(X,n)     ((X) &= ~(1 << (n)))
#define BIT_TST(X,n)     ((X) & 1 << (n))

// Set type of control message structure for received socket data.
#ifdef IP_PKTINFO
#define IFINFO IP_PKTINFO
#elif IP_RECVIF
#define IFINFO IP_RECVIF
#endif

// Buffering.
#define BUF_SIZE 9216

// Limit of configuration token.
#define READ_BUFFER_SIZE    2048
#define MAX_TOKEN_LENGTH    128
#define MAX_GROUPNAME_SIZE  32

// Keeps common configuration settings.
struct Config {
    // Daemon parameters.
    bool                notAsDaemon;
    char               *configFilePath;
    char               *runPath;
    // Default interface igmp parameters.
    uint32_t            querierIp;
    unsigned int        robustnessValue;
    unsigned int        queryInterval;
    unsigned int        queryResponseInterval;
    unsigned int        bwControlInterval;
    // Used on querier startup.
    unsigned int        startupQueryInterval;
    // Last member probe.
    unsigned int        lastMemberQueryInterval;
    unsigned int        lastMemberQueryCount;
    // Set if upstream leave messages should be sent instantly..
    bool                fastUpstreamLeave;
    // Size in bytes of hash table of downstream hosts used for fast leave
    unsigned int        downstreamHostsHashTableSize;
    // Max origins for route when bw control is disabled.
    unsigned int        maxOrigins;
    // Set default interface status and parameters.
    unsigned short      defaultInterfaceState;   // 0: disable, 2: downstream
    unsigned char       defaultThreshold;
    unsigned int        defaultRatelimit;
    // Logging Parameters.
    int                 logLevel;
    bool                logFile;
    char               *logFilePath;
    bool                log2Stderr;              // Log to stderr instead of to syslog / file
    // Set if nneed to detect new interface.
    unsigned int        rescanVif;
    // Set if nneed to detect config change.
    unsigned int        rescanConf;
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

struct filters {
    struct subnet {
        uint32_t  ip;
        uint32_t  mask;
    }                     src, dst;
    uint64_t              action;
    struct filters       *next;
};

// Keeps configured Querier parameters.
struct queryParam {
    uint32_t            ip;
    bool                election;                // Configured querier election mode
    uint8_t             robustness;              // Configured robustness value
    unsigned int        interval;                // Configured query interval
    unsigned int        responseInterval;        // Configured query response interval
    unsigned int        lmInterval;              // Configured lastmember query interval value
    uint8_t             lmCount;                 // Configured lastmember count value
};

// Structure to keep configuration for VIFs.
struct vifconfig {
    char                name[IF_NAMESIZE];
    unsigned short      state;
    unsigned int        threshold;
    uint64_t            ratelimit;
    struct queryParam   qry;
    unsigned int       *index;                   // Pointer to matching IfDesc->index
    bool                compat;                  // Compatibility with old altnet/whitelist
    struct filters     *filters;
    struct vifconfig   *next;
};

// Limits on vifs / routes
#define MAX_UPS_VIFS    8

// Interface states
#define IF_STATE_DISABLED      0   // Interface should be ignored.
#define IF_STATE_UPSTREAM      1   // Interface is the upstream interface
#define IF_STATE_DOWNSTREAM    2   // Interface is a downstream interface

// Interfaces configuration.
struct IfDesc {
    char                          Name[IF_NAMESIZE];
    struct in_addr                InAdr;
    unsigned short                Flags;
    unsigned short                state;
    struct queryParam             *qry;
    struct querier {                                        // igmp querier for interface
        uint32_t       ip;
        uint8_t        ver;                                 // Querier version
        uint8_t        qqi;                                 // Queriers query interval
        uint8_t        qrv;                                 // Queriers robustness value
        uint8_t        mrc;                                 // Queriers max response code
        uint64_t       v1Timer;                             // v1 Querier timer
        uint64_t       v2Timer;                             // v2 Querier timer
        uint64_t       v3Timer;                             // v3 Querier timer
        uint64_t       ageTimer;                            // Route aging timer
    }                             querier;
    struct Igmp {
        uint8_t        ver;
        uint64_t       v1Timer;                             // V1 timer.
        uint64_t       v2Timer;                             // V2 timer.
    }                             igmp;
    struct filters               *aliases;                  // All aliases / subnets for interface
    struct filters               *filters;                  // Interface filters (linked to configed filters)
    unsigned char                 threshold;                // ttl limit
    unsigned int                  startupQueryInterval;     // Interface startup query interval
    uint8_t                       startupQueryCount;        // Interface startup query count
    uint64_t                      bytes, rate, ratelimit;   // bw control
    unsigned int                  index;
};

// Multicast default values.
#define DEFAULT_ROBUSTNESS  2
#define DEFAULT_THRESHOLD   1
#define DEFAULT_RATELIMIT   0

// Query default values.
#define DEFAULT_INTERVAL_QUERY          125
#define DEFAULT_INTERVAL_QUERY_RESPONSE 100

// IGMP Global Values.
#define MAX_IP_PACKET_LEN	576
#define MIN_IP_HEADER_LEN	20
#define MAX_IP_HEADER_LEN	60
#define IP_HEADER_RAOPT_LEN	24

// Route parameters.
#define DEFAULT_MAX_ORIGINS     64  // Maximun nr of route sources, controlable by maxorigins config paramter, in which case this also acts as mimimun
#define DEFAULT_HASHTABLE_SIZE  32  // Default host tracking hashtable size.

// Group specific query structs.
typedef struct {
    uint32_t        group;
    char            sourceVif[IF_NAMESIZE];
    bool            started;
    bool            aging;
    uint64_t        timerid;
} GroupVifDesc;

struct gvDescL {
    GroupVifDesc     *gvDesc;
    struct gvDescL   *next;
};

// Signal Handling. 0 = no signal, 2 = SIGHUP, 4 = SIGUSR1, 8 = SIGUSR2, 5 = Timed Reload, 9 = Timed Rebuild
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
#define STARTUP NOSIG

// CLI Defines.
#define CLI_CMD_BUF    256
#define CLI_SOCK_PATHS "/run /var/run /tmp /var/tmp"

//#################################################################################
//  Global Variables.
//############A#####################################################################
// Timekeeping
extern struct timespec curtime, utcoff;

// Process Signaling.
extern unsigned int sighandled, sigstatus;

// Global IGMP groups.
extern uint32_t allhosts_group;            /* All hosts addr in net order */
extern uint32_t allrouters_group;          /* All hosts addr in net order */
extern uint32_t alligmp3_group;            /* IGMPv3 addr in net order */

//#################################################################################
//  Lib function prototypes.
//#################################################################################

/**
*   syslog.c
*/
void my_log(int Serverity, int Errno, const char *FmtSt, ...);

/**
*   ifvc.c
*/
void           freeIfDescP(int old);
void           rebuildIfVc(uint64_t *tid);
void           buildIfVc(void);
struct IfDesc *getIfByName(const char *IfName, int old);
void           getNextIf(struct IfDesc **IfDp);
uint64_t       isAddressValidForIf(void *Dp, register int ifdesc, register uint32_t src, register uint32_t group);
void           getIfStats(int h, struct sockaddr_un *cliSockAddr, int fd);
void           getIfFilters(int h, struct sockaddr_un *cliSockAddr, int fd);

/**
*   mroute-api.c
*/
int  getMrouterFD(void);
int  enableMRouter(void);
void disableMRouter(void);
void addVIF(struct IfDesc *Dp);
void delVIF(struct IfDesc *Dp);
int  addMRoute(uint32_t src, uint32_t group, int vif, uint8_t ttlVc[MAXVIFS]);
int  delMRoute(uint32_t src, uint32_t group, int vif);
void deleteUpcalls(uint32_t src, uint32_t group);

/**
*   config.c
*/
#define CONFIG getConfig()
struct Config *getConfig(void);
void           freeConfig(int old);
void           reloadConfig(uint64_t *tid);
bool           loadConfig(void);
void           configureVifs(void);
void           createVifs(void);

/**
*   cli.c
*/
int  openCliSock(void);
int  cliSetGroup(int gid);
void processCliCon(int fd);
void cliCmd(char *cmd);

/**
*   igmp.c
*/
char    *initIgmp(void);
void     acceptIgmp(int recvlen, struct msghdr msgHdr);
uint16_t getIgmpExp(int val, int d);
void     ctrlQuerier(int start, struct IfDesc *IfDp);
void     freeQueriers(void);
void     sendGroupSpecificMemberQuery(GroupVifDesc *gvDesc);
void     sendGeneralMemberQuery(struct IfDesc *IfDp);

/**
*   lib.c
*/
char    *fmtInAdr(struct in_addr InAdr, int pos);
char    *inetFmt(uint32_t addr, int pos);
char    *inetFmts(uint32_t addr, uint32_t mask, int pos);
uint16_t inetChksum(uint16_t *addr, int len);

/**
*   kern.c
*/
void k_set_rcvbuf(int bufsize, int minsize);
int  k_set_ttl(int t);
void k_set_loop(int l);
void k_set_if(struct IfDesc *IfDp);
bool k_joinMcGroup(struct IfDesc *IfDp, uint32_t mcastaddr);
bool k_leaveMcGroup(struct IfDesc *IfDp, uint32_t mcastaddr);

/**
*   rttable.c
*/
uint64_t           getGroupBw(struct subnet group, void *Dp, register int ifdesc);
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
void               processBwUpcall(struct bw_upcall *bwUpc, int nr);
#endif
void               bwControl(uint64_t *tid);
struct gvDescL    *clearRoutes(void *Dp1, void *Dp2);
uint32_t           getRouteVifbits(register uint32_t group);
struct RouteTable *insertRoute(register uint32_t src, register uint32_t group, struct IfDesc *IfDp);
void               activateRoute(register uint32_t src, register uint32_t group, struct IfDesc *IfDp);
void               ageActiveRoutes(struct IfDesc *IfDp);
bool               setRouteLastMemberMode(uint32_t group, uint32_t src, struct IfDesc *IfDp);
bool               lastMemberGroupAge(uint32_t group, struct IfDesc *IfDp);
void               logRouteTable(const char *header, int h, const struct sockaddr_un *cliSockAddr, int fd);

/**
*   callout.c
*/
typedef void  (*timer_f)(void *);
void            timer_freeQueue(void);
struct timespec timer_ageQueue();
uint64_t        timer_setTimer(uint64_t timer_id, unsigned int delay, const char name[40], timer_f action, void *);
void           *timer_clearTimer(uint64_t timer_id);
