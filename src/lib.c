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
*   lib.c - Various library and common processing functions.
*/

#include "igmpv3proxy.h"

char Usage[] =
"Usage: %s [-h | -V] [-t table] [-c [-cbriftm...] [-h]] [[-n | -v | -d] <configfile>]\n"
"\n"
"   -h   Display this help screen\n"
"   -V   Display version.\n"
"   -n   Do not run as a daemon\n"
"   -v   Run in verbose mode, Output all messages on stderr. Implies -n.\n"
"   -vv  Run in more verbose mode. Implies -n.\n"
"   -d   Run in debug mode. Implies -vv.\n"
"   -t   Operate on routing table.\n"
"   -c   Daemon control and statistics.\n"
"        -c   Reload Configuration.\n"
"        -b   Rebuild Interfaces.\n"
"        -p   Display Multiple Routing Table Information.\n"
"        -r   Display routing table.\n"
"        -i   Display interface statistics.\n"
"        -f   Display configured filters.\n"
"        -t   Display running timers.\n"
"        -m   Display Memory Statistics.\n"
"        -h   Do not display headers.\n"
"\n"
PACKAGE_STRING "\n";

// Buffers for representations of IP addresses / IGMP / GREC types, to be passed to inetFmt(), grecKind() and igmpPacketKind().
static char    s[8][STRBUF];
static uint64_t pos = 0;

/**
*   Formats log string based on condition.
*/
char *strFmt(bool cond, const char *s1, const char *s2, ...) {
    uint8_t i = pos++%8;
    va_list argPt;

    va_start(argPt, s2);
    vsnprintf(s[i], sizeof(s[i]), cond ? s1 : s2, argPt);
    return s[i];
}

/**
*   Convert an IP subnet number in network format into a printable string including the netmask as a number of bits.
*/
const char *inetFmt(uint32_t addr, uint32_t mask) {
    uint8_t i = pos++%8, bits = 33 - ffs(ntohl(mask)), *a = (uint8_t *)&addr;

    if (addr == 0 && mask == 0)
        sprintf(s[i], "0/0");
    else if (mask == 0 || mask == (uint32_t)-1)
        sprintf(s[i], "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    else if (((uint8_t *)&mask)[3] != 0)
        sprintf(s[i], "%u.%u.%u.%u/%d", a[0], a[1], a[2], a[3], bits);
    else if (((uint8_t *)&mask)[2] != 0)
        sprintf(s[i], "%u.%u.%u.0/%d",    a[0], a[1], a[2], bits);
    else if (((uint8_t *)&mask)[1] != 0)
        sprintf(s[i], "%u.%u.0.0/%d",       a[0], a[1], bits);
    else
        sprintf(s[i], "%u.0.0.0/%d",          a[0], bits);
    return s[i];
}

/**
*   Filters *.conf files from dirent.
*/
int confFilter(const struct dirent *d) {
    return !strcmp(&d->d_name[strlen(d->d_name) - 5], ".conf");
}

/**
*   Calculate time difference between two timespecs. Return 0,-1 if t1 is already past t2.
*/
struct timespec timeDiff(struct timespec t1, struct timespec t2) {
    return t1.tv_sec  > t2.tv_sec || (t1.tv_sec == t2.tv_sec && t1.tv_nsec > t2.tv_nsec) ? (struct timespec){ 0, -1 } :
           t1.tv_nsec > t2.tv_nsec ? (struct timespec){ t2.tv_sec - t1.tv_sec - 1, 1000000000 - t1.tv_nsec + t2.tv_nsec }
                                   : (struct timespec){ t2.tv_sec - t1.tv_sec, t2.tv_nsec - t1.tv_nsec };
}

/**
*   Return struct timespec offest by delay (in .1s) from current time.
*/
struct timespec timeDelay(int delay) {
    clock_gettime(CLOCK_REALTIME, &curtime);
    return curtime.tv_nsec + ((delay % 10) * 100000000) >= 1000000000 ?
           (struct timespec){ curtime.tv_sec + delay / 10 + 1, curtime.tv_nsec + ((delay % 10) * 100000000) - 1000000000 } :
           (struct timespec){ curtime.tv_sec + delay / 10,     curtime.tv_nsec + ((delay % 10) * 100000000) };
}

/**
*   Returns uint32_t ip address from struct sockaddr..
*/
uint32_t uint32_t_from_sockaddr(const struct sockaddr *addr) {
    return ((struct sockaddr_in *)addr)->sin_addr.s_addr;
}

/**
*   Parses a subnet address string on the format a.b.c.d/n into a subnet addr and mask.
*/
bool parseSubnetAddress(const char *str, uint32_t *addr, uint32_t *mask) {
    uint8_t i = pos++%8, bitcnt = 32;
    strncpy(s[i], str, 18);

    // First get the network part of the address...
    str = strtok(s[i], "/");
    *addr = inet_addr(str);
    // Next parse the subnet mask.
    str = strtok(NULL, "/");
    if (str && ((bitcnt = atoi(str)) < 0 || bitcnt > 32))
        *addr = *mask = (uint32_t)-1;
    else
        *mask = bitcnt == 0 ? 0 : ntohl(0xFFFFFFFF << (32 - bitcnt));
    if ((*addr | *mask) != *mask)
        *addr = (uint32_t)-1;
    return (*addr != (uint32_t)-1);
}

/**
*   Ones complement IGMP checksum calculation routine.
*   Original Author - Mike Muuss, U. S. Army Ballistic Research Laboratory, December, 1983
*   Our algorithm is simple, using a 32 bit accumulator (sum), we add sequential 16 bit words to it,
*   and at the end, fold back all the carry bits from the top 16 bits into the lower 16 bits.
*/
uint16_t inetChksum(register uint16_t *addr, register int len) {
    register int32_t sum = 0;

    do sum += *addr++;
        while ((len -= 2) > 1);
    if (len)
        sum += *(uint8_t *)addr;
    sum = (sum >> 16) + (uint16_t)sum;
    return (uint16_t) ~(sum + (sum >> 16));
}

/**
*   Functions for downstream hosts hash table
*   MurmurHash3 32bit hash function by Austin Appleby, public domain
*/
uint32_t murmurhash3(register uint32_t x) {
    x ^= CONF->hashSeed;
    x = (x ^ (x >> 16)) * 0x85ebca6b;
    x = (x ^ (x >> 13)) * 0xc2b2ae35;
    return x ^ (x >> 16);
}

/**
*   Sort array in numerical asceding order, endianess is irrelevant.
*   Reversed Insertion Sort with duplicates moved to end of list as 0xFFFF and removed (no valid IP).
*/
uint16_t sortArr(register uint32_t *arr, register uint16_t nr) {
    register uint32_t i, j, t, o = 0;
    if (nr > 1) {
        for(i = --nr, j = nr - 1, o = 0; j != (uint32_t )-1; arr[j] = t, j = --i - 1, o++)
            for (t = arr[j]; j < nr && arr[j + 1] <= t; t = arr[j + 1] == t ? (uint32_t)-1 : t, arr[j] = arr[j + 1], j++, o++);
        for (i = nr++; nr >= 1 && arr[i] == (uint32_t)-1; i--, nr--, o++);
        LOG(LOG_DEBUG, 0, "Sorted array of %d elements in %d operations.", nr, o);
    }
    return nr;
}

/**
*   Finds the textual name of the supplied IGMP request.
*/
const char *igmpPacketKind(unsigned int type, unsigned int code) {
    uint8_t i = pos++%8;
    sprintf(s[i], type == IGMP_MEMBERSHIP_QUERY     ? "Membership query" :
                    type == IGMP_V1_MEMBERSHIP_REPORT ? "V1 join" :
                    type == IGMP_V2_MEMBERSHIP_REPORT ? "V2 join" :
                    type == IGMP_V2_LEAVE_GROUP       ? "V2 leave" :
                    type == IGMP_V3_MEMBERSHIP_REPORT ? "V3 group report" :
                                                        "Unkown: 0x%02x/0x%02x", type, code);
    return s[i];
}

/**
*   Returns the IGMP group record type in string.
*/
const char *grecKind(unsigned int type) {
    uint8_t i = pos++%8;
    sprintf(s[i], type == IGMPV3_MODE_IS_INCLUDE   ? "IS_IN" :
                    type == IGMPV3_MODE_IS_EXCLUDE   ? "IS_EX" :
                    type == IGMPV3_CHANGE_TO_INCLUDE ? "TO_IN" :
                    type == IGMPV3_CHANGE_TO_EXCLUDE ? "TO_EX" :
                    type == IGMPV3_ALLOW_NEW_SOURCES ? "ALLOW" :
                    type == IGMPV3_BLOCK_OLD_SOURCES ? "BLOCK" :
                                                       "???");
    return s[i];
}

/**
*   Returns the igmpv3 group record normalized type.
*/
uint16_t grecType(struct igmpv3_grec *grec) {
    return grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT
                           || grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT ? IGMPV3_MODE_IS_EXCLUDE
                            : grec->grec_type == IGMP_V2_LEAVE_GROUP       ? IGMPV3_CHANGE_TO_INCLUDE
                            : grec->grec_type;
}

/**
*   Returns the igmpv3 group record normalized inumber of sources.
*/
uint16_t grecNscrs(struct igmpv3_grec *grec) {
    return grec->grec_type == IGMP_V1_MEMBERSHIP_REPORT
                           || grec->grec_type == IGMP_V2_MEMBERSHIP_REPORT
                           || grec->grec_type == IGMP_V2_LEAVE_GROUP       ? 0
                            : ntohs(grec->grec_nsrcs);
}

/**
*   Calculate QQIC / RESV value from given 15 bit integer (RFC Max).
*   We use our own implementation, as various OS do not provide a common one.
*   d = 0: convert from 15 bit to 8 bit qrv. d = 1: convert from 8 bit qrv to 15 bit value.
*/
uint16_t getIgmpExp(register int val, register int d) {
    int i, exp;
    if (val <= 0 || val > 32767)
        return 0;
    else if (val < 128)
        return (uint8_t)val;
    else if (!d)
        return (uint16_t)((val & 0xf) | 0x10) << (((val & 0x70) >> 4) + 3);

    for (exp = 0, i = val >> 7; i != 1; i >>= 1, exp++);
    return (uint8_t)(0x80 | exp << 4 | ((val >> (exp + 3)) & 0xf));
}

/**
*   Logging function. Logs to file (if specified in config), stderr (-d option) or syslog (default).
*/
bool myLog(int Severity, const char *func, int Errno, const char *FmtSt, ...) {
    int       Ln = 0, err = errno;
    clock_gettime(CLOCK_REALTIME, &curtime);
    long      sec = curtime.tv_sec + utcoff.tv_sec, nsec = curtime.tv_nsec;
    char      LogMsg[512];
    FILE     *lfp = CONF->logFilePath ? fopen(CONF->logFilePath, "a") : stderr;
    va_list   ArgPt;

    va_start(ArgPt, FmtSt);
    if (CONF->logLevel == LOG_DEBUG && Severity >= LOG_NOTICE)
        Ln = snprintf(LogMsg, sizeof(LogMsg), "%s: ", func);
    Ln += vsnprintf(LogMsg + Ln, sizeof(LogMsg) - Ln, FmtSt, ArgPt);
    if (Errno > 0)
        snprintf(LogMsg + Ln, sizeof(LogMsg) - Ln, "; errno(%d): %s", err, strerror(err));
    va_end(ArgPt);

    if ((CONF->logFilePath || CONF->log2Stderr) && lfp) {
        FILE *conf = fopen(CONF->configFilePath, "r");
        int   fd   = conf ? fileno(conf) : -1;
        flock(fd, LOCK_EX);
        if (mrt_tbl >= 0 && chld.onr > 0)
            fprintf(lfp, "%02ld:%02ld:%02ld:%04ld [%d] %s\n", sec % 86400 / 3600, sec % 3600 / 60,
                          sec % 3600 % 60, nsec / 100000, mrt_tbl, LogMsg);
        else
            fprintf(lfp, "%02ld:%02ld:%02ld:%04ld %s\n", sec % 86400 / 3600, sec % 3600 / 60,
                          sec % 3600 % 60, nsec / 100000, LogMsg);
        flock(fd, LOCK_UN);
        if (conf)
            fclose(conf);
    } else
        syslog(Severity, "%s", LogMsg);

    if (lfp && lfp != stderr)
        fclose(lfp);
    if (Severity <= LOG_CRIT) {
        BLOCKSIGS;
        IF_FOR_IF(!SHUTDOWN && mrt_tbl < 0 && chld.nr, (Ln = 0; Ln < chld.nr; Ln++), chld.c[Ln].pid > 0) {
            LOG(LOG_NOTICE, 0, "SIGTERM: To PID: %d for table: %d.", chld.c[Ln].pid, chld.c[Ln].tbl);
            kill(chld.c[Ln].pid, SIGTERM);
        }
        if (Errno < 0)
            Errno = -Errno;
        if (SHUTDOWN || Errno == SIGABRT || Errno == SIGSEGV)
            exit(Errno);
        sigstatus = GOT_SIGTERM;
        igmpProxyCleanUp(Errno);
    }

    return true;
}

/**
*   Sets or removes ip mrules for table.
*/
void ipRules(struct IfDesc *IfDp, bool activate) {
    LOG(LOG_INFO, 0, "%s ip mrules for interface %s, table %d.", activate ? "Adding" : "Removing", IfDp->Name, IfDp->conf->tbl);
    FOR_IF((int i = 0; i < 2; i++), igmpProxyFork(NULL) == 0) {
        execlp("ip", "ip", "mrule", activate ? "add" : "del", i ? "iif" : "oif", IfDp->Name, "table",
                strFmt(1, "%d", "", IfDp->conf->tbl), NULL);
        LOG(LOG_WARNING, eNOFORK, "Cannot exec 'ip mrules'.");
        exit(ENOEXEC);
    }
}

/**
*   Show memory statistics for debugging purposes.
*/
void getMemStats(int h, int cli_fd) {
    char buf[1280] = "%lld, %lld, %lld, %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld "
                     "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld "
                     "%lld %lld",
         msg[1024] = "Current Memory Statistics:\n"
                     "Various: %lldb in use, %lld allocs, %lld frees.\n"
                     "Buffers: %lldb total buffers, %lld kernel, %lldb receive, %lldb send, %lld allocs, %lld frees.\n"
                     "Timers:  %lldb in use, %lld allocs, %lld frees.\n"
                     "Config:  %lldb total, %lldb interfaces, %lldb config, %lldb filters.\n"
                     "         %lld allocs total, %lld interfaces, %lld config, %lld filters.\n"
                     "         %lld  frees total, %lld interfaces, %lld config, %lld filters.\n"
                     "Routes:  %lldb total, %lldb table, %lldb sources, %lldb interfaces, %lldb routes, %lldb queries.\n"
                     "         %lld allocs total, %lld tables, %lld sources, %lld interfaces, %lld routes, %lld queries.\n"
                     "         %lld  frees total, %lld tables, %lld sources, %lld interfaces, %lld routes, %lld queries.\n";
    struct rusage usage;

    if (cli_fd >= 0) {
        sprintf(h ? buf : msg, h ? msg : buf, memuse.var, memalloc.var, memfree.var,
                          memuse.rcv + memuse.snd, memuse.rcv - memuse.snd, memuse.rcv - (memuse.rcv - memuse.snd), memuse.snd,
                          memalloc.rcv + memalloc.snd, memfree.rcv + memfree.snd, memuse.tmr, memalloc.tmr, memfree.tmr,
                          memuse.ifd + memuse.vif + memuse.fil, memuse.ifd, memuse.vif, memuse.fil,
                          memalloc.ifd + memalloc.vif + memalloc.fil, memalloc.ifd, memalloc.vif, memalloc.fil,
                          memfree.ifd + memfree.vif + memfree.fil, memfree.ifd, memfree.vif, memfree.fil,
                          memuse.mct + memuse.src + memuse.ifm + memuse.mfc + memuse.qry,
                          memuse.mct, memuse.src, memuse.ifm, memuse.mfc, memuse.qry,
                          memalloc.mct + memalloc.src + memalloc.ifm + memalloc.mfc + memalloc.qry,
                          memalloc.mct, memalloc.src, memalloc.ifm, memalloc.mfc, memalloc.qry,
                          memfree.mct + memfree.src + memfree.ifm + memfree.mfc + memfree.qry,
                          memfree.mct, memfree.src, memfree.ifm, memfree.mfc, memfree.qry);
        send(cli_fd, h ? buf : msg, strlen(buf), MSG_DONTWAIT);
    }

    LOG(LOG_DEBUG, 0, "Buffer Stats: %lldb total buffers, %lld kernel, %lldb receive, %lldb send, %lld allocs, %lld frees.",
        memuse.rcv + memuse.snd, memuse.rcv - memuse.snd, memuse.rcv - (memuse.rcv - memuse.snd), memuse.snd,
        memalloc.rcv + memalloc.snd, memfree.rcv + memfree.snd);
    LOG(LOG_DEBUG, 0, "Various Stats: %lldb in use, %lld allocs, %lld frees.", memuse.var, memalloc.var, memfree.var);
    LOG(LOG_DEBUG, 0, "Timer   Stats: %lldb in use, %lld allocs, %lld frees.", memuse.tmr, memalloc.tmr, memfree.tmr);
    LOG(LOG_DEBUG, 0, "Config  Stats: %lldb total, %lldb interfaces, %lldb config, %lldb filters.",
        memuse.ifd + memuse.vif + memuse.fil, memuse.ifd, memuse.vif, memuse.fil);
    LOG(LOG_DEBUG, 0, "              %lld allocs total, %lld interfaces, %lld config, %lld filters.",
        memalloc.ifd + memalloc.vif + memalloc.fil, memalloc.ifd, memalloc.vif, memalloc.fil);
    LOG(LOG_DEBUG, 0, "              %lld  frees total, %lld interfaces, %lld config, %lld filters.",
        memfree.ifd + memfree.vif + memfree.fil, memfree.ifd, memfree.vif, memfree.fil);
    LOG(LOG_DEBUG, 0, "Routes  Stats: %lldb total, %lldb table, %lldb sources, %lldb interfaces, %lldb routes, %lldb queries.",
        memuse.mct + memuse.src + memuse.ifm + memuse.mfc + memuse.qry,
        memuse.mct, memuse.src, memuse.ifm, memuse.mfc, memuse.qry);
    LOG(LOG_DEBUG, 0, "              %lld allocs total, %lld tables, %lld sources, %lld interfaces, %lld routes, %lld queries.",
        memalloc.mct + memalloc.src + memalloc.ifm + memalloc.mfc + memalloc.qry,
        memalloc.mct, memalloc.src, memalloc.ifm, memalloc.mfc, memalloc.qry);
    LOG(LOG_DEBUG, 0, "              %lld  frees total, %lld tables, %lld sources, %lld interfaces, %lld routes, %lld queries.",
        memfree.mct + memfree.src + memfree.ifm + memfree.mfc + memfree.qry,
        memfree.mct, memfree.src, memfree.ifm, memfree.mfc, memfree.qry);

    if (getrusage(RUSAGE_SELF, &usage) < 0) {
        if (cli_fd)
            send(cli_fd, h ? "getrusage() failed.\n" : " -1 -1 -1 -1 -1 -1\n", h ? 20 : 19, MSG_DONTWAIT);
        LOG(LOG_WARNING, 1, "getrusage() failed.");
    } else {
        if (cli_fd >= 0) {
            sprintf(buf, h ? "System Stats: resident %ldKB, shared %ldKB, unshared %ldKB, stack %ldKB, signals %ld.\n"
                           : " %ld %ld %ld %ld %ld\n",
                    usage.ru_maxrss, usage.ru_ixrss, usage.ru_idrss, usage.ru_isrss, usage.ru_nsignals);
            send(cli_fd, buf, strlen(buf), MSG_DONTWAIT);
        }
        LOG(LOG_DEBUG, 0, "System Stats: resident %lldKB, shared %lldKB, unshared %lldKB, stack %lldKB, signals %lld.",
            usage.ru_maxrss, usage.ru_ixrss, usage.ru_idrss, usage.ru_isrss, usage.ru_nsignals);
    }
    LOG(LOG_DEBUG, 0, "%lld strings formatted.", pos);
}
