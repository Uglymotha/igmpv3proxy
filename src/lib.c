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

// buffers to hold the string representations of IP addresses, to be passed to inet_fmt() or inet_fmts().
static char s[4][19];

/**
*   Convert an IP address in u_long (network) format into a printable string.
*/
const char *inetFmt(uint32_t addr, int pos) {
    uint8_t *a = (uint8_t *)&addr;
    sprintf(s[pos - 1], "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    return s[pos - 1];
}

/**
*   Convert an IP subnet number in u_long (network) format into a printable string including the netmask as a number of bits.
*/
const char *inetFmts(uint32_t addr, uint32_t mask, int pos) {
    uint8_t *a    = (uint8_t *)&addr;
    int      bits = 33 - ffs(ntohl(mask));

    if ((addr == 0) && (mask == 0))
        sprintf(s[pos - 1], "0/0");
    else if (((uint8_t *)&mask)[3] != 0)
        sprintf(s[pos - 1], "%u.%u.%u.%u/%d", a[0], a[1], a[2], a[3], bits);
    else if (((uint8_t *)&mask)[2] != 0)
        sprintf(s[pos - 1], "%u.%u.%u/%d",    a[0], a[1], a[2], bits);
    else if (((uint8_t *)&mask)[1] != 0)
        sprintf(s[pos - 1], "%u.%u/%d",       a[0], a[1], bits);
    else
        sprintf(s[pos - 1], "%u/%d",          a[0], bits);

    return s[pos - 1];
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
*   Copies s_addr from struct sockaddr to struct sockaddr_in.
*/
uint32_t s_addr_from_sockaddr(const struct sockaddr *addr) {
    return ((struct sockaddr_in *)addr)->sin_addr.s_addr;
}

/**
*   Parses a subnet address string on the format a.b.c.d/n into a subnet addr and mask.
*/
bool parseSubnetAddress(const char * const str, uint32_t *addr, uint32_t *mask) {
    char addrstr[19];
    strncpy(addrstr, str, 18);
    // First get the network part of the address...
    char *tmpStr = strtok(addrstr, "/");
    *addr = inet_addr(tmpStr);
    if (*addr == (in_addr_t)-1)
        return false;

    // Next parse the subnet mask.
    int bitcnt;
    tmpStr = strtok(NULL, "/");
    if (tmpStr) {
        bitcnt = atoi(tmpStr);
        if (bitcnt < 0 || bitcnt > 32) {
            *addr = (uint32_t)-1;
            return false;
        }
    } else
        bitcnt = 32;
    *mask = bitcnt == 0 ? 0 : ntohl(0xFFFFFFFF << (32 - bitcnt));

    return true;
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
    switch (type) {
    case IGMP_MEMBERSHIP_QUERY:      return "Membership query  ";
    case IGMP_V1_MEMBERSHIP_REPORT:  return "V1 member report  ";
    case IGMP_V2_MEMBERSHIP_REPORT:  return "V2 member report  ";
    case IGMP_V3_MEMBERSHIP_REPORT:  return "V3 member report  ";
    case IGMP_V2_LEAVE_GROUP:        return "Leave message     ";
    }

    static char unknown[20];
    sprintf(unknown, "unk: 0x%02x/0x%02x    ", type, code);
    return unknown;
}

/**
*   Returns the IGMP group record type in string.
*/
const char *grecKind(unsigned int type) {
    switch (type) {
    case IGMPV3_MODE_IS_INCLUDE:    return "IS_IN";
    case IGMPV3_MODE_IS_EXCLUDE:    return "IS_EX";
    case IGMPV3_CHANGE_TO_INCLUDE:  return "TO_IN";
    case IGMPV3_CHANGE_TO_EXCLUDE:  return "TO_EX";
    case IGMPV3_ALLOW_NEW_SOURCES:  return "ALLOW";
    case IGMPV3_BLOCK_OLD_SOURCES:  return "BLOCK";
    }
    return "???";
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

    if ((CONF->logFilePath || CONF->log2Stderr) && lfp)
        if (mrt_tbl >= 0 && chld.onr > 0)
            fprintf(lfp, "%02ld:%02ld:%02ld:%04ld [%d] %s\n", sec % 86400 / 3600, sec % 3600 / 60,
                          sec % 3600 % 60, nsec / 100000, mrt_tbl, LogMsg);
        else
            fprintf(lfp, "%02ld:%02ld:%02ld:%04ld %s\n", sec % 86400 / 3600, sec % 3600 / 60,
                          sec % 3600 % 60, nsec / 100000, LogMsg);
    else
        syslog(Severity, "%s", LogMsg);

    if (lfp && lfp != stderr)
        fclose(lfp);
    if (Severity <= LOG_CRIT && !SHUTDOWN) {
        BLOCKSIGS;
        sigstatus = GOT_SIGTERM;
        IF_FOR_IF(mrt_tbl < 0 && chld.nr, Ln = 0; Ln < chld.nr; Ln++, chld.c[Ln].pid > 0) {
            LOG(LOG_NOTICE, 0, "SIGINT: To PID: %d for table: %d.", chld.c[Ln].pid, chld.c[Ln].tbl);
            kill(chld.c[Ln].pid, SIGINT);
        }
        if (Errno < 0)
            Errno = -Errno;
        if (Errno == SIGABRT || Errno == SIGSEGV)
            exit(Errno);
        igmpProxyCleanUp(Errno);
    }

    return true;
}

/**
*   Sets or removes ip mrules for table.
*/
void ipRules(int tbl, bool activate) {
    struct IfDesc *IfDp;
    char           msg[12];

    sprintf(msg, "%d", tbl);
    LOG(LOG_NOTICE, 0, "%s mrules for table %d.", activate ? "Adding" : "Removing", tbl);
    GETIFL_IF(IfDp, IfDp->conf->tbl == tbl && !IfDp->conf->disableIpMrules) {
        LOG(LOG_INFO, 0, "%s ip mrules for interface %s.", activate ? "Adding" : "Removing", IfDp->Name);
        FOR_IF(int i = 0; i < 2; i++, igmpProxyFork(-2) == 0) {
            execlp("ip", "ip", "mrule", activate ? "add" : "del", i ? "iif" : "oif", IfDp->Name, "table", msg, NULL);
            LOG(LOG_ERR, eNOFORK, "Cannot exec 'ip mrules'.");
            exit(ENOEXEC);
        }
    }
}

/**
*   Show memory statistics for debugging purposes.
*/
void getMemStats(int h, int cli_fd) {
    char buf[1280], msg[1024];
    struct rusage usage;

    if (cli_fd >= 0) {
        if (h) {
            strcpy(msg, "Current Memory Statistics:\n");
            strcat(msg, "Various: %lldb in use, %lld allocs, %lld frees.\n");
            strcat(msg, "Buffers: %lldb total buffers, %lld kernel, %lldb receive, %lldb send, %lld allocs, %lld frees.\n");
            strcat(msg, "Timers:  %lldb in use, %lld allocs, %lld frees.\n");
            strcat(msg, "Config:  %lldb total, %lldb interfaces, %lldb config, %lldb filters.\n");
            strcat(msg, "         %lld allocs total, %lld interfaces, %lld config, %lld filters.\n");
            strcat(msg, "         %lld  frees total, %lld interfaces, %lld config, %lld filters.\n");
            strcat(msg, "Routes:  %lldb total, %lldb table, %lldb sources, %lldb interfaces, %lldb routes, %lldb queries.\n");
            strcat(msg, "         %lld allocs total, %lld tables, %lld sources, %lld interfaces, %lld routes, %lld queries.\n");
            strcat(msg, "         %lld  frees total, %lld tables, %lld sources, %lld interfaces, %lld routes, %lld queries.\n");
        } else
            strcpy(msg, "%lld, %lld, %lld, %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld"
                        "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld"
                        "%lld %lld");
        sprintf(buf, msg, memuse.var, memalloc.var, memfree.var,
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
        send(cli_fd, buf, strlen(buf), MSG_DONTWAIT);
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
        if (cli_fd && !h)
            send(cli_fd, "\n", 1, MSG_DONTWAIT);
        LOG(LOG_WARNING, 1, "getrusage() failed.");
    } else {
        if (cli_fd >= 0) {
            if (h)
                strcpy(msg, "System Stats: resident %lldKB, shared %lldKB, unshared %lldKB, stack %lldKB, signals %lld.\n");
            else
                strcpy(msg, " %lld %lld %lld %lld %lld\n");
            sprintf(buf, msg, usage.ru_maxrss, usage.ru_ixrss, usage.ru_idrss, usage.ru_isrss, usage.ru_nsignals);
            send(cli_fd, buf, strlen(buf), MSG_DONTWAIT);
        }
        LOG(LOG_DEBUG, 0, "System Stats:  resident %lldKB, shared %lldKB, unshared %lldKB, stack %lldKB, signals %lld.",
            usage.ru_maxrss, usage.ru_ixrss, usage.ru_idrss, usage.ru_isrss, usage.ru_nsignals);
    }
}
