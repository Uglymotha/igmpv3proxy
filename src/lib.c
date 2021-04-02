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

#include "igmpproxy.h"

// buffers to hold the string representations of IP addresses, to be passed to inet_fmt() or inet_fmts().
static char s[4][19];

/**
*   Formats 'InAdr' into a dotted decimal string.
*   returns: - pointer to 'St'
*/
inline char *fmtInAdr(struct in_addr InAdr, int pos) {
    sprintf(s[pos - 1], "%u.%u.%u.%u", ((uint8_t *)&InAdr.s_addr)[0], ((uint8_t *)&InAdr.s_addr)[1], ((uint8_t *)&InAdr.s_addr)[2], ((uint8_t *)&InAdr.s_addr)[3]);
    return s[pos - 1];
}

/**
*   Convert an IP address in u_long (network) format into a printable string.
*/
inline char *inetFmt(uint32_t addr, int pos) {
    register unsigned char *a = (unsigned char *)&addr;

    sprintf(s[pos - 1], "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    return s[pos - 1];
}

/**
*   Convert an IP subnet number in u_long (network) format into a printable string including the netmask as a number of bits.
*/
inline char *inetFmts(uint32_t addr, uint32_t mask, int pos) {
    register unsigned char *a = (unsigned char *)&addr, *m = (unsigned char *)&mask;
    int bits = 33 - ffs(ntohl(mask));

    if ((addr == 0) && (mask == 0)) sprintf(s[pos - 1], "default");
    else if (m[3] != 0) sprintf(s[pos - 1], "%u.%u.%u.%u/%d", a[0], a[1], a[2], a[3], bits);
    else if (m[2] != 0) sprintf(s[pos - 1], "%u.%u.%u/%d",    a[0], a[1], a[2], bits);
    else if (m[1] != 0) sprintf(s[pos - 1], "%u.%u/%d",       a[0], a[1], bits);
    else                sprintf(s[pos - 1], "%u/%d",          a[0], bits);

    return s[pos - 1];
}

/**
*   Optimized ones complement IGMP checksum calculation routine.
*   Original Author - Mike Muuss, U. S. Army Ballistic Research Laboratory, December, 1983
*   Our algorithm is simple, using a 32 bit accumulator (sum), we add sequential 16 bit words to it,
*   and at the end, fold back all the carry bits from the top 16 bits into the lower 16 bits.
*/
inline uint16_t inetChksum(register uint16_t *addr, register int len) {
    register int32_t sum = 0;

    do sum += *addr++; while ((len -= 2) > 1);
    if (len) sum += *(uint8_t *)addr;

    sum = (sum >> 16) + (sum & 0xffff);
    return (uint16_t) ~(sum + (sum >> 16));
}

/**
*   Functions for downstream hosts hash table
*   MurmurHash3 32bit hash function by Austin Appleby, public domain
*/
inline uint32_t murmurhash3(register uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6b;
    x ^= x >> 13;
    x *= 0xc2b2ae35;
    return x ^ (x >> 16);
}

/**
*   Calculate QQIC / RESV value from given 15 bit integer (RFC Max). We use our own implementation, as various OS do not provide a common one.
*/
inline uint16_t getIgmpExp(register int val, register int d) {
    int i, exp;
    if      (val <= 0 || val > 32767) return 0;
    else if (val < 128)               return (uint8_t)val;
    else if (!d)                      return (uint16_t)((val & 0xf) | 0x10) << (((val & 0x70) >> 4) + 3);
    for (exp = 0, i = val >> 7; i != 1; i >>= 1, exp++);
    return (uint8_t)(0x80 | exp << 4 | ((val >> (exp + 3)) & 0xf));
}

/**
*   Logging function. Logs to file (if specified in config), stderr (-d option) or syslog (default).
*/
inline bool myLog(int Severity, int Errno, const char *FmtSt, ...) {
    struct timespec logtime;
    char            LogMsg[256];
    FILE           *lfp = NULL;
    va_list         ArgPt;
    unsigned        Ln;

    if (Severity > CONFIG->logLevel) return false;
    va_start(ArgPt, FmtSt);
    Ln = vsnprintf(LogMsg, sizeof(LogMsg), FmtSt, ArgPt);
    if (Errno > 0) snprintf(LogMsg + Ln, sizeof(LogMsg) - Ln, "; Errno(%d): %s", Errno, strerror(Errno));
    va_end(ArgPt);

    if (CONFIG->log2File || CONFIG->log2Stderr || (STARTUP && Severity <= LOG_ERR)) {
        clock_gettime(CLOCK_REALTIME, &logtime);
        long sec = logtime.tv_sec + utcoff.tv_sec, nsec = logtime.tv_nsec;
        lfp = CONFIG->log2File ? freopen(CONFIG->logFilePath, "a", stderr) : NULL;
        fprintf(stderr, "%02ld:%02ld:%02ld:%04ld %s\n", sec % 86400 / 3600, sec % 3600 / 60, sec % 3600 % 60, nsec / 100000, LogMsg);
        if (lfp) fclose(lfp);
    } else syslog(Severity, "%s", LogMsg);

    if (Severity <= LOG_ERR)
        exit(-1);

    return true;
}
