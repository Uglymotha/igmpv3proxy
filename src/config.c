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
*   Generic config file reader. Used to open a config file, and read the tokens from it.
*   The parser is really simple nd does no backlogging. This means that no form of text escaping
*   and qouting is currently supported. '#' chars are read as comments, which lasts until a newline.
*/

#include "igmpv3proxy.h"

// Local Prototypes.
static inline FILE *configFile(void *file, int open);
static inline bool  nextToken(char *token);
static inline void  initCommonConfig();
static inline bool  parseFilters(char *in, char *token, struct filters ***filP, struct filters ***rateP);
static inline bool  parsePhyintToken(char *token);

// All valid configuration options. Prepend whitespace to allow for strstr() exact token matching.
static const char *options = " include logfile loglevel rescanvif rescanvifnl rescanconf phyint user group chroot mctables"
                             " defaulthashtablesize reqqueuesize timerqueuesize kbufsize pbufsize maxtbl defaulttable"
                             " defaultquickleave quickleave defaultmaxorigins defaultdown defaultup defaultupdown defaultthreshold"
                             " defaultratelimit defaultquerierver defaultquerierip defaultrobustness defaultqueryinterval"
                             " defaultqueryrepsonseinterval defaultlastmemberinterval defaultlastmembercount defaultbwcontrol"
                             " defaultproxylocalmc defaultnoquerierelection defaultproxylocalmc defaultnocksumverify defaultfilter"
                             " defaultfilterany nodefaultfilter defaultdisableipmrules defaultssmrange ";
static const char *phyintopt = " table updownstream upstream downstream disabled proxylocalmc noproxylocalmc quickleave"
                               " noquickleave hashtablesize ratelimit threshold nocksumverify cksumverify noquerierelection"
                               " querierelection querierip querierver robustnessvalue queryinterval queryrepsonseinterval"
                               " lastmemberinterval lastmembercount defaultfilter filter altnet whitelist disableipmrules"
                               " bwcontrol maxorigins ssmrange ";

// Process signaling.
extern volatile uint64_t  sighandled;

// Daemon Configuration.
static struct Config      conf, oldconf;

// Structures to keep vif configuration and black/whitelists.
static struct vifConfig *vifConf = NULL, *ovifConf = NULL;
uint32_t                  uVifs;

// Keeps timer ids for configurable timed functions.
static struct timers      timers = { (intptr_t)NULL, (intptr_t)NULL };

// Macro to get a token which should be integer.
#define INTTOKEN ((nextToken(token)) && ((intToken = atoll(token + 1)) || !intToken))

/**
*   Returns pointer to the configuration.
*/
inline struct Config *getConfig(bool old) {
    return old ? &oldconf : &conf;
}

/**
*   Returns pointer to the multicast vif configuration.
*/
inline struct vifConfig **getVifConf(void) {
    return &vifConf;
}

/**
*   Frees the old vifconf list and associated filters.
*/
void freeConfig(bool old) {
    struct vifConfig *tConf, **cConf;
    struct filters   *tFil,  **dFil  = old ? &oldconf.filters : &conf.filters,
                     *tRate, **dRate = old ? &oldconf.rates   : &conf.rates;

    // Free vifconf and filters, Alloced by parsePhyintToken(), configureVifs() and parseFilters()
    for (cConf = old ? &ovifConf : &vifConf; *cConf; *cConf = tConf) {
        tConf = (*cConf)->next;
        // Remove and free filters and ratelimits, be careful not to free default filters here.
        while ((*cConf)->filters && (*cConf)->filters != *dFil) {
            tFil = (*cConf)->filters->next;
            _free((*cConf)->filters, fil, FILSZ);
            (*cConf)->filters = tFil;
        }
        while ((*cConf)->rates && (*cConf)->rates != *dRate) {
            tRate = (*cConf)->rates->next;
            _free((*cConf)->rates, fil, FILSZ);
            (*cConf)->rates = tRate;
        }
        _free(*cConf, vif, VIFSZ);
    }
    *cConf = NULL;
    if (old || SHUTDOWN) {
        // Free default filters when clearing old config, or on shutdown / restart.
        while (*dFil) {
            tFil = (*dFil)->next;
            _free(*dFil, fil, FILSZ);
            *dFil = tFil;
        }
        while (*dRate) {
            tRate = (*dRate)->next;
            _free(*dRate, fil, FILSZ);
            *dRate = tRate;
        }
    }
    if (SHUTDOWN) {
        // On Shutdown stop any running timers.
        timers.rescanConf = timerClear(timers.rescanConf, false);
        timers.rescanVif = timerClear(timers.rescanVif, false);
    }
    LOG(LOG_INFO, 0, "%s cleared.", (old ? "Old configuration" : "Configuration"));
}

/**
*   Opens or closes config file specified by fileName.
*   When called with NULL pointer to filename, return current config file pointer.
*   When called with open = 2, restore the pointer to previous config file.
*/
static inline FILE *configFile(void *file, int open) {
    static FILE *confFilePtr = NULL;

    if (!open && confFilePtr && fclose(confFilePtr) == 0)
        confFilePtr = NULL;
    else if (open == 2)
        confFilePtr = (FILE *)file;
    else if (open && file)
        confFilePtr = fopen(file, "r");

    return confFilePtr;
}

/**
*   Read next token from config file. Return 0 if EOF.
*   Parameter is pointer to token and config file buffer. loadConfig will allocate and initialize the buffer for us.
*   At the end of the buffer space we have 2 uint32_t for counters.
*/
static inline bool nextToken(char *token) {
    char     *cBuffer  = token + MAX_TOKEN_LENGTH;
    uint32_t *readSize = (uint32_t *)((char *)token + MAX_TOKEN_LENGTH + READ_BUFFER_SIZE), *bufPtr = readSize + 1, tokenPtr = 1;
    bool      finished = false, overSized = false, commentFound = false;

    token[0] = ' ';
    while (!finished && !(*bufPtr == *readSize && !(*bufPtr = 0) &&
                           (    (*readSize > 0 && *readSize < READ_BUFFER_SIZE && !(*readSize = 0))
                             || (*readSize = fread(cBuffer, sizeof(char), READ_BUFFER_SIZE, configFile(NULL, 1))) == 0)))
        // Outer loop, buffer filling, reset bufPtr on buffer fill and readSize when EOF.
        do switch (cBuffer[*bufPtr]) {
            // Inner loop, character processing.
            case '#':
                // Found a comment start.
                commentFound = true;
                break;

            case '\n':
                commentFound = false;  /* FALLTHRU */
            case '\0':
            case '\r':
            case '\t':
            case ' ':
                // Newline, Null, CR, Tab and space are end of token, or ignored.
                finished = (tokenPtr > 1);
                break;
            default:
                // Append char to token. When oversized do not increase tokenPtr and keep parsing until EOL.
                if (!commentFound && !overSized)
                    token[tokenPtr++] = cBuffer[*bufPtr];
                if (tokenPtr == MAX_TOKEN_LENGTH - 1)
                    overSized = true;
        } while (++*bufPtr < *readSize && !finished);
    token[tokenPtr] = '\0';  // Make sure token is null terminated string.
    return (tokenPtr > 1);   // Return false if no more valid tokens.
}

/**
*   Initialize default values of configuration parameters.
*/
static inline void initCommonConfig(void) {
    // User and group to run daemon process.
    conf.runPath        = conf.runPath;
    conf.configFilePath = conf.configFilePath;
    conf.logFilePath    = STARTUP ? NULL : conf.logFilePath;
    conf.chroot         = STARTUP ? NULL : conf.chroot;
    conf.user           = STARTUP ? NULL : conf.user;
    conf.group          = STARTUP ? NULL : conf.group;
    conf.mcTables = STARTUP | RESTART ? DEFAULT_ROUTE_TABLES : oldconf.mcTables;
    // Request queue size. This many request buffered requests will be handled before other work is done.
    conf.reqQsz = REQQSZ;
    conf.tmQsz  = TMQSZ;
    conf.kBufsz = K_BUF_SIZE;
    conf.pBufsz = BUF_SIZE;
    // Defaul Query Parameters.
    conf.robustnessValue = DEFAULT_ROBUSTNESS;
    conf.queryInterval = conf.topQueryInterval = DEFAULT_INTERVAL_QUERY;
    conf.queryResponseInterval = DEFAULT_INTERVAL_QUERY_RESPONSE;
    conf.bwControl = 0;
    // Default values for leave intervals...
    conf.lastMemberQueryInterval = DEFAULT_INTERVAL_QUERY_RESPONSE / 10;
    conf.lastMemberQueryCount    = DEFAULT_ROBUSTNESS;
    // Sent leave message upstream on leave messages from downstream.
    conf.quickLeave = false;
    // Default maximum nr of sources for route. Always a minimum of 64 sources is allowed
    // This is controlable by the maxorigins config parameter.
    conf.maxOrigins = DEFAULT_MAX_ORIGINS;
    // Default size of hash table is 32 bytes (= 256 bits) and can store
    // up to the 256 non-collision hosts, approximately half of /24 subnet
    conf.dHostsHTSize    = DEFAULT_HASHTABLE_SIZE;
    conf.defaultTable    = 0;
    conf.disableIpMrules = false;
    // Default interface state and parameters.
    conf.InterfaceState = IF_STATE_DISABLED;
    conf.threshold      = DEFAULT_THRESHOLD;
    parseSubnetAddress(DEFAULT_SSMRANGE, &conf.ssmRange.ip, &conf.ssmRange.mask);
    conf.rateLimit      = DEFAULT_RATELIMIT;
    conf.filters        = NULL;
    conf.rates          = NULL;
    // Log to file disabled by default.
    conf.logLevel = !conf.log2Stderr ? LOG_WARNING : conf.logLevel;
    // Default no timed rebuild interfaces / reload config.
    conf.rescanVif  = 0;
    conf.rescanConf = 0;
    // Do not proxy local mc by default.
    conf.proxyLocalMc = false;
    // Default igmpv3, validate checksums and participate in querier election by default.
    conf.querierIp = (uint32_t)-1;
    conf.querierVer = 3;
    conf.querierElection = true;
    conf.cksumVerify = true;
}

/*
*   Parsing of filters. We do not want to bother the user with configuring filters in reverse.
*   We will dereference the vifConf->filters/rates(->next) pointers several times, so they will be added
*   in the order they are configured, while using only one assignment. Seems complex, but really isn't.
*   Configured filters will be split up into two lists, ACL and ratelimits.
*/
static inline bool parseFilters(char *in, char *token, struct filters ***filP, struct filters ***rateP) {
    int64_t  intToken;
    uint32_t addr, mask;

    char     list[MAX_TOKEN_LENGTH], *filteropt = " allow a block b ratelimit r rl up down updown both 0 1 2 ";
    struct filters filNew = { {0xFFFFFFFF, 0xFFFFFFFF}, {0xFFFFFFFF, 0xFFFFFFFF}, (uint8_t)-1, (uint8_t)-1, (uint64_t)-1, NULL },
                   filErr = { {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint8_t)-1, (uint8_t)-1, (uint64_t)-1, NULL },
                   fil    = filNew;

    strcpy(list, token);
    for (;(nextToken(token)) && (strstr(filteropt, token) || !strstr(options, token));) {
        if (strcmp(" filter", list) == 0 && fil.dst.ip != 0xFFFFFFFF && fil.action == (uint64_t)-1) {
            if (fil.dir == (uint8_t)-1) {
                if (strcmp(" up", token) == 0 || strcmp(" 1", token) == 0)
                    fil.dir = 1;
                else if (strcmp(" down", token) == 0 || strcmp(" 2", token) == 0)
                    fil.dir = 2;
                else
                    fil.dir = 3;
            }
            if ((strcmp(" ratelimit", token) == 0 || strcmp(" r", token) == 0 || strcmp(" rl", token) == 0
                                                  || strcmp(" 2", token) == 0) && INTTOKEN) {
                fil.action = intToken >= 2 ? intToken : 2;
            } else if (strcmp(" allow", token) == 0 || strcmp(" a", token) == 0 || strcmp(" 1", token) == 0)
                fil.action = ALLOW;
            else if (strcmp(" block", token) == 0 || strcmp(" b", token) == 0 || strcmp(" 0", token) == 0)
                fil.action = BLOCK;
            else if (!strstr(filteropt, token)) {
                LOG(LOG_WARNING, 0, "Config (%s): '%s' is not a valid filter action.", in, token + 1);
                fil = filErr;
            }
        } else if (!parseSubnetAddress(token + 1, &addr, &mask)) {
            // Unknown token. Ignore.
            LOG(LOG_WARNING, 0, "Config (%s): Uparsable subnet '%s'.", in, token + 1, list);
            fil = filErr;
        } else if ((strcmp(" whitelist", list) == 0 || (strcmp(" filter", list) == 0 && fil.src.ip != 0xFFFFFFFF))
                   && !IN_MULTICAST(ntohl(addr))) {
            // Check if valid MC group for whitelist are filter dst.
            LOG(LOG_WARNING, 0, "Config (%s): '%s' is not a valid multicast address.", in, inetFmt(addr, 0));
            fil = filErr;
        } else if (strcmp(" altnet", list) == 0) {
            // altnet is not usefull or compatible with igmpv3, ignore.
            fil = filErr;
        } else if (strcmp(" whitelist", list) == 0) {
            fil = (struct filters){ {INADDR_ANY, 0}, {addr, mask}, 3, 3, ALLOW, NULL };
        } else if (fil.src.ip == 0xFFFFFFFF) {
            if (! IN_MULTICAST(ntohl(addr))) {
                fil.src.ip   = addr;
                fil.src.mask = mask;
            } else {
                LOG(LOG_WARNING, 0, "Config (%s): Source address '%s' cannot be multicast.", in, inetFmt(addr, mask));
                fil = filErr;
            }
        } else if (fil.dst.ip == 0xFFFFFFFF) {
            fil.dst.ip   = addr;
            fil.dst.mask = mask;
        }

        if (fil.src.ip == 0xFFFFFFFF && fil.src.mask == 0) {
            // Error in list detected, go to next.
            while ((nextToken(token)) && (strstr(phyintopt, token) || !strstr(options, token)));
            return false;
        } else if (   (fil.src.ip != 0xFFFFFFFF || (fil.src.ip == 0xFFFFFFFF && fil.action > ALLOW))
                   &&  fil.dst.ip != 0xFFFFFFFF && ! (fil.action == (uint64_t)-1)) {
            // Correct filter, add and reset fil to process next entry.
            LOG(LOG_NOTICE, 0, "Config (%s): Adding filter Src: %s, Dst: %s, Dir: %s, Action: %s.", in,
                inetFmt(fil.src.ip, fil.src.mask), inetFmt(fil.dst.ip, fil.dst.mask),
                fil.dir == 1 ? "up" : fil.dir == 2 ? "down" : "updown",
                fil.action == BLOCK ? "BLOCK" : fil.action == ALLOW ? "ALLOW" : "RATELIMIT");
            // Allocate memory for filter and copy from argument.
            struct filters ****n = fil.action <= ALLOW ? &filP : &rateP;
            _calloc(***n, 1, fil, FILSZ);  // Freed by freeConfig()
            ****n = fil;
            **n = &(****n).next;
            fil = filNew;
        }
    }
    return true;
}

/**
*   Parsing interface configuration. Takes pointer to token buffer and location in buffer, latter is only updated.
*/
static inline bool parsePhyintToken(char *token) {
    struct vifConfig  *tmpPtr;
    struct filters   **filP, **rateP;
    int64_t            intToken;

    if (!nextToken(token)) {
        // First token should be the interface name.
        LOG(LOG_WARNING, 0, "Config: You should at least name your interfeces.");
        return false;
    }
    // Find existing or create new vifConf.
    for (tmpPtr = vifConf; tmpPtr && strncmp(tmpPtr->name, token + 1, IF_NAMESIZE); tmpPtr = tmpPtr->next);
    if (! tmpPtr) {
        _calloc(tmpPtr, 1, vif, VIFSZ);  // Freed by freeConfig
        // Insert vifconf in list and set default config and filters pointers.
        *tmpPtr = DEFAULT_VIFCONF;
        vifConf = tmpPtr;
        // Make a copy of the token to store the IF name. Make sure it is NULL terminated.
        memcpy(tmpPtr->name, token + 1, IF_NAMESIZE);
        tmpPtr->name[IF_NAMESIZE - 1] = '\0';
        if (strlen(token + 1) >= IF_NAMESIZE)
            LOG(LOG_WARNING, 0, "Config (%s): '%s' larger than system IF_NAMESIZE (%d).", tmpPtr->name, token + 1, IF_NAMESIZE);
        filP = &tmpPtr->filters, rateP = &tmpPtr->rates;
    } else {
        // If any (default) filters have already been set, find the end of the list.
        for (filP = &tmpPtr->filters; *filP && *filP != conf.filters; filP = &(*filP)->next);
        for (rateP = &tmpPtr->rates; *rateP && *rateP != conf.rates; rateP = &(*rateP)->next);
    }

    // Parse the rest of the config.
    LOG(LOG_NOTICE, 0, "Config (%s): Configuring Interface.", tmpPtr->name);
    while (!logerr && nextToken(token)) {
        while (token[1] && (strcmp(" filter", token) == 0 || strcmp(" altnet", token) == 0 || strcmp(" whitelist", token) == 0)) {
            LOG(LOG_NOTICE, 0, "Config (%s): Parsing ACL '%s'.", tmpPtr->name, token + 1);
            if (!parseFilters(tmpPtr->name, token, &filP, &rateP))
                return false;
        }
        if (strcmp(" nodefaultfilter", token) == 0) {
            tmpPtr->noDefaultFilter = true;
            LOG(LOG_NOTICE, 0, "Config (%s): Not setting default filters.", tmpPtr->name);

        } else if (strcmp(" table", token) == 0 && INTTOKEN) {
#ifdef __Linux__
            if (intToken < 0 || intToken > 999999999)
                LOG(LOG_WARNING, 0, "Config (%s): Table id should be between 0 and 999999999.", tmpPtr->name);
            else {
                tmpPtr->tbl = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Assigned to table %d.", tmpPtr->name, intToken);
                sighandled = STARTUP && tmpPtr->tbl > 0 ? GOT_SIGPROXY : 0;
            }
#else
            LOG(LOG_WARNING, 0, "Config (%s): Table id is only valid on linux.", tmpPtr->name);
#endif
        } else if (strcmp(" disableipmrules", token) == 0) {
#ifdef __Linux__
            LOG(LOG_NOTICE, 0, "Config (%s): Will disable ip mrules.", tmpPtr->name);
            tmpPtr->disableIpMrules = true;
#else
            LOG(LOG_WARNING, 0, "Config (%s): disableipmrules is ony valid for linux.");
#endif
        } else if (strcmp(" updownstream", token) == 0) {
            tmpPtr->state = IF_STATE_UPDOWNSTREAM;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting to Updownstream.", tmpPtr->name);

        } else if (strcmp(" upstream", token) == 0) {
            tmpPtr->state = IF_STATE_UPSTREAM;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting to Upstream.", tmpPtr->name);

        } else if (strcmp(" downstream", token) == 0) {
            tmpPtr->state = IF_STATE_DOWNSTREAM;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting to Downstream.", tmpPtr->name);

        } else if (strcmp(" disabled", token) == 0) {
            tmpPtr->state = IF_STATE_DISABLED;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting to Disabled.", tmpPtr->name);

        } else if (strcmp(" ratelimit", token) == 0 && INTTOKEN) {
            if (intToken < 0)
                LOG(LOG_WARNING, 0, "Config (%s): Ratelimit must 0 or more.", tmpPtr->name);
            else {
                tmpPtr->ratelimit = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting ratelimit to %lld.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" threshold", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config (%s): Threshold must be between 1 and 255.", tmpPtr->name);
            else {
                tmpPtr->threshold = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting threshold to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" quickleave", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config (%s): Quick leave mode enabled.", tmpPtr->name);
            tmpPtr->quickLeave = true;

        } else if (strcmp(" noquickleave", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config (%s): Quick leave mode disabled.", tmpPtr->name);
            tmpPtr->quickLeave = false;

        } else if (strcmp(" hashtablesize", token) == 0 && INTTOKEN) {
            if (intToken < 8 || intToken > 65536)
                LOG(LOG_WARNING, 0, "Config (%s): Hash Table size must be 8 to 65536 bytes (multiples of 8).");
            else {
                tmpPtr->dhtSz = intToken % 8 == 0 ? intToken : intToken + (8 - (intToken % 8));
                LOG(LOG_NOTICE, 0, "Config (%s): Hash table size for quickleave is %d.", tmpPtr->dhtSz);
            }

        } else if (strcmp(" proxylocalmc", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config (%s): Will forward local multicast.", tmpPtr->name);
            tmpPtr->proxyLocalMc = true;

        } else if (strcmp(" noproxylocalmc", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config (%s): Will not forward local multicast.", tmpPtr->name);
            tmpPtr->proxyLocalMc = false;

        } else if (strcmp(" maxorigins", token) == 0 && INTTOKEN) {
            if ((intToken < DEFAULT_MAX_ORIGINS && intToken != 0) || intToken > 65535)
                LOG(LOG_WARNING, 0, "Config: Default Max origins must be between %d and 65535", DEFAULT_MAX_ORIGINS);
            else {
                tmpPtr->maxOrigins = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting max multicast group sources to %d.", conf.maxOrigins);
            }

        } else if (strcmp(" querierip", token) == 0 && nextToken(token)) {
            tmpPtr->qry.ip = inet_addr(token + 1);
            LOG(LOG_NOTICE, 0, "Config (%s): Setting querier ip address to %s.", tmpPtr->name, inetFmt(tmpPtr->qry.ip, 0));

        } else if (strcmp(" querierver", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config (%s): IGMP version %d not valid.", tmpPtr->name, intToken);
            else {
                tmpPtr->qry.ver = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting querier version %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" ssmrange", token) == 0 && nextToken(token)) {
            if (!parseSubnetAddress(token + 1, &tmpPtr->ssmRange.ip, &tmpPtr->ssmRange.mask)
                || (tmpPtr->ssmRange.ip != 0 && !IN_MULTICAST(ntohl(tmpPtr->ssmRange.ip)))) {
                LOG(LOG_NOTICE, 0, "%s is not a valid multicast address, using default %s.",
                    inetFmt(tmpPtr->ssmRange.ip, tmpPtr->ssmRange.mask),
                    inetFmt(conf.ssmRange.ip, conf.ssmRange.mask));
                tmpPtr->ssmRange = conf.ssmRange;
            } else
                LOG(LOG_NOTICE, 0, "Config (%s): Setting SSM Range to %s.", tmpPtr->name,
                    inetFmt(tmpPtr->ssmRange.ip, tmpPtr->ssmRange.mask));

        } else if (strcmp(" noquerierelection", token) == 0) {
            tmpPtr->qry.election = false;
            LOG(LOG_NOTICE, 0, "Config (%s): Will not participate in IGMP querier election.", tmpPtr->name);

        } else if (strcmp(" querierelection", token) == 0) {
            tmpPtr->qry.election = true;
            LOG(LOG_NOTICE, 0, "Config (%s): Will participate in IGMP querier election.", tmpPtr->name);

        } else if (strcmp(" nocksumverify", token) == 0) {
            tmpPtr->cksumVerify = false;
            LOG(LOG_NOTICE, 0, "Config (%s): Will not verify IGMP checksums.", tmpPtr->name);

        } else if (strcmp(" cksumverify", token) == 0) {
            tmpPtr->cksumVerify = true;
            LOG(LOG_NOTICE, 0, "Config (%s): Will verify IGMP checksums.", tmpPtr->name);

        } else if (strcmp(" bwcontrol", token) == 0 && INTTOKEN) {
            tmpPtr->bwControl = (intToken < 3 ? 0 : intToken > 3600 ? 3600 : intToken);
            LOG(LOG_NOTICE, 0, "Config (%s): Setting bandwidth control interval to %ds.", tmpPtr->name, intToken * 10);

        } else if (strcmp(" robustness", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config (%s): Robustness value must be between 1 and 7.", tmpPtr->name);
            else {
                tmpPtr->qry.robustness = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Settings robustness to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" queryinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config (%s): Query interval value must be between 1 than 255.", tmpPtr->name);
            else {
                tmpPtr->qry.interval = intToken;
                if (intToken > conf.topQueryInterval)
                    conf.topQueryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting query interval to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" queryresponseinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config (%s): Query response interval value must be between 1 than 255.", tmpPtr->name);
            else {
                tmpPtr->qry.responseInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting query response interval to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" lastmemberinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config (%s): Last member query interval value must be between 1 than 255.", tmpPtr->name);
            else {
                tmpPtr->qry.lmInterval =  intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting last member query interval to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" lastmembercount", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config (%s): Last member count must be between 1 and 7.");
            else {
                tmpPtr->qry.lmCount = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting last member query count to %d.", tmpPtr->name, tmpPtr->qry.lmCount);
            }

        } else if (!strstr(options, token) && token[1] != '\0') {
            // Unknown token, return error. Token may be " " if parseFilters() returns without valid token.
            LOG(LOG_ERR, 0, "Config (%s): Unknown token '%s'.", tmpPtr->name, token + 1);

        } else if (!strstr(phyintopt, token) || token[1] == '\0')
            break;
    }

    // Check Query response interval and adjust if necessary (query response must be <= query interval).
    if ((tmpPtr->qry.ver != 3 ? tmpPtr->qry.responseInterval : getIgmpExp(tmpPtr->qry.responseInterval, 0)) / 10
                          > tmpPtr->qry.interval) {
        if (tmpPtr->qry.ver != 3)
            tmpPtr->qry.responseInterval = tmpPtr->qry.interval * 10;
        else
            tmpPtr->qry.responseInterval = getIgmpExp(tmpPtr->qry.interval * 10, 1);
        float f = (tmpPtr->qry.ver != 3 ? tmpPtr->qry.responseInterval : getIgmpExp(tmpPtr->qry.responseInterval, 0)) / 10;
        LOG(LOG_NOTICE, 0, "Config (%s): Setting default query interval to %ds. Default response interval %.1fs",
            tmpPtr->name, tmpPtr->qry.interval, f);
    }
    if (!tmpPtr->noDefaultFilter)
        *filP = conf.filters;

    // Return false if error in interface config was detected.
    if (!logerr)
        LOG(LOG_NOTICE, 0, "Config (%s): Ratelimit: %d, Threshold: %d, State: %s, cksum: %s, quickleave: %s",
            tmpPtr->name, tmpPtr->ratelimit, tmpPtr->threshold,
            tmpPtr->state == IF_STATE_DOWNSTREAM ? "Downstream" : tmpPtr->state == IF_STATE_UPSTREAM ? "Upstream" :
            tmpPtr->state == IF_STATE_DISABLED   ? "Disabled"   : "UpDownstream",
            tmpPtr->cksumVerify ? "Enabled" : "Disabled", tmpPtr->quickLeave ? "Enabled" : "Disabled");
    return !logerr;
}

/**
*   Loads the configuration from specified file.
*   Recursive function used for processing configuration files as they are encountered by include directive.
*   Because of this recursion it is important to keep track of configuration file and buffer pointers.
*/
bool loadConfig(char *cfgFile) {
    static struct filters  **filP, **rateP;
    int64_t                  intToken    = 0, st_mode, n;
    FILE                    *confFilePtr = NULL, *fp;
    char                    *token       = NULL;
    struct stat              st;

    if (conf.cnt++ == 0) {
        // Initialize common config on first entry.
        logerr = 0;
        initCommonConfig();
        filP  = &conf.filters;
        rateP = &conf.rates;
    }
    if (conf.cnt == 0xFF) {
        // Check recursion and return if exceeded.
        LOG(LOG_ERR, 0, "Config: Too many includes (%d) while loading '%s'.", 0xFF, cfgFile);
    } else if (stat(cfgFile, &st) != 0 || !(st_mode = st.st_mode)) {
        LOG(LOG_ERR, 1, "Config: Cannot stat '%s'.", cfgFile);
    } else if (S_ISDIR(st_mode)) {
        // Include all .conf files in include directory.
        struct dirent **d;
        LOG(LOG_NOTICE, 0, "Config: Searching for config files in '%s'.", cfgFile);
        if ((n = scandir(cfgFile, &d, confFilter, alphasort)) > 0) while (n--) {
            char file[strlen(cfgFile) + strlen(d[n]->d_name) + 2];
            if ((sprintf(file, "%s/%s", cfgFile, d[n]->d_name) == 0 || !loadConfig(file)) && !logerr)
                LOG(LOG_ERR, 0, "Config: Failed to load config from '%s'", file);
            free(d[n]);
        }
        free(d);
    } else if (!S_ISREG(st_mode) || ! (confFilePtr = configFile(cfgFile, 1))) {
        // Open config file.
        LOG(LOG_ERR, 1, "Config: Failed to open config file '%s'.", cfgFile);
    } else
        LOG(LOG_NOTICE, 0, "Config: Loading config (%d) from '%s'.", conf.cnt, cfgFile);
    _calloc(token, 1, var, MAX_TOKEN_LENGTH + READ_BUFFER_SIZE + 2 * sizeof(uint32_t));  // Freed by self

    // Loop though file tokens until all configuration is read or error encounterd.
    if (S_ISREG(st_mode)) while (!logerr && nextToken(token)) {
        // Process parameters which will result in a next valid config token first.
        while (token[1] && (!strcmp(" phyint", token) || !strcmp(" defaultfilter", token) || strstr(phyintopt, token))) {
            if (strcmp(" phyint", token) == 0 && !parsePhyintToken(token)) {
                return false;
            } else if (strcmp(" defaultfilter", token) == 0) {
                if (conf.filters && *filP == conf.filters) {
                    LOG(LOG_ERR, 0, "Config: Defaultfilterany cannot be combined with default filters.");
                    break;
                } else {
                    LOG(LOG_NOTICE, 0, "Config: Parsing default filters.");
                    strcpy(token, "filter");
                    parseFilters("default", token, &filP, &rateP);
                }
            } else if (strstr(phyintopt, token) && token[1] != '\0') {
                if (strcmp(" quickleave", token) != 0) // Quickleave is valid for both config and phyint.
                    LOG(LOG_ERR, 0, "Config: '%s' without phyint.", token + 1);
                break;
            }
        }

        if (strcmp(" include", token) == 0 && nextToken(token) && strcmp(conf.configFilePath, token + 1) != 0) {
            // Load the config from include file and restore current.
            if (loadConfig(token + 1))
                LOG(LOG_NOTICE, 0, "Config: Succesfully included config from '%s'.", token + 1);
            else if (!logerr)
                LOG(LOG_ERR, 0, "Config: Failed to include config from '%s'.", token + 1);
            configFile(confFilePtr, 2);
        } else if (strcmp(" chroot", token) == 0 && nextToken(token) && (STARTUP || (token[1] = '\0'))) {
            if (! (conf.chroot = malloc(strlen(token))))   // Freed by igmpProxyCleanUp() or Self
                LOG(LOG_CRIT, eNOMEM, "Config: Out of Memory.");
            memcpy(conf.chroot, token + 1, strlen(token));
            if (stat(token + 1, &st) != 0 && !(stat(dirname(token + 1), &st) == 0 && mkdir(conf.chroot, 0770) == 0)) {
                LOG(LOG_ERR, 1, "Config: Could not find or create %s.", conf.chroot);
                free(conf.chroot);  // Alloced by Self
                conf.chroot = NULL;
            } else
                LOG(LOG_NOTICE, 0, "Config: Chroot to %s.", conf.chroot);

        } else if (strcmp(" defaulttable", token) == 0 && INTTOKEN) {
#ifdef __Linux__
            if (intToken < 0 || intToken > 999999999)
                LOG(LOG_WARNING, 0, "Config: Default table id should be between 0 and 999999999.");
            else {
                conf.defaultTable = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default to table %d for interfaces.", conf.defaultTable);
                sighandled = STARTUP && conf.defaultTable > 0 ? GOT_SIGPROXY : 0;
            }
#else
            LOG(LOG_ERR, 0, "Config: Default table id is only valid on linux.");
#endif

        } else if (strcmp(" user", token) == 0 && nextToken(token) && (STARTUP || (token[1] = '\0'))) {
#ifdef __Linux__
            if (! (conf.user = getpwnam(token + 1)))
                LOG(LOG_ERR, 0, "Config: User '%s' does not exist.", token + 1);
            else
                LOG(LOG_NOTICE, 0, "Config: Running daemon as '%s' (%d)", conf.user->pw_name, conf.user->pw_uid);
#else
            LOG(LOG_ERR, 0, "Config: Run as user '%s' is only valid for linux.", token + 1);
#endif

        } else if (strcmp(" defaultdisableipmrules", token) == 0) {
#ifdef __Linux__
            LOG(LOG_NOTICE, 0, "Config: Will disable ip mrules for mc route tables.");
            conf.disableIpMrules = true;
#else
            LOG(LOG_WARNING, 0, "Config: defaultdisableipmrules is ony valid for linux.");
#endif
        } else if (strcmp(" group", token) == 0 && nextToken(token) && (STARTUP || (token[1] = '\0'))) {
            if (! (conf.group = getgrnam(token + 1)))
                LOG(LOG_ERR, 1, "Config: Incorrect CLI group '%s'.", token + 1, conf.group->gr_gid);
            else
                LOG(LOG_NOTICE, 0, "Config: Group for cli access: '%s'.", conf.group->gr_name);

        } else if (strcmp(" mctables", token) == 0 && INTTOKEN && (STARTUP || (token[1] = '\0'))) {
            conf.mcTables = intToken < 1 || intToken > 65536 ? DEFAULT_ROUTE_TABLES : intToken;
            LOG(LOG_NOTICE, 0, "Config: %d multicast table hash entries.", conf.mcTables);

        } else if (strcmp(" kbufsize", token) == 0 && INTTOKEN) {
            conf.kBufsz = intToken > 0 && intToken < 65536 ? intToken : K_BUF_SIZE;
            LOG(LOG_NOTICE, 0, "Config: Setting kernel ring buffer to %dKB.", intToken);

        } else if (strcmp(" pbufsize", token) == 0 && INTTOKEN && (STARTUP || (token[1] = '\0'))) {
            conf.pBufsz = intToken > 0 && intToken < 65536 ? intToken : BUF_SIZE;
            LOG(LOG_NOTICE, 0, "Config: Setting packet buffer to %dB.", intToken);

        } else if (strcmp(" reqqueuesize", token) == 0 && INTTOKEN) {
            conf.reqQsz = intToken > 0 && intToken < 65535 ? intToken : REQQSZ;
            LOG(LOG_NOTICE, 0, "Config: Setting request queue size to %d.", intToken);

        } else if (strcmp(" timerqueuesize", token) == 0 && INTTOKEN) {
            conf.tmQsz = intToken > 0 && intToken < 65535 ? intToken : REQQSZ;
            LOG(LOG_NOTICE, 0, "Config: Setting timer queue size to %d.", intToken);

        } else if (strcmp(" quickleave", token) == 0 || strcmp(" defaultquickleave", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config: Quick leave mode enabled.");
            conf.quickLeave = true;

        } else if (strcmp(" defaultmaxorigins", token) == 0 && INTTOKEN) {
            if ((intToken < DEFAULT_MAX_ORIGINS && intToken != 0) || intToken > 65535)
                LOG(LOG_WARNING, 0, "Config: Default Max origins must be between %d and 65535", DEFAULT_MAX_ORIGINS);
            else {
                conf.maxOrigins = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting max multicast group sources to %d.", conf.maxOrigins);
            }

        } else if (strcmp(" defaulthashtablesize", token) == 0 && INTTOKEN) {
            if (intToken < 8 || intToken > 65536)
                LOG(LOG_WARNING, 0, "Config: Default Hash Table size must be 8 to 65536 bytes (multiples of 8).");
            else {
                conf.dHostsHTSize = intToken % 8 == 0 ? intToken : intToken + (8 - (intToken % 8));
                LOG(LOG_NOTICE, 0, "Config: Default Hash table size for quickleave is %d.", conf.dHostsHTSize);
            }

        } else if (strcmp(" defaultupdown", token) == 0) {
            conf.InterfaceState = IF_STATE_UPDOWNSTREAM;
            LOG(LOG_NOTICE, 0, "Config: Interfaces default to updownstream.");

        } else if (strcmp(" defaultup", token) == 0) {
            conf.InterfaceState = IF_STATE_UPSTREAM;
            LOG(LOG_NOTICE, 0, "Config: Interfaces default to upstream.");

        } else if (strcmp(" defaultdown", token) == 0) {
            conf.InterfaceState = IF_STATE_DOWNSTREAM;
            LOG(LOG_NOTICE, 0, "Config: Interfaces default to downstream.");

        } else if (strcmp(" defaultfilterany", token) == 0) {
            if (conf.filters)
                LOG(LOG_ERR, 0, "Config: Default filters cannot be combined with defaultfilterany.");
            else {
                LOG(LOG_NOTICE, 0, "Config: Interface default filter any.");
                _calloc(conf.filters, 1, fil, FILSZ);  // Freed by freeConfig()
                *conf.filters = FILTERANY;
            }

        } else if (strcmp(" defaultratelimit", token) == 0 && INTTOKEN) {
            if (intToken < 0)
                LOG(LOG_WARNING, 0, "Config: Ratelimit must be more than 0.");
            else {
                conf.rateLimit = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default ratelimit %d.", intToken);
            }

        } else if (strcmp(" defaultthreshold", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Threshold must be between 1 and 255.");
            else {
                conf.threshold = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default threshold %d.", intToken);
            }

        } else if (strcmp(" defaultquerierip", token) == 0 && nextToken(token)) {
            conf.querierIp = inet_addr(token + 1);
            LOG(LOG_NOTICE, 0, "Config: Setting default querier ip address to %s.", inetFmt(conf.querierIp, 0));

        } else if (strcmp(" defaultquerierver", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config: Querier version %d invalid.", intToken);
            else {
                conf.querierVer = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default querier version to %d.", intToken);
            }

        } else if (strcmp(" defaultssmrange", token) == 0 && nextToken(token)) {
            if (!parseSubnetAddress(token + 1, &conf.ssmRange.ip, &conf.ssmRange.mask)
                || (conf.ssmRange.ip != 0 && !IN_MULTICAST(ntohl(conf.ssmRange.ip)))) {
                LOG(LOG_WARNING, 0, "%s is not a valid multicast address, using default %s.",
                    inetFmt(conf.ssmRange.ip, conf.ssmRange.mask), DEFAULT_SSMRANGE);
                parseSubnetAddress(DEFAULT_SSMRANGE, &conf.ssmRange.ip, &conf.ssmRange.mask);
            } else
                LOG(LOG_NOTICE, 0, "Config: Setting default SSM Range to %s.",
                    inetFmt(conf.ssmRange.ip, conf.ssmRange.mask));

        } else if (strcmp(" defaultrobustness", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config: Robustness value must be between 1 and 7.");
            else {
                conf.robustnessValue = intToken;
                conf.lastMemberQueryCount = conf.lastMemberQueryCount != DEFAULT_ROBUSTNESS
                                                  ? conf.lastMemberQueryCount : conf.robustnessValue;
                LOG(LOG_NOTICE, 0, "Config: Setting default robustness value to %d.", intToken);
            }

        } else if (strcmp(" defaultqueryinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Query interval must be between 1 and 255.");
            else {
                conf.queryInterval = intToken;
                if (intToken > conf.topQueryInterval)
                    conf.topQueryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default query interval to %ds.", conf.queryInterval);
            }

        } else if (strcmp(" defaultqueryrepsonseinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Query response interval must be between 1 and 255.");
            else {
                conf.queryResponseInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default query response interval to %d.", intToken);
            }

        } else if (strcmp(" defaultlastmemberinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Last member query interval must be between 1 and 255.");
            else {
                conf.lastMemberQueryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default last member query interval to %d.", intToken);
            }

        } else if (strcmp(" defaultlastmembercount", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config: Last member count must be between 1 and 7.");
            else {
                conf.lastMemberQueryCount = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default last member query count to %d.", intToken);
            }

        } else if (strcmp(" defaultbwcontrol", token) == 0 && INTTOKEN) {
            conf.bwControl = (intToken < 3 ? 3 : intToken > 3600 ? 3600 : intToken) ;
            LOG(LOG_NOTICE, 0, "Config: Setting bandwidth control interval to %ds.", intToken * 10);

        } else if (strcmp(" rescanvifnl", token) == 0) {
#ifdef HAVE_NETLINK
            conf.rescanVif = 1;
#else
            LOG(LOG_WARNING, 0, "Netlink is not supported on this system.");
#endif
        } else if (strcmp(" rescanvif", token) == 0 && INTTOKEN) {
#ifdef HAVE_NETLINK
            conf.rescanVif = conf.rescanVif != 1 && intToken > 0 ? intToken : conf.rescanVif;
            if (conf.rescanVif == 1)
                LOG(LOG_NOTICE, 0, "Config: Use netlink to detect interface changes.", intToken);
            else
#else
            conf.rescanVif = intToken == 1 ? 2 : intToken > 1 ? intToken : 0;
#endif
                LOG(LOG_NOTICE, 0, "Config: Need detect new interface every %ds.", intToken);

        } else if (strcmp(" rescanconf", token) == 0 && INTTOKEN) {
            conf.rescanConf = intToken > 0 ? intToken : 0;
            LOG(LOG_NOTICE, 0, "Config: Need detect config change every %ds.", intToken);

        } else if (strcmp(" loglevel", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config: Logleven must be between 1 and 7.");
            else {
                conf.logLevel = !conf.log2Stderr ? intToken : conf.logLevel;
                LOG(LOG_NOTICE, 0, "Config: Log Level %d", conf.logLevel);
            }

        } else if (strcmp(" logfile", token) == 0 && nextToken(token)) {
            // Only use log file if not logging to stderr.
            char *t = (!STARTUP && conf.chroot) ? basename(token + 1) : token + 1;
            if (conf.log2Stderr || (conf.logFilePath && strcmp(conf.logFilePath, t) == 0))
                continue;
            else if ((! ((fp = fopen(token + 1, "w")) && (t = token + 1)) && ! (fp = fopen(t, "w"))) || fclose(fp) != 0)
                LOG(LOG_ERR, 1, "Config: Cannot open log file '%s'.", token + 1);
            else if (! (conf.logFilePath = realloc(conf.logFilePath, strlen(token))))
                // Freed by igmpProxyCleanUp() or igmpProxyInit()
                LOG(LOG_CRIT, eNOMEM, "Config: Out of Memory.");
            else {
                strcpy(conf.logFilePath, t);
                chmod(conf.logFilePath, 0640);
                time_t rawtime = time(NULL);
                utcoff.tv_sec = timegm(localtime(&rawtime)) - rawtime;
                LOG(LOG_NOTICE, 0, "Config: Logging to file '%s'", conf.logFilePath);
            }

        } else if (strcmp(" defaultproxylocalmc", token) == 0) {
            conf.proxyLocalMc = true;
            LOG(LOG_NOTICE, 0, "Config: Will proxy local multicast range 224.0.0.0/8.");

        } else if (strcmp(" defaultnoquerierelection", token) == 0) {
            conf.querierElection = false;
            LOG(LOG_NOTICE, 0, "Config: Will not participate in IGMP querier election by default.");

        } else if (strcmp(" defaultnocksumverify", token) == 0) {
            conf.cksumVerify = false;
            LOG(LOG_NOTICE, 0, "Config: Will not verify IGMP checksums by default.");

        } else if (token[1] != '\0')
            // Token may be " " if parsePhyintToken() returns without valid token.
            LOG(LOG_ERR, 0, "Config: Unknown token '%s' in config file '%s'.", token + 1, cfgFile);
    }
    if (! vifConf)
        LOG(LOG_WARNING, 0, "No valid interfaces configuration. Everything will be set to defaults.");

    // Close the configfile. When including files, we're done. Decrease count when file has loaded. Reset common flag.
    _free(token, var, MAX_TOKEN_LENGTH + READ_BUFFER_SIZE + 2 * sizeof(uint32_t));  // Alloced by self
    if (confFilePtr && (confFilePtr = configFile(NULL, 0)))
        LOG(LOG_ERR, 1, "Config: Failed to close config file (%d) '%s'.", conf.cnt, cfgFile);
    if (--conf.cnt > 0 || logerr)
        return !logerr;
    // Check Query response interval and adjust if necessary (query response must be <= query interval).
    if ((conf.querierVer != 3 ? conf.queryResponseInterval
                              : getIgmpExp(conf.queryResponseInterval, 0)) / 10 > conf.queryInterval) {
        if (conf.querierVer != 3)
            conf.queryResponseInterval = conf.queryInterval * 10;
        else
            conf.queryResponseInterval = getIgmpExp(conf.queryInterval * 10, 1);
        float f = (conf.querierVer != 3 ? conf.queryResponseInterval
                                        : getIgmpExp(conf.queryResponseInterval, 0)) / 10;
        LOG(LOG_NOTICE, 0, "Config: Setting default query interval to %ds. Default response interval %.1fs", conf.queryInterval, f);
    }
    // Check if buffer sizes or timers have changed, reinit accordingly.
    if (mrt_tbl >= 0 && (CONFRELOAD || SHUP) && (conf.kBufsz != oldconf.kBufsz || conf.pBufsz != oldconf.pBufsz))
        initIgmp(2);
    if (conf.rescanVif > 1 && timers.rescanVif == (intptr_t)NULL)
        timers.rescanVif = timerSet(conf.rescanVif * 10, "Rebuild Interfaces", rebuildIfVc, &timers.rescanVif);
    else if (!conf.rescanVif && timers.rescanVif != (intptr_t)NULL)
        timers.rescanVif = timerClear(timers.rescanVif, false);
    if (conf.rescanConf && timers.rescanConf == (intptr_t)NULL)
        timers.rescanConf = timerSet(conf.rescanConf * 10, "Reload Configuration", reloadConfig, &timers.rescanConf);
    else if (!conf.rescanConf && timers.rescanConf != (intptr_t)NULL)
        timers.rescanConf = timerClear(timers.rescanConf, false);

    return !logerr;
}

/**
 *   Reloads the configuration file and removes interfaces which were removed from config.
 */
void reloadConfig(intptr_t *tid) {
    // Check and set sigstatus if we are doing a reload confi timer..
    ovifConf        = vifConf;
    vifConf         = NULL;
    if (tid)
        sigstatus |= GOT_SIGUSR1;

    // Load the new configuration keep reference to the old. If loading fails, retstore current config.
    memcpy(&oldconf, &conf, sizeof(struct Config));
    conf.cnt = 0;
    if (!loadConfig(conf.configFilePath)) {
        LOG(LOG_ERR, 0, "Failed to reload config from '%s', keeping current.", conf.configFilePath);
        if (vifConf)
            freeConfig(0);
        vifConf = ovifConf;
        memcpy(&conf, &oldconf, sizeof(struct Config));
    } else {
        rebuildIfVc(NULL);
        freeConfig(1);
        LOG(LOG_WARNING, 0, "Configuration Reloaded from '%s'.", conf.configFilePath);
    }
    if (conf.rescanConf && tid) {
        *tid = timerSet(conf.rescanConf * 10, "Reload Configuration", reloadConfig, tid);
        sigstatus &= ~GOT_SIGUSR1;
    }
    getMemStats(0, -1);
}
