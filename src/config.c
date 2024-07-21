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
static inline void  parseFilters(char *in, char *token, struct filters ***filP, struct filters ***rateP);
static inline bool  parsePhyintToken(char *token);

// All valid configuration options. Prepend whitespace to allow for strstr() exact token matching.
static const char *options = " include phyint user group chroot defaultquickleave quickleave maxorigins hashtablesize routetables defaultdown defaultup defaultupdown defaultthreshold defaultratelimit defaultquerierver defaultquerierip defaultrobustness defaultqueryinterval defaultqueryrepsonseinterval defaultlastmemberinterval defaultlastmembercount bwcontrol rescanvif rescanconf loglevel logfile defaultproxylocalmc defaultnoquerierelection proxylocalmc noproxylocalmc upstream downstream disabled ratelimit threshold querierver querierip robustness queryinterval queryrepsonseinterval lastmemberinterval lastmembercount defaultnocksumverify nocksumverify cksumverify noquerierelection querierelection nocksumverify cksumverify noquerierelection querierelection defaultfilterany nodefaultfilter filter altnet whitelist reqqueuesize kbufsize pbufsize maxtbl defaulttable defaultdisableipmrules";
static const char *phyintopt = " table updownstream upstream downstream disabled proxylocalmc noproxylocalmc quickleave noquickleave ratelimit threshold nocksumverify cksumverify noquerierelection querierelection querierip querierver robustnessvalue queryinterval queryrepsonseinterval lastmemberinterval lastmembercount defaultfilter filter altnet whitelist disableipmrules";

// Daemon Configuration.
static struct Config       conf, oldconf;

// Structures to keep vif configuration and black/whitelists.
static struct vifConfig   *vifConf = NULL, *ovifConf = NULL;
uint32_t                   uVifs;

// Keeps timer ids for configurable timed functions.
static struct timers timers = { 0, 0, 0 };

// Macro to get a token which should be integer.
#define INTTOKEN ((nextToken(token)) && ((intToken = atoll(token + 1)) || !intToken))

/**
*   Returns pointer to the configuration.
*/
inline struct Config *getConfig(bool old) {
    return old ? &oldconf : &conf;
}

/**
*   Frees the old vifconf list and associated filters.
*/
void freeConfig(bool old) {
    struct vifConfig *tConf, *cConf;
    struct filters   *fil, *tFil,  *dFil  = old ? oldconf.defaultFilters : conf.defaultFilters,
                           *tRate, *dRate = old ? oldconf.defaultRates   : conf.defaultRates;

    // Free vifconf and filters, Alloced by parsePhyintToken(), configureVifs() and parseFilters()
    for (cConf = old ? ovifConf : vifConf; cConf; cConf = tConf) {
        tConf = cConf->next;
        // Remove and free filters and ratelimits.
        while (cConf->filters && cConf->filters != dFil) {
            tFil = cConf->filters->next;
            _free(cConf->filters, fil, FILSZ);
            cConf->filters = tFil;
        }
        while (cConf->rates && cConf->rates != dRate) {
            tRate = cConf->rates->next;
            _free(cConf->rates, fil, FILSZ);
            cConf->rates = tRate;
        }
        _free(cConf, vif, VIFSZ);
    }

    if (old || SHUTDOWN || RESTART) {
        // Free default filters when clearing old config, or on shutdown / restart.
        while (dFil) {
            tFil = dFil->next;
            _free(dFil, fil, FILSZ);
            dFil = tFil;
        }
        while (dRate) {
            tRate = dRate->next;
            _free(dRate, fil, FILSZ);
            dRate = tRate;
        }
    }
    if (SHUTDOWN) {
        // On Shutdown stop any running timers.
        timer_clearTimer(timers.rescanConf);
        timer_clearTimer(timers.rescanVif);
        timer_clearTimer(timers.bwControl);
        timers = (struct timers){ 0, 0, 0 };
    }
    LOG(LOG_DEBUG, 0, "freeConfig: %s cleared.", (old ? "Old configuration" : "Configuration"));
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

    // Defaul Query Parameters.
    conf.robustnessValue = DEFAULT_ROBUSTNESS;
    conf.queryInterval = DEFAULT_INTERVAL_QUERY;
    conf.queryResponseInterval = DEFAULT_INTERVAL_QUERY_RESPONSE;
    conf.bwControlInterval = 0;

    // Request queue size. This many request buffered requests will be handled before other work is done.
    conf.reqQsz = REQQSZ;
    conf.tmQsz  = TMQSZ;
    conf.kBufsz = K_BUF_SIZE;
    conf.pBufsz = BUF_SIZE;

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
    conf.dHostsHTSize = DEFAULT_HASHTABLE_SIZE;

    // Number of (hashed) route tables.
    conf.defaultTable    = 0;
    conf.disableIpMrules = false;
    conf.mcTables = STARTUP ? DEFAULT_ROUTE_TABLES : oldconf.mcTables;

    // Default interface state and parameters.
    conf.defaultInterfaceState = IF_STATE_DISABLED;
    conf.defaultThreshold      = DEFAULT_THRESHOLD;
    conf.defaultRatelimit      = DEFAULT_RATELIMIT;
    conf.defaultFilters        = NULL;
    conf.defaultRates          = NULL;

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
static inline void parseFilters(char *in, char *token, struct filters ***filP, struct filters ***rateP) {
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
                if (! conf.bwControlInterval || (fil.src.ip != 0 && fil.src.ip != 0xFFFFFFFF)) {
                    LOG(LOG_NOTICE, 0, "Config (%s): %s Ignoring '%s - %s %lld.'", in, !conf.bwControlInterval ?
                        "BW Control disabled." : "Ratelimit rules must have INADDR_ANY as source.",
                         inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), intToken);
                    fil = filNew;
                    continue;
                } else
                    fil.action = intToken >= 2 ? intToken : 2;
            } else if (strcmp(" allow", token) == 0 || strcmp(" a", token) == 0 || strcmp(" 1", token) == 0)
                fil.action = ALLOW;
            else if (strcmp(" block", token) == 0 || strcmp(" b", token) == 0 || strcmp(" 0", token) == 0)
                fil.action = BLOCK;
            else if (!strstr(filteropt, token)) {
                LOG(LOG_WARNING, 0, "Config (%s): '%s' is not a valid filter action or direction.", in, token + 1);
                fil = filErr;
            }

        } else if (!parseSubnetAddress(token + 1, &addr, &mask)) {
            // Unknown token. Ignore.
            LOG(LOG_WARNING, 0, "Config (%s): Uparsable subnet '%s'.", in, token + 1, list);
            fil = filErr;
        } else if ((strcmp(" whitelist", list) == 0 || (strcmp(" filter", list) == 0 && fil.src.ip != 0xFFFFFFFF))
                   && !IN_MULTICAST(ntohl(addr))) {
            // Check if valid MC group for whitelist are filter dst.
            LOG(LOG_WARNING, 0, "Config (%s): '%s' is not a valid multicast address.", in, inetFmt(addr, 1));
            fil = filErr;
        } else if ((addr | mask) != mask) {
            // Check if valid sn/mask pair.
            LOG(LOG_WARNING, 0, "Config (%s): '%s' is not valid subnet/mask pair.", in, inetFmts(addr, mask, 1));
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
                LOG(LOG_WARNING, 0, "Config (%s): Source address '%s' cannot be multicast.", in, inetFmts(addr, mask, 1));
                fil = filErr;
            }
        } else if (fil.dst.ip == 0xFFFFFFFF) {
            fil.dst.ip   = addr;
            fil.dst.mask = mask;
        }

        if (fil.src.ip == 0xFFFFFFFF && fil.src.mask == 0) {
            // Error in list detected, go to next.
            while ((nextToken(token)) && !strstr(options, token));
            break;
        } else if (   (fil.src.ip != 0xFFFFFFFF || (fil.src.ip == 0xFFFFFFFF && fil.action > ALLOW))
                   &&  fil.dst.ip != 0xFFFFFFFF && ! (fil.action == (uint64_t)-1)) {
            // Correct filter, add and reset fil to process next entry.
            LOG(LOG_NOTICE, 0, "Config (%s): Adding filter Src: %15s, Dst: %15s, Dir: %6s, Action: %5s.", in,
                                inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2),
                                fil.dir == 1 ? "up" : fil.dir == 2 ? "down" : "updown",
                                fil.action == BLOCK ? "BLOCK" : fil.action == ALLOW ? "ALLOW" : "RATELIMIT");
            // Allocate memory for filter and copy from argument.
            struct filters ****n = fil.action <= ALLOW ? &filP : &rateP;
            if (! _calloc(***n, 1, fil, FILSZ))
                LOG(LOG_ERR, eNOMEM, "parseFilters: Out of Memory.");  // Freed by freeConfig()
            ****n = fil;

            **n = &(****n).next;
            fil = filNew;
        }
    }
}

/**
*   Parsing interface configuration. Takes pointer to token buffer and location in buffer, latter is only updated.
*/
static inline bool parsePhyintToken(char *token) {
    struct vifConfig  *tmpPtr;
    struct filters   **filP, **rateP;
    int64_t            intToken, i;

    if (!nextToken(token)) {
        // First token should be the interface name.
        LOG(LOG_WARNING, 0, "Config: You should at least name your interfeces.");
        return false;
    }

    // Find existing or create new vifConf.
    for (tmpPtr = vifConf; tmpPtr && strncmp(tmpPtr->name, token + 1, IF_NAMESIZE); tmpPtr = tmpPtr->next);
    if (! tmpPtr) {
        if (! _calloc(tmpPtr, 1, vif, VIFSZ))  // Freed by freeConfig
            LOG(LOG_ERR, eNOMEM, "parsePhyintToken: Out of memory.");
        // Insert vifconf in list and set default config and filters pointers.
        *tmpPtr = DEFAULT_VIFCONF;
        vifConf = tmpPtr;
        // Make a copy of the token to store the IF name. Make sure it is NULL terminated.
        memcpy(tmpPtr->name, token + 1, IF_NAMESIZE);
        tmpPtr->name[IF_NAMESIZE - 1] = '\0';
        if (strlen(token + 1) >= IF_NAMESIZE)
            LOG(LOG_NOTICE, 0, "Config (%s): '%s' larger than system IF_NAMESIZE (%d).", tmpPtr->name, token + 1, IF_NAMESIZE);
        filP = &tmpPtr->filters, rateP = &tmpPtr->rates;
    } else {
        // If any (default) filters have already been set, find the end of the list.
        for (filP = &tmpPtr->filters; *filP && *filP != conf.defaultFilters; filP = &(*filP)->next);
        for (rateP = &tmpPtr->rates; *rateP && *rateP != conf.defaultRates; rateP = &(*rateP)->next);
    }

    // Parse the rest of the config.
    LOG(LOG_NOTICE, 0, "Config (%s): Configuring Interface.", tmpPtr->name);
    while (!logwarning && nextToken(token)) {
        while (token[1] && (strcmp(" filter", token) == 0 || strcmp(" altnet", token) == 0 || strcmp(" whitelist", token) == 0)) {
            LOG(LOG_NOTICE, 0, "Config (%s): Parsing ACL '%s'.", tmpPtr->name, token + 1);
            parseFilters(tmpPtr->name, token, &filP, &rateP);
        }
        if (strcmp(" nodefaultfilter", token) == 0) {
            tmpPtr->noDefaultFilter = true;
            LOG(LOG_NOTICE, 0, "Config (%s): Not setting default filters.", tmpPtr->name);

        } else if (strcmp(" table", token) == 0 && INTTOKEN) {
#ifdef __linux__
            if (intToken < 0 || intToken > 999999999)
                LOG(LOG_WARNING, 0, "Config (%s): Table id should be between 0 and 999999999.", tmpPtr->name);
            else {
                tmpPtr->tbl = intToken;
                LOG(LOG_INFO, 0, "Config (%s): Assigning to table %d.", tmpPtr->name, intToken);
                if (mrt_tbl < 0) // Check again becasue of fork().
                    igmpProxyFork(intToken);
            }
#else
            LOG(LOG_NOTICE, 0, "Config (%s): Table id is only valid on linux.", tmpPtr->name);
#endif
        } else if (strcmp(" disableipmrules", token) == 0) {
#ifdef __linux__
            LOG(LOG_NOTICE, 0, "Config (%s): Will disable ip mrules.", tmpPtr->name);
            tmpPtr->disableIpMrules = true;
#else
            LOG(LOG_NOTICE, 0, "disableipmrules is ony valid for linux.");
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

        } else if (strcmp(" proxylocalmc", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config (%s): Will forward local multicase.", tmpPtr->name);
            tmpPtr->proxyLocalMc = true;

        } else if (strcmp(" noproxylocalmc", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config (%s): Will not forward local multicase.", tmpPtr->name);
            tmpPtr->proxyLocalMc = false;

        } else if (strcmp(" querierip", token) == 0 && nextToken(token)) {
            tmpPtr->qry.ip = inet_addr(token + 1);
            LOG(LOG_NOTICE, 0, "Config (%s): Setting querier ip address to %s.", tmpPtr->name, inetFmt(tmpPtr->qry.ip, 1));

        } else if (strcmp(" querierver", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config (%s): IGMP version %d not valid.", tmpPtr->name, intToken);
            else {
                tmpPtr->qry.ver = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting querier version %d.", tmpPtr->name, intToken);
            }

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
                LOG(LOG_WARNING, 0, "Config (%s): Last member interval value must be between 1 than 255.", tmpPtr->name);
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
            LOG(LOG_WARNING, 0, "Config (%s): Unknown token '%s'.", tmpPtr->name, token + 1);

        } else if (!strstr(phyintopt, token) || token[1] == '\0')
            break;
    }

    // Return false if error in interface config was detected. freeConfig will cleanup.
    if (logwarning)
        return false;

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
        *filP = conf.defaultFilters;

    LOG(LOG_INFO, 0, "Config (%s): Ratelimit: %d, Threshold: %d, State: %s, cksum: %s, quickleave: %s",
        tmpPtr->name, tmpPtr->ratelimit, tmpPtr->threshold,
        tmpPtr->state == IF_STATE_DOWNSTREAM ? "Downstream" : tmpPtr->state == IF_STATE_UPSTREAM ? "Upstream" :
        tmpPtr->state == IF_STATE_DISABLED   ? "Disabled"   : "UpDownstream",
        tmpPtr->cksumVerify ? "Enabled" : "Disabled", tmpPtr->quickLeave ? "Enabled" : "Disabled");
    return true;
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

    // Initialize common config on first entry.
    if (conf.cnt++ == 0) {
        logwarning = 0;
        initCommonConfig();
        filP  = &conf.defaultFilters;
        rateP = &conf.defaultRates;
    }

    if (conf.cnt == 0xFF) {
        // Check recursion and return if exceeded.
        LOG(LOG_WARNING, 0, "Config: Too many includes (%d) while loading '%s'.", 0xFF, cfgFile);
    } else if (stat(cfgFile, &st) != 0 || !(st_mode = st.st_mode)) {
        LOG(LOG_WARNING, errno, "Config: Cannot stat '%s'.", cfgFile);
    } else if (S_ISDIR(st_mode)) {
        // Include all .conf files in include directory.
        struct dirent **d;
        LOG(LOG_NOTICE, 0, "Config: Searching for config files in '%s'.", cfgFile);
        if ((n = scandir(cfgFile, &d, confFilter, alphasort)) > 0) while (n--) {
            char file[strlen(cfgFile) + strlen(d[n]->d_name) + 2];
            if ((sprintf(file, "%s/%s", cfgFile, d[n]->d_name) == 0 || !loadConfig(file)) && !logwarning)
                LOG(LOG_WARNING, 0, "Config: Failed to load config from '%s' %d.", file, logwarning);
            free(d[n]);
        }
        free(d);
        //return !logwarning;
    } else if (!S_ISREG(st_mode) || ! (confFilePtr = configFile(cfgFile, 1))) {
        // Open config file.
        LOG(LOG_WARNING, errno, "Config: Failed to open config file '%s'.", cfgFile);
    } else if (! _malloc(token, var, MAX_TOKEN_LENGTH + READ_BUFFER_SIZE + 2 * sizeof(uint32_t))) {  // Freed by self
        // Allocate buffer and open config file and initialize common config when loading main config file.
        LOG(LOG_ERR, eNOMEM, "loadConfig: Out of Memory.");
    } else {
        // Increase count and initialize buffer. First char of token is ' ', counters to 0.
        token[0] = ' ';
        *(uint64_t *)((char *)token + MAX_TOKEN_LENGTH + READ_BUFFER_SIZE) = 0;
        LOG(LOG_INFO, 0, "Config: Loading config (%d) from '%s'.", conf.cnt, cfgFile);
    }

    // Loop though file tokens until all configuration is read or error encounterd.
    if (S_ISREG(st_mode)) while (!logwarning && nextToken(token)) {
        // Process parameters which will result in a next valid config token first.
        while (token[1] && (strcmp(" phyint", token) == 0 || strcmp(" defaultfilter", token) == 0 || strstr(phyintopt, token))) {
            if (strcmp(" phyint", token) == 0) {
                parsePhyintToken(token);
            } else if (strcmp(" defaultfilter", token) == 0) {
                if (conf.defaultFilters && *filP == conf.defaultFilters) {
                    LOG(LOG_WARNING, 0, "Config: Defaultfilterany cannot be combined with default filters.");
                    break;
                } else {
                    LOG(LOG_NOTICE, 0, "Config: Parsing default filters.");
                    strcpy(token, "filter");
                    parseFilters("default", token, &filP, &rateP);
                }
            } else if (strstr(phyintopt, token)) {
                if (strcmp(" quickleave", token) != 0) // Quickleave is valid for both config and phyint.
                    LOG(LOG_WARNING, 0, "Config: '%s' without phyint.", token + 1);
                break;
            }
        }

        if (strcmp(" include", token) == 0 && nextToken(token) && strcmp(conf.configFilePath, token + 1) != 0) {
            // Load the config from include file and restore current.
            if (loadConfig(token + 1))
                LOG(LOG_NOTICE, 0, "Config: Succesfully included config from '%s'.", token + 1);
            else if (!logwarning)
                LOG(LOG_WARNING, 0, "Config: Failed to include config from '%s'.", token + 1);
            configFile(confFilePtr, 2);
        } else if (strcmp(" chroot", token) == 0 && nextToken(token) && (STARTUP || (token[1] = '\0'))) {
            if (! (conf.chroot = malloc(strlen(token))))   // Freed by signalHandler() or Self
                LOG(LOG_ERR, eNOMEM, "Config: Out of Memory.");
            memcpy(conf.chroot, token + 1, strlen(token));
            if (stat(token + 1, &st) != 0 && !(stat(dirname(token + 1), &st) == 0 && mkdir(conf.chroot, 0770) == 0)) {
                LOG(LOG_WARNING, errno, "Config: Could not find or create %s.", conf.chroot);
                free(conf.chroot);  // Alloced by Self
                conf.chroot = NULL;
            } else
                LOG(LOG_NOTICE, 0, "Config: Chroot to %s.", conf.chroot);

        } else if (strcmp(" defaulttable", token) == 0 && INTTOKEN) {
#ifdef __linux__
            if (intToken < 0 || intToken > 999999999)
                LOG(LOG_NOTICE, 0, "Config: Default table id should be between 0 and 999999999.");
            else {
                conf.defaultTable = intToken;
                if (mrt_tbl < 0 && conf.defaultTable > 0)
                    igmpProxyFork(conf.defaultTable);
                LOG(LOG_NOTICE, 0, "Config: Default to table %d for interfaces.", conf.defaultTable);
            }
#else
            LOG(LOG_NOTICE, 0, "Config: Default table id is only valid on linux.");
#endif

        } else if (strcmp(" user", token) == 0 && nextToken(token) && (STARTUP || (token[1] = '\0'))) {
#ifdef __linux__
            if (! (conf.user = getpwnam(token + 1)))
                LOG(LOG_WARNING, 0, "Config: User '%s' does not exist.", token + 1);
            else
                LOG(LOG_NOTICE, 0, "Config: Running daemon as '%s' (%d)", conf.user->pw_name, conf.user->pw_uid);
#else
            LOG(LOG_NOTICE, 0, "Config: Run as user '%s' is only valid for linux.", token + 1);
#endif

        } else if (strcmp(" defaultdisableipmrules", token) == 0) {
#ifdef __linux__
            LOG(LOG_NOTICE, 0, "Config: Will disable ip mrules for mc route tables.");
            conf.disableIpMrules = true;
#else
            LOG(LOG_NOTICE, 0, "defaultdisableipmrules is ony valid for linux.");
#endif
        } else if (strcmp(" group", token) == 0 && nextToken(token) && (STARTUP || (token[1] = '\0'))) {
            if (! (conf.group = getgrnam(token + 1)))
                LOG(LOG_WARNING, errno, "Config: Incorrect CLI group '%s'.", token + 1, conf.group->gr_gid);
            else
                LOG(LOG_NOTICE, 0, "Config: Group for cli access: '%s' (%d).", conf.group->gr_name, conf.group->gr_gid);

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

        } else if (strcmp(" maxorigins", token) == 0 && INTTOKEN) {
            if (intToken < DEFAULT_MAX_ORIGINS || intToken > 65535)
                LOG(LOG_WARNING, 0, "Config: Max origins must be between %d and 65535", DEFAULT_MAX_ORIGINS);
            else {
                conf.maxOrigins = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting max multicast group sources to %d.", conf.maxOrigins);
            }

        } else if (strcmp(" hashtablesize", token) == 0 && INTTOKEN) {
            if (intToken < 8 || intToken > 131072)
                LOG(LOG_WARNING, 0, "Config: hashtablesize must be 8 to 131072 bytes (multiples of 8).");
            else {
                conf.dHostsHTSize = (intToken - intToken % 8) * 8;
                LOG(LOG_NOTICE, 0, "Config: Hash table size for quickleave is %d.", conf.dHostsHTSize / 8);
            }

        } else if (strcmp(" defaultupdown", token) == 0) {
            if (conf.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state already set.");
            else {
                conf.defaultInterfaceState = IF_STATE_UPDOWNSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to updownstream.");
            }

        } else if (strcmp(" defaultup", token) == 0) {
            if (conf.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state already set.");
            else {
                conf.defaultInterfaceState = IF_STATE_UPSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to upstream.");
            }

        } else if (strcmp(" defaultdown", token) == 0) {
            if (conf.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state already set.");
            else {
                conf.defaultInterfaceState = IF_STATE_DOWNSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to downstream.");
            }

        } else if (strcmp(" defaultfilterany", token) == 0) {
            if (conf.defaultFilters)
                LOG(LOG_WARNING, 0, "Config: Default filters cannot be combined with defaultfilterany.");
            else {
                LOG(LOG_NOTICE, 0, "Config: Interface default filter any.");
                if (! _calloc(conf.defaultFilters, 1, fil, FILSZ))  // Freed by freeConfig()
                    LOG(LOG_ERR, eNOMEM, "loadConfig: Out of Memory.");
                *conf.defaultFilters = FILTERANY;
            }

        } else if (strcmp(" defaultratelimit", token) == 0 && INTTOKEN) {
            if (intToken < 0)
                LOG(LOG_WARNING, 0, "Config: Ratelimit must be more than 0.");
            else {
                conf.defaultRatelimit = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default ratelimit %d.", intToken);
            }

        } else if (strcmp(" defaultthreshold", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Threshold must be between 1 and 255.");
            else {
                conf.defaultThreshold = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default threshold %d.", intToken);
            }

        } else if (strcmp(" defaultquerierip", token) == 0 && nextToken(token)) {
            conf.querierIp = inet_addr(token + 1);
            LOG(LOG_NOTICE, 0, "Config: Setting default querier ip address to %s.", inetFmt(conf.querierIp, 1));

        } else if (strcmp(" defaultquerierver", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config: Querier version %d invalid.", intToken);
            else {
                conf.querierVer = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default querier version to %d.", intToken);
            }

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

        } else if (strcmp(" bwcontrol", token) == 0 && INTTOKEN) {
            conf.bwControlInterval = intToken < 3 ? 3 : intToken;
            LOG(LOG_NOTICE, 0, "Config: Setting bandwidth control interval to %ds.", intToken);

        } else if (strcmp(" rescanvif", token) == 0 && INTTOKEN) {
            conf.rescanVif = intToken > 0 ? intToken : 0;
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
                LOG(LOG_WARNING, errno, "Config: Cannot open log file '%s'.", token + 1);
            else if (! (conf.logFilePath = realloc(conf.logFilePath, strlen(token))))
                // Freed by signalHandler()
                LOG(LOG_ERR, eNOMEM, "loadConfig: Out of Memory.");
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
            LOG(LOG_WARNING, 0, "Config: Unknown token '%s' in config file '%s'.", token + 1, cfgFile);
    }

    // Close the configfile. When including files, we're done. Decrease count when file has loaded. Reset common flag.
    _free(token, var, MAX_TOKEN_LENGTH + READ_BUFFER_SIZE + 2 * sizeof(uint32_t));  // Alloced by self
    if (confFilePtr && (confFilePtr = configFile(NULL, 0)))
        LOG(LOG_WARNING, errno, "Config: Failed to close config file (%d) '%s'.", conf.cnt, cfgFile);

    if (--conf.cnt > 0 || logwarning)
        return !logwarning;

    // Check Query response interval and adjust if necessary (query response must be <= query interval).
    if ((conf.querierVer != 3 ? conf.queryResponseInterval
                                      : getIgmpExp(conf.queryResponseInterval, 0)) / 10 > conf.queryInterval) {
        if (conf.querierVer != 3)
            conf.queryResponseInterval = conf.queryInterval * 10;
        else
            conf.queryResponseInterval = getIgmpExp(conf.queryInterval * 10, 1);
        float f = (conf.querierVer != 3 ? conf.queryResponseInterval
                                                : getIgmpExp(conf.queryResponseInterval, 0)) / 10;
        LOG(LOG_NOTICE, 0, "Config: Setting default query interval to %ds. Default response interval %.1fs",
                            conf.queryInterval, f);
    }

    // Check if buffer sizes have changed.
    if (CONFRELOAD && (conf.kBufsz != oldconf.kBufsz || conf.pBufsz != oldconf.pBufsz))
        initIgmp(false);

    // Check rescanvif status and start or clear timers if necessary.
    if (conf.rescanVif && timers.rescanVif == 0) {
        timers.rescanVif = timer_setTimer(conf.rescanVif * 10, "Rebuild Interfaces", rebuildIfVc, &timers.rescanVif);
    } else if (!conf.rescanVif && timers.rescanVif != 0) {
        timer_clearTimer(timers.rescanVif);
        timers.rescanVif = 0;
    }

    // Check rescanconf status and start or clear timers if necessary.
    if (conf.rescanConf && timers.rescanConf == 0) {
        timers.rescanConf = timer_setTimer(conf.rescanConf * 10, "Reload Configuration", reloadConfig, &timers.rescanConf);
    } else if (!conf.rescanConf && timers.rescanConf != 0) {
        timer_clearTimer(timers.rescanConf);
        timers.rescanConf = 0;
    }

    // Check bwcontrol status and start or clear timers if necessary..
    if (oldconf.bwControlInterval != conf.bwControlInterval) {
        timer_clearTimer(timers.bwControl);
        timers.bwControl = 0;
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        int Va, len = sizeof(Va);
        if (!STARTUP && (getsockopt(MROUTERFD, IPPROTO_IP, MRT_API_CONFIG, (void *)&Va, (void *)&len) < 0
                         || ! (Va & MRT_MFC_BW_UPCALL))) {
            LOG(LOG_WARNING, errno, "Config: MRT_API_CONFIG Failed. Disabling bandwidth control.");
            conf.bwControlInterval = 0;
        } else if (!STARTUP)
            clearGroups(getConfig);
#endif
        if (conf.bwControlInterval)
            timers.bwControl = timer_setTimer(conf.bwControlInterval * 10, "Bandwidth Control",
                                              bwControl, &timers.bwControl);
    }
    return !logwarning;
}

/**
 *   Reloads the configuration file and removes interfaces which were removed from config.
 */
void reloadConfig(uint64_t *tid) {
    // Check and set sigstatus if we are doing a reload confi timer..
    ovifConf        = vifConf;
    vifConf         = NULL;
    if (tid)
        sigstatus |= GOT_SIGUSR1;

    // Load the new configuration keep reference to the old.
    memcpy(&oldconf, &conf, sizeof(struct Config));
    conf.cnt = 0;
    if (!loadConfig(conf.configFilePath)) {
        LOG(LOG_WARNING, 0, "Failed to reload config from '%s', keeping current.", conf.configFilePath);
        if (vifConf)
            freeConfig(0);
        vifConf = ovifConf;
        memcpy(&conf, &oldconf, sizeof(struct Config));
    } else {
        // Rebuild the interfaces config, then free the old configuration.
        if (!STARTUP)
            rebuildIfVc(NULL);
        freeConfig(1);
        LOG(LOG_WARNING, 0, "Configuration Reloaded from '%s'.", conf.configFilePath);
    }
    if (conf.rescanConf && tid) {
        *tid = timer_setTimer(conf.rescanConf * 10, "Reload Configuration", reloadConfig, tid);
        sigstatus &= ~GOT_SIGUSR1;
    }
    getMemStats(0, -1);
}

/**
*   Configures all multicast vifs and links to interface configuration. This function is responsible for:
*   - All active interfaces have a matching configuration. Either explicit through config file or implicit defaults.
*   - Default filters are created for the interface if necessary.
*   - Establish correct old and new state of interfaces.
*   - Control querier process and do route maintenance on interface transitions.
*   - Add and remove vifs from the kernel if needed.
*   - IfDp->state represents the old and new state of interfaces as below.
*      8        7         6       5       4       3       2       1
*      removed  existing  unused  unused  olddown oldup   down    up
*/
void configureVifs(void) {
    struct IfDesc    *IfDp = NULL;
    struct vifConfig *vconf = NULL, *oconf = NULL;
    struct filters   *fil, *ofil;
    bool              quickLeave = false, tbl0 = false;
    uint32_t          vifcount = 0, upvifcount = 0, downvifcount = 0;

    uVifs = 0;
    if (! vifConf)
        LOG(LOG_WARNING, 0, "No valid interfaces configuration. Everything will be set to defaults.");
    GETIFL(IfDp) {
        // Find and link matching config to interfaces, except when rescanning vifs and exisiting interface.
        oconf = NULL;
        if (!IFREBUILD || ! IfDp->conf) {
            for (oconf = NULL, vconf = vifConf; vconf && strcmp(IfDp->Name, vconf->name); vconf = vconf->next);
            if (vconf) {
                LOG(LOG_INFO, 0, "Found config for %s", IfDp->Name);
            } else {
                // Interface has no matching config, create default config.
                LOG(LOG_INFO, 0, "configureVifs: Creating default config for %s interface %s.",
                                  IS_DISABLED(conf.defaultInterfaceState)     ? "disabled"
                                : IS_UPDOWNSTREAM(conf.defaultInterfaceState) ? "updownstream"
                                : IS_UPSTREAM(conf.defaultInterfaceState)     ? "upstream"     : "downstream", IfDp->Name);
                if (! _calloc(vconf, 1, vif, VIFSZ))
                    LOG(LOG_ERR, eNOMEM, "configureVifs: Out of Memory.");   // Freed by freeConfig()
                *vconf = DEFAULT_VIFCONF;
                vifConf  = vconf;
                strcpy(vconf->name, IfDp->Name);
                vconf->filters = conf.defaultFilters;
            }
            // Link the configuration to the interface. And update the states.
            oconf = IfDp->conf;
            IfDp->conf = vconf;
        }
        if (!SHUTDOWN && !IFREBUILD && mrt_tbl < 0 && chld.nr && IfDp->conf->tbl == 0 && !tbl0++)
            igmpProxyFork(0);

        // Evaluate to old and new state of interface.
        if (!CONFRELOAD && !(IfDp->state & 0x40)) {
            // If no state flag at this point it is because buildIfVc detected new or removed interface.
            if (!(IfDp->state & 0x80))
                // Removed interface, oldstate is current state, newstate is disabled, flagged for removal.
                IfDp->state = ((IfDp->state & 0x03) << 2) | 0x80;
            else
                // New interface, oldstate is disabled, newstate is configured state.
                IfDp->state = IfDp->mtu && IfDp->Flags & IFF_MULTICAST ? IfDp->conf->state : IF_STATE_DISABLED;
        } else
            // Existing interface, oldstate is current state, newstate is configured state.
            IfDp->state = ((IfDp->state & 0x3) << 2) | (IfDp->mtu && (IfDp->Flags & IFF_MULTICAST) ? IfDp->conf->state : 0);

        if (IfDp->conf->tbl != mrt_tbl) {
            // Check if Interface is in table for current process.
            LOG(LOG_NOTICE, 0, "Not enabling table %d interface %s", IfDp->conf->tbl, IfDp->Name);
            IfDp->state &= ~0x3;  // Keep old state, new state disabled.
        }
        if (mrt_tbl < 0)
            // Monitor process only needs config.
            continue;
        register uint8_t oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);
        quickLeave |= !IS_DISABLED(IfDp->state) && IfDp->conf->quickLeave;

        // Set configured querier ip to interface address if not configured
        // and set version to 3 for disabled/upstream only interface.
        if (IfDp->conf->qry.ip == (uint32_t)-1)
            IfDp->conf->qry.ip = IfDp->InAdr.s_addr;
        if (!IS_DOWNSTREAM(IfDp->state))
            IfDp->conf->qry.ver = 3;
        if (IfDp->conf->qry.ver == 1)
            IfDp->conf->qry.interval = 10, IfDp->conf->qry.responseInterval = 10;

        // Check if filters have changed so that ACLs will be reevaluated.
        if (!IfDp->filCh && (CONFRELOAD || SHUP)) {
            for (fil = vconf->filters, ofil = oconf ? oconf->filters : NULL;
                 fil && ofil && !memcmp(fil, ofil, sizeof(struct filters) - sizeof(void *));
                 fil = fil->next, ofil = ofil->next);
            if (fil || ofil) {
                LOG(LOG_DEBUG, 0, "configureVifs: Filters changed for %s.", IfDp->Name);
                IfDp->filCh = true;
            }
        }

        // Check if querier process needs to be restarted, because election was turned of and other querier present.
        if (!IfDp->conf->qry.election && IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate)
                                      && IfDp->querier.ip != IfDp->conf->qry.ip)
            ctrlQuerier(2, IfDp);

        // Increase counters and call addVif if necessary.
        if (!IS_DISABLED(newstate) && (IfDp->index != (uint8_t)-1 || k_addVIF(IfDp))) {
            vifcount++;
            if (IS_DOWNSTREAM(newstate))
                downvifcount++;
            if (IS_UPSTREAM(newstate)) {
                upvifcount++;
                BIT_SET(uVifs, IfDp->index);
            } else
                BIT_CLR(uVifs, IfDp->index);
        }

        // Do maintenance on vifs according to their old and new state.
        if      (               IS_DISABLED(oldstate)  && IS_UPSTREAM(newstate))    { ctrlQuerier(1, IfDp); clearGroups(IfDp); }
        else if ((STARTUP   ||  IS_DISABLED(oldstate)) && IS_DOWNSTREAM(newstate))  { ctrlQuerier(1, IfDp);                    }
        else if (!STARTUP   && !IS_DISABLED(oldstate)  && IS_DISABLED(newstate))    { ctrlQuerier(0, IfDp); clearGroups(IfDp); }
        else if (!STARTUP   &&  oldstate != newstate)                               { ctrlQuerier(2, IfDp); clearGroups(IfDp); }
        else if ( IFREBUILD &&  oldstate == newstate   && !IS_DISABLED(newstate))   {                       clearGroups(IfDp); }
        IfDp->filCh = false;

        // Check if vif needs to be removed.
        if (IS_DISABLED(newstate) && IfDp->index != (uint8_t)-1) {
            BIT_CLR(uVifs, IfDp->index);
            k_delVIF(IfDp);
            if (vifcount)
                vifcount--;
            if (IS_DOWNSTREAM(oldstate) && downvifcount)
                downvifcount--;
            if (IS_UPSTREAM(oldstate)   && upvifcount)
                upvifcount--;
        }
    }
    if (mrt_tbl < 0)
        // Monitor process only needs config and state.
        return;

    // Set hashtable size to 0 when quickleave is not enabled on any interface.
    if (!quickLeave) {
        LOG(LOG_NOTICE, 0, "Disabling quickleave, no interfaces have it enabled.");
        conf.quickLeave = false;
        conf.dHostsHTSize = 0;
    }

    // Check if quickleave was enabled or disabled due to config change.
    if ((CONFRELOAD || SHUP) && oldconf.dHostsHTSize != conf.dHostsHTSize) {
        LOG(LOG_WARNING, 0, "configureVifs: Downstream host hashtable size changed from %d to %d, reinitializing group tables.",
                             oldconf.dHostsHTSize, conf.dHostsHTSize);
        clearGroups(&conf);
    }

    // All vifs created / updated, check if there is an upstream and at least one downstream.
    if (!SHUTDOWN && !RESTART && (vifcount < 2 || upvifcount == 0 || downvifcount == 0))
        LOG(LOG_ERR, 0 - eNOINIT, "There must be at least 2 interfaces, 1 upstream and 1 dowstream.");
}
