/*
**  igmpv3proxy - IGMPv3 Proxy based multicast router
**  Copyright (C) 2022 Sietse van Zanen <uglymotha@wizdom.nu>
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
static const char *options = " phyint quickleave maxorigins hashtablesize routetables defaultdown defaultup defaultupdown defaultthreshold defaultratelimit defaultquerierver defaultquerierip defaultrobustness defaultqueryinterval defaultqueryrepsonseinterval defaultlastmemberinterval defaultlastmembercount bwcontrol rescanvif rescanconf loglevel logfile proxylocalmc defaultnoquerierelection upstream downstream disabled ratelimit threshold querierver querierip robustness queryinterval queryrepsonseinterval lastmemberinterval lastmembercount noquerierelection defaultfilterany nodefaultfilter filter altnet whitelist reqqueuesize kbufsize pbufsize";
static const char *phyintopt = " updownstream upstream downstream disabled ratelimit threshold noquerierelection querierip querierver robustnessvalue queryinterval queryrepsonseinterval lastmemberinterval lastmembercount defaultfilter filter altnet whitelist";

// Daemon Configuration.
static struct Config commonConfig, oldcommonConfig;

// Structures to keep vif configuration and black/whitelists.
static struct vifConfig   *vifConf = NULL, *ovifConf = NULL;
uint32_t                   uVifs;

// Keeps timer ids for configurable timed functions.
static struct timers {
    uint64_t rescanConf;
    uint64_t rescanVif;
    uint64_t bwControl;
} timers = { 0, 0, 0 };

// Macro to get a token which should be integer.
#define INTTOKEN ((nextToken(token)) && ((intToken = atoll(token + 1)) || !intToken))

/**
*   Returns pointer to the configuration.
*/
inline struct Config *getConfig(void) {
    return &commonConfig;
}

/**
*   Frees the old vifconf list and associated filters.
*/
void freeConfig(int old) {
    struct vifConfig *tConf, *cConf;
    struct filters   *fil, *tFil,  *dFil  = old ? oldcommonConfig.defaultFilters : commonConfig.defaultFilters,
                           *tRate, *dRate = old ? oldcommonConfig.defaultRates   : commonConfig.defaultRates;

    // Free vifconf and filters, Alloced by parsePhyintToken() and parseFilters()
    for (cConf = old ? ovifConf : vifConf; cConf; cConf = tConf) {
        tConf = cConf->next;
        // Remove and free filters and ratelimits.
        for (; cConf->filters && cConf->filters != dFil; tFil = cConf->filters->next, free(cConf->filters), cConf->filters = tFil);
        for (; cConf->rates && cConf->rates != dRate; tRate = cConf->rates->next, free(cConf->rates), cConf->rates = tRate);
        free(cConf);
    }

    if (old || SHUTDOWN) {
        // Free default filters when clearing old config, or on shutdown.
        for (; dFil; tFil = dFil->next, free(dFil), dFil = tFil);
        for (; dRate; tRate = dRate->next, free(dRate), dRate = tRate);
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
                    token[tokenPtr++] = tolower(cBuffer[*bufPtr]);
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
    // Defaul Query Parameters.
    commonConfig.robustnessValue = DEFAULT_ROBUSTNESS;
    commonConfig.queryInterval = DEFAULT_INTERVAL_QUERY;
    commonConfig.queryResponseInterval = DEFAULT_INTERVAL_QUERY_RESPONSE;
    commonConfig.bwControlInterval = 0;

    // Request queue size. This many request buffered requests will be handled before other work is done.
    commonConfig.reqQsz = REQQSZ;
    commonConfig.tmQsz  = TMQSZ;
    commonConfig.kBufsz = K_BUF_SIZE;
    commonConfig.pBufsz = BUF_SIZE;

    // Default values for leave intervals...
    commonConfig.lastMemberQueryInterval = DEFAULT_INTERVAL_QUERY_RESPONSE / 10;
    commonConfig.lastMemberQueryCount    = DEFAULT_ROBUSTNESS;

    // Sent leave message upstream on leave messages from downstream.
    commonConfig.fastUpstreamLeave = false;

    // Default maximum nr of sources for route. Always a minimum of 64 sources is allowed
    // This is controlable by the maxorigins config parameter.
    commonConfig.maxOrigins = DEFAULT_MAX_ORIGINS;

    // Default size of hash table is 32 bytes (= 256 bits) and can store
    // up to the 256 non-collision hosts, approximately half of /24 subnet
    commonConfig.dHostsHTSize = DEFAULT_HASHTABLE_SIZE;

    // Number of (hashed) route tables.
    commonConfig.mcTables = STARTUP ? DEFAULT_ROUTE_TABLES : oldcommonConfig.mcTables;

    // Default interface state and parameters.
    commonConfig.defaultInterfaceState = IF_STATE_DISABLED;
    commonConfig.defaultThreshold = DEFAULT_THRESHOLD;
    commonConfig.defaultRatelimit = DEFAULT_RATELIMIT;
    commonConfig.defaultFilters   = NULL;
    commonConfig.defaultRates     = NULL;

    // Log to file disabled by default.
    commonConfig.logLevel = !commonConfig.log2Stderr ? LOG_WARNING : commonConfig.logLevel;

    // Default no timed rebuild interfaces / reload config.
    commonConfig.rescanVif  = 0;
    commonConfig.rescanConf = 0;

    // Do not proxy local mc by default.
    commonConfig.proxyLocalMc = false;

    // Default igmpv3 and participate in querier election by default.
    commonConfig.querierIp = (uint32_t)-1;
    commonConfig.querierVer = 3;
    commonConfig.querierElection = true;

    // Default no group for socket (use root's).
    if (! (commonConfig.socketGroup = getgrgid(0)))
        LOG(LOG_WARNING, errno, "Failed to get grgid for root/wheel.", errno);
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
                if (! commonConfig.bwControlInterval || (fil.src.ip != 0 && fil.src.ip != 0xFFFFFFFF)) {
                    LOG(LOG_NOTICE, 0, "Config (%s): %s Ignoring '%s - %s %lld.'", in, !commonConfig.bwControlInterval ?
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
            if (! (***n = calloc(1, sizeof(struct filters))))
                LOG(LOG_ERR, errno, "parseFilters: Out of Memory.");  // Freed by freeConfig()
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
    struct vifConfig *tmpPtr;
    int64_t           intToken;

    if (!nextToken(token)) {
        // First token should be the interface name.
        LOG(LOG_WARNING, 0, "Config: You should at least name your interfeces.");
        return false;
    } else if (! (tmpPtr = malloc(sizeof(struct vifConfig))))
        // Allocate and initialize memory for new configuration.
        LOG(LOG_ERR, errno, "parsePhyintToken: Out of memory.");  // Freed by freeConfig or self()
    *tmpPtr = DEFAULT_VIFCONF;
    LOG(LOG_NOTICE, 0, "Config (%s): Configuring Interface.", token + 1);

    // Make a copy of the token to store the IF name. Make sure it is NULL terminated.
    memcpy(tmpPtr->name, token + 1, IF_NAMESIZE);
    tmpPtr->name[IF_NAMESIZE - 1] = '\0';
    if (strlen(token) >= IF_NAMESIZE)
        LOG(LOG_NOTICE, 0, "Config (%s): '%s' larger than system IF_NAMESIZE (%d).", tmpPtr->name, token + 1, IF_NAMESIZE);

    // Set pointer to pointer to filters list.
    struct filters **filP = &tmpPtr->filters, **rateP = &tmpPtr->rates;

    // Parse the rest of the config.
    while (!logwarning && nextToken(token)) {
        while (token[1] && (strcmp(" filter", token) == 0 || strcmp(" altnet", token) == 0 || strcmp(" whitelist", token) == 0)) {
            LOG(LOG_NOTICE, 0, "Config (%s): Parsing ACL '%s'.", tmpPtr->name, token + 1);
            parseFilters(tmpPtr->name, token, &filP, &rateP);
        }

        if (strcmp(" nodefaultfilter", token) == 0) {
            tmpPtr->noDefaultFilter = true;
            LOG(LOG_NOTICE, 0, "Config (%s): Not setting default filters.", tmpPtr->name);

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

    // Return false if error in interface config was detected.
    if (logwarning) {
        free(tmpPtr);  // Alloced by self.
        return false;
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

    // Insert vifconf in list and set default filters.
    tmpPtr->next = vifConf;
    vifConf      = tmpPtr;
    if (!tmpPtr->noDefaultFilter)
        *filP = commonConfig.defaultFilters;

    LOG(LOG_INFO, 0, "Config (%s): Ratelimit: %d, Threshold: %d, State: %s", tmpPtr->name, tmpPtr->ratelimit, tmpPtr->threshold,
        tmpPtr->state == IF_STATE_DOWNSTREAM ? "Downstream" : tmpPtr->state == IF_STATE_UPSTREAM ? "Upstream" :
        tmpPtr->state == IF_STATE_DISABLED   ? "Disabled"   : "UpDownstream");
}

/**
*   Loads the configuration from specified file.
*   Recursive function used for processing configuration files as they are encountered by include directive.
*   Because of this recursion it is important to keep track of configuration file and buffer pointers.
*/
bool loadConfig(char *cfgFile) {
    static struct filters  **filP, **rateP;
    static int64_t           intToken    = 0,     count = 0;
    FILE                    *confFilePtr = NULL, *fp;
    char                    *token       = NULL;
    struct stat              st;
    uint32_t                 st_mode;
    logwarning = 0;

    if (count == 0) {
        // Initialize common config on first entry.
        initCommonConfig();
        filP  = &commonConfig.defaultFilters;
        rateP = &commonConfig.defaultRates;
    }

    if (stat(cfgFile, &st) != 0 || !(st_mode = st.st_mode)) {
        LOG(LOG_WARNING, errno, "Config: Cannot stat '%s'.", cfgFile);
        return false;
    } else if (S_ISDIR(st_mode)) {
        // Include all .conf files in include directory.
        struct dirent *dirEnt;
        DIR           *dir;
        LOG(LOG_NOTICE, 0, "Config: Searching for config files in '%s'.", cfgFile);
        if (! (dir = opendir(cfgFile)))
            LOG(LOG_WARNING, errno, "Config: Cannot open include directory '%s'.", cfgFile);
        else while (!logwarning && (dirEnt = readdir(dir))) {
            char file[strlen(cfgFile) + strlen(dirEnt->d_name) + 2];
            sprintf(file, "%s/%s", cfgFile, dirEnt->d_name);
            if (strcmp(&file[strlen(file) - 5], ".conf") + stat(file, &st) == 0 && S_ISREG(st.st_mode) && !loadConfig(file))
                LOG(LOG_WARNING, 0, "Config: Failed to load config from '%s'.", file);
        }
        free(dir);
    } else if (count >= MAX_CFGFILE_RECURSION) {
        // Check recursion and return if exceeded.
        LOG(LOG_WARNING, 0, "Config: Too many includes (%d) while loading '%s'.", MAX_CFGFILE_RECURSION, token + 1);
        return false;
    } else if (! (confFilePtr = configFile(cfgFile, 1))) {
        // Open config file.
        return false;
    } else if (! (token = malloc(MAX_TOKEN_LENGTH + READ_BUFFER_SIZE + 2 * sizeof(uint32_t)))) {  // Freed by self
        // Allocate buffer and open config file and initialize common config when loading main config file.
        LOG(LOG_ERR, errno, "loadConfig: Out of Memory.");
    } else {
        // Increase count and initialize buffer. First char of token is ' ', counters to 0.
        count++;
        token[0] = ' ';
        *(uint64_t *)((char *)token + MAX_TOKEN_LENGTH + READ_BUFFER_SIZE) = 0;
        LOG(LOG_INFO, 0, "Config: Loading config (%d) from '%s'.", count, cfgFile);
    }

    // Loop until all configuration is read.
    if (S_ISREG(st_mode)) while (!logwarning && nextToken(token)) {
        // Process parameters which will result in a next valid config token first.
        while (token[1] && (strcmp(" phyint", token) == 0 || strcmp(" defaultfilter", token) == 0 || strstr(phyintopt, token))) {
            if (strcmp(" phyint", token) == 0) {
                parsePhyintToken(token);
            } else if (strcmp(" defaultfilter", token) == 0) {
                if (commonConfig.defaultFilters && *filP == commonConfig.defaultFilters) {
                    LOG(LOG_WARNING, 0, "Config: Defaultfilterany cannot be combined with default filters.");
                    break;
                } else {
                    LOG(LOG_NOTICE, 0, "Config: Parsing default filters.");
                    strcpy(token, "filter");
                    parseFilters("default", token, &filP, &rateP);
                }
            } else if (strstr(phyintopt, token)) {
                LOG(LOG_WARNING, 0, "Config: '%s' without phyint.", token + 1);
                break;
            }
        }

        if (strcmp(" include", token) == 0 && nextToken(token) && strcmp(commonConfig.configFilePath, token + 1) != 0) {
            // Load the config from include file and restore current.
            if (loadConfig(token + 1))
                LOG(LOG_NOTICE, 0, "Config: Succesfully loaded config from '%s'.", token + 1);
            else
                LOG(LOG_WARNING, 0, "Config: Failed to load config from '%s'.", token + 1);
            configFile(confFilePtr, 2);

        } else if (strcmp(" mctables", token) == 0 && INTTOKEN && (STARTUP || (token[1] = '\0'))) {
            commonConfig.mcTables = intToken < 1 || intToken > 65536 ? DEFAULT_ROUTE_TABLES : intToken;
            LOG(LOG_NOTICE, 0, "Config: %d multicast table hash entries.", commonConfig.mcTables);

        } else if (strcmp(" kbufsize", token) == 0 && INTTOKEN && (STARTUP || (token[1] = '\0'))) {
            commonConfig.kBufsz = intToken > 0 && intToken < 65536 ? intToken : K_BUF_SIZE;
            LOG(LOG_NOTICE, 0, "Config: Setting kernel ring buffer to %dKB.", intToken);

        } else if (strcmp(" pbufsize", token) == 0 && INTTOKEN && (STARTUP || (token[1] = '\0'))) {
            commonConfig.pBufsz = intToken > 0 && intToken < 65536 ? intToken : BUF_SIZE;
            LOG(LOG_NOTICE, 0, "Config: Setting kernel ring buffer to %dB.", intToken);

        } else if (strcmp(" reqqueuesize", token) == 0 && INTTOKEN) {
            commonConfig.reqQsz = intToken > 0 && intToken < 65535 ? intToken : REQQSZ;
            LOG(LOG_NOTICE, 0, "Config: Setting request queue size to %d.", intToken);

        } else if (strcmp(" timerqueuesize", token) == 0 && INTTOKEN) {
            commonConfig.tmQsz = intToken > 0 && intToken < 65535 ? intToken : REQQSZ;
            LOG(LOG_NOTICE, 0, "Config: Setting timer queue size to %d.", intToken);

        } else if (strcmp(" quickleave", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config: Quick leave mode enabled.");
            commonConfig.fastUpstreamLeave = true;

        } else if (strcmp(" maxorigins", token) == 0 && INTTOKEN) {
            if (intToken < DEFAULT_MAX_ORIGINS || intToken > 65535)
                LOG(LOG_WARNING, 0, "Config: Max origins must be between %d and 65535", DEFAULT_MAX_ORIGINS);
            else {
                commonConfig.maxOrigins = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting max multicast group sources to %d.", commonConfig.maxOrigins);
            }

        } else if (strcmp(" hashtablesize", token) == 0 && INTTOKEN) {
            if (! commonConfig.fastUpstreamLeave)
                LOG(LOG_WARNING, 0, "Config: hashtablesize is specified but quickleave not enabled.");
            else if (intToken < 8 || intToken > 131072)
                LOG(LOG_WARNING, 0, "Config: hashtablesize must be 8 to 131072 bytes (multiples of 8).");
            else {
                commonConfig.dHostsHTSize = (intToken - intToken % 8) * 8;
                LOG(LOG_NOTICE, 0, "Config: Hash table size for quickleave is %d.", commonConfig.dHostsHTSize / 8);
            }

        } else if (strcmp(" defaultupdown", token) == 0) {
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state already set.");
            else {
                commonConfig.defaultInterfaceState = IF_STATE_UPDOWNSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to updownstream.");
            }

        } else if (strcmp(" defaultup", token) == 0) {
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state already set.");
            else {
                commonConfig.defaultInterfaceState = IF_STATE_UPSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to upstream.");
            }

        } else if (strcmp(" defaultdown", token) == 0) {
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state already set.");
            else {
                commonConfig.defaultInterfaceState = IF_STATE_DOWNSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to downstream.");
            }

        } else if (strcmp(" defaultfilterany", token) == 0) {
            if (commonConfig.defaultFilters)
                LOG(LOG_WARNING, 0, "Config: Default filters cannot be combined with defaultfilterany.");
            else {
                LOG(LOG_NOTICE, 0, "Config: Interface default filter any.");
                if (! (commonConfig.defaultFilters = calloc(1, sizeof(struct filters))))
                    LOG(LOG_ERR, errno, "loadConfig: Out of Memory.");
                *commonConfig.defaultFilters = FILTERANY;
            }

        } else if (strcmp(" defaultratelimit", token) == 0 && INTTOKEN) {
            if (intToken < 0)
                LOG(LOG_WARNING, 0, "Config: Ratelimit must be more than 0.");
            else {
                commonConfig.defaultRatelimit = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default ratelimit %d.", intToken);
            }

        } else if (strcmp(" defaultthreshold", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Threshold must be between 1 and 255.");
            else {
                commonConfig.defaultThreshold = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default threshold %d.", intToken);
            }

        } else if (strcmp(" defaultquerierip", token) == 0 && nextToken(token)) {
            commonConfig.querierIp = inet_addr(token + 1);
            LOG(LOG_NOTICE, 0, "Config: Setting default querier ip address to %s.", inetFmt(commonConfig.querierIp, 1));

        } else if (strcmp(" defaultquerierver", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config: Querier version %d invalid.", intToken);
            else {
                commonConfig.querierVer = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default querier version to %d.", intToken);
            }

        } else if (strcmp(" defaultrobustness", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config: Robustness value must be between 1 and 7.");
            else {
                commonConfig.robustnessValue = intToken;
                commonConfig.lastMemberQueryCount = commonConfig.lastMemberQueryCount != DEFAULT_ROBUSTNESS
                                                  ? commonConfig.lastMemberQueryCount : commonConfig.robustnessValue;
                LOG(LOG_NOTICE, 0, "Config: Setting default robustness value to %d.", intToken);
            }

        } else if (strcmp(" defaultqueryinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Query interval must be between 1 and 255.");
            else {
                commonConfig.queryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default query interval to %ds.", commonConfig.queryInterval);
            }

        } else if (strcmp(" defaultqueryrepsonseinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Query response interval must be between 1 and 255.");
            else {
                commonConfig.queryResponseInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default query response interval to %d.", intToken);
            }

        } else if (strcmp(" defaultlastmemberinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Last member query interval must be between 1 and 255.");
            else {
                commonConfig.lastMemberQueryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default last member query interval to %d.", intToken);
            }

        } else if (strcmp(" defaultlastmembercount", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config: Last member count must be between 1 and 7.");
            else {
                commonConfig.lastMemberQueryCount = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default last member query count to %d.", intToken);
            }

        } else if (strcmp(" bwcontrol", token) == 0 && INTTOKEN) {
            commonConfig.bwControlInterval = intToken < 3 ? 3 : intToken;
            LOG(LOG_NOTICE, 0, "Config: Setting bandwidth control interval to %ds.", intToken);

        } else if (strcmp(" rescanvif", token) == 0 && INTTOKEN) {
            commonConfig.rescanVif = intToken > 0 ? intToken : 0;
            LOG(LOG_NOTICE, 0, "Config: Need detect new interface every %ds.", intToken);

        } else if (strcmp(" rescanconf", token) == 0 && INTTOKEN) {
            commonConfig.rescanConf = intToken > 0 ? intToken : 0;
            LOG(LOG_NOTICE, 0, "Config: Need detect config change every %ds.", intToken);

        } else if (strcmp(" loglevel", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config: Logleven must be between 1 and 7.");
            else {
                commonConfig.logLevel = intToken;
                LOG(LOG_NOTICE, 0, "Config: Log Level %d", commonConfig.logLevel);
            }

        } else if (strcmp(" logfile", token) == 0 && nextToken(token)) {
            // Only use log file if not logging to stderr.
            if (commonConfig.log2Stderr || (commonConfig.logFilePath &&
                                            memcmp(commonConfig.logFilePath, token + 1, strlen(token) - 2) == 0))
                continue;
            else if (! (fp = fopen(token + 1, "w")) || fclose(fp))
                LOG(LOG_WARNING, errno, "Config: Cannot open log file '%s'.", token + 1);
            else if (! (commonConfig.logFilePath = realloc(commonConfig.logFilePath, strlen(token))))
                // Freed by igmpProxyCleanUp()
                LOG(LOG_ERR, errno, "loadConfig: Out of Memory.");
            else {
                memcpy(commonConfig.logFilePath, token + 1, strlen(token) - 1);
                commonConfig.logFilePath[strlen(token) - 1] = '\0';
                time_t rawtime = time(NULL);
                utcoff.tv_sec = timegm(localtime(&rawtime)) - rawtime;
                LOG(LOG_NOTICE, 0, "Config: Logging to file '%s'", commonConfig.logFilePath);
            }

        } else if (strcmp(" proxylocalmc", token) == 0) {
            commonConfig.proxyLocalMc = true;
            LOG(LOG_NOTICE, 0, "Config: Will proxy local multicast range 224.0.0.0/8.");

        } else if (strcmp(" defaultnoquerierelection", token) == 0) {
            commonConfig.querierElection = false;
            LOG(LOG_NOTICE, 0, "Config: Will not participate in IGMP querier election by default.");

        } else if (strcmp(" cligroup", token) == 0 && nextToken(token)) {
            if (! getgrnam(token + 1))
                LOG(LOG_WARNING, errno, "Config: Incorrect CLI group '%s'.", token + 1);
            else if (! (commonConfig.socketGroup = getgrnam(token + 1)))
                LOG(LOG_WARNING, errno, "Failed to get grgid for '%s'.", token + 1, errno);
            else {
                if (!STARTUP)
                    cliSetGroup(commonConfig.socketGroup);
                LOG(LOG_NOTICE, 0, "Config: Group for cli access: '%s'.", commonConfig.socketGroup->gr_name);
            }

        } else if (token[1] != '\0')
            // Token may be " " if parsePhyintToken() returns without valid token.
            LOG(LOG_WARNING, 0, "Config: Unknown token '%s' in config file.", token + 1);
    }

    // Close the configfile. When including files, we're done.
    if (confFilePtr && configFile(NULL, 0))
        LOG(LOG_WARNING, errno, "Failed to close config file (%d) '%s'.", count, cfgFile);
    free(token);  // Alloced by self
    count--;
    if (count > 0 || S_ISDIR(st_mode))
        return true;

    // Check Query response interval and adjust if necessary (query response must be <= query interval).
    if ((commonConfig.querierVer != 3 ? commonConfig.queryResponseInterval
                                      : getIgmpExp(commonConfig.queryResponseInterval, 0)) / 10 > commonConfig.queryInterval) {
        if (commonConfig.querierVer != 3)
            commonConfig.queryResponseInterval = commonConfig.queryInterval * 10;
        else
            commonConfig.queryResponseInterval = getIgmpExp(commonConfig.queryInterval * 10, 1);
        float f = (commonConfig.querierVer != 3 ? commonConfig.queryResponseInterval
                                                : getIgmpExp(commonConfig.queryResponseInterval, 0)) / 10;
        LOG(LOG_NOTICE, 0, "Config: Setting default query interval to %ds. Default response interval %.1fs",
                            commonConfig.queryInterval, f);
    }

    // Check rescanvif status and start or clear timers if necessary.
    if (commonConfig.rescanVif && timers.rescanVif == 0) {
        timers.rescanVif = timer_setTimer(TDELAY(commonConfig.rescanVif * 10), "Rebuild Interfaces",
                                          rebuildIfVc, &timers.rescanVif);
    } else if (! commonConfig.rescanVif && timers.rescanVif != 0) {
        timer_clearTimer(timers.rescanVif);
        timers.rescanVif = 0;
    }

    // Check rescanconf status and start or clear timers if necessary.
    if (commonConfig.rescanConf && timers.rescanConf == 0)
        timers.rescanConf = timer_setTimer(TDELAY(commonConfig.rescanConf * 10), "Reload Configuration",
                                           reloadConfig, &timers.rescanConf);
    else if (! commonConfig.rescanConf && timers.rescanConf != 0) {
        timer_clearTimer(timers.rescanConf);
        timers.rescanConf = 0;
    }

    // Check bwcontrol status and start or clear timers if necessary..
    if (oldcommonConfig.bwControlInterval != commonConfig.bwControlInterval) {
        timer_clearTimer(timers.bwControl);
        timers.bwControl = 0;
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        int Va, len = sizeof(Va);
        if (!STARTUP && (getsockopt(MROUTERFD, IPPROTO_IP, MRT_API_CONFIG, (void *)&Va, (void *)&len) < 0
                         || ! (Va & MRT_MFC_BW_UPCALL))) {
            LOG(LOG_WARNING, errno, "Config: MRT_API_CONFIG Failed. Disabling bandwidth control.");
            commonConfig.bwControlInterval = 0;
        } else if (!STARTUP)
            clearGroups(getConfig);
#endif
        if (commonConfig.bwControlInterval)
            timers.bwControl = timer_setTimer(TDELAY(commonConfig.bwControlInterval * 10), "Bandwidth Control",
                                              bwControl, &timers.bwControl);
    }

    // Set hashtable size to 0 when quickleave is disabled.
    if (!commonConfig.fastUpstreamLeave)
        commonConfig.dHostsHTSize = 0;

    // Check if quickleave was enabled or disabled due to config change.
    if (!STARTUP && oldcommonConfig.fastUpstreamLeave != commonConfig.fastUpstreamLeave) {
        LOG(LOG_WARNING, 0, "Config: Quickleave mode was %s, reinitializing group tables.",
                            commonConfig.fastUpstreamLeave ? "disabled" : "enabled");
        clearGroups(CONFIG);
    }

    // Check if hashtable size was changed due to config change.
    if (!STARTUP && commonConfig.fastUpstreamLeave
                 && oldcommonConfig.dHostsHTSize != commonConfig.dHostsHTSize) {
        LOG(LOG_WARNING, 0, "Config: Downstream host hashtable size changed from %d to %d, reinitializing group tables.",
                            oldcommonConfig.dHostsHTSize, commonConfig.dHostsHTSize);
        clearGroups(CONFIG);
    }

    return !logwarning;
}

/**
 *   Reloads the configuration file and removes interfaces which were removed from config.
 */
void reloadConfig(uint64_t *tid) {
    // Check and set sigstatus to what we are actually doing right now.
    sigstatus       = NOSIG ? GOT_CONFREL : sigstatus;
    ovifConf        = vifConf;
    vifConf         = NULL;
    oldcommonConfig = commonConfig;

    // Load the new configuration keep reference to the old.
    if (!loadConfig(commonConfig.configFilePath)) {
        LOG(LOG_WARNING, 0, "Failed to reload config from '%s', keeping current.", commonConfig.configFilePath);
        if (vifConf)
            freeConfig(0);
        vifConf = ovifConf;
        commonConfig = oldcommonConfig;
    } else {
        // Rebuild the interfaces config, then free the old configuration.
        rebuildIfVc(NULL);
        freeConfig(1);
        LOG(LOG_WARNING, 0, "Configuration Reloaded.");
    }
    if (sigstatus == GOT_CONFREL && commonConfig.rescanConf)
        *tid = timer_setTimer(TDELAY(commonConfig.rescanConf * 10), "Reload Configuration", reloadConfig, tid);

    sigstatus = 0;
}

/**
*   Configures all multicast vifs and links to interface configuration. This function is responsible for:
*   - All active interfaces have a matching configuration. Either explicit through config file or implicit defaults.
*   - Default filters are created for the interface if necessary.
*   - Establish correct old and new state of interfaces.
*   - Control querier process and do route maintenance on interface transitions.
*   - Add and remove vifs from the kernel if needed.
*/
inline void configureVifs(void) {
    struct IfDesc    *IfDp = NULL;
    struct vifConfig *confPtr = NULL, *oconfPtr = NULL;
    struct filters   *fil, *ofil;
    uint32_t          vifcount = 0, upsvifcount = 0, downvifcount = 0;

    if (! vifConf)
        LOG(LOG_WARNING, 0, "No valid interfaces configuration. Beware, everything will be default.");
    GETIFLIF(IfDp, !IFREBUILD || (!(IfDp->state & 0x40) && (IfDp->state & 0x80))) {
        // Loop through all (new) interfaces and find matching config.
        for (confPtr = vifConf; confPtr && strcmp(IfDp->Name, confPtr->name); confPtr = confPtr->next);
        if (confPtr) {
            LOG(LOG_INFO, 0, "Found config for %s", IfDp->Name);
        } else {
            // Interface has no matching config, create default config.
            LOG(LOG_INFO, 0, "configureVifs: Creating default config for %s interface %s.",
                               IS_DISABLED(commonConfig.defaultInterfaceState)     ? "disabled"
                             : IS_UPDOWNSTREAM(commonConfig.defaultInterfaceState) ? "updownstream"
                             : IS_UPSTREAM(commonConfig.defaultInterfaceState)     ? "upstream"     : "downstream", IfDp->Name);
            if (! (confPtr = malloc(sizeof(struct vifConfig))))
                LOG(LOG_ERR, errno, "configureVifs: Out of Memory.");   // Freed by freeConfig()
            *confPtr = DEFAULT_VIFCONF;
            confPtr->filters = commonConfig.defaultFilters;
            strcpy(confPtr->name, IfDp->Name);
            confPtr->next = vifConf;
            vifConf = confPtr;
        }
        // Link the configuration to the interface. And update the states.
        oconfPtr = IfDp->conf;
        IfDp->conf = confPtr;
    }

    for (uVifs = 0, IFL(IfDp)) {
        // Loop through all interface and configure corresponding MC vifs.
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
        register uint8_t oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);

        // Set configured querier ip to interface address if not configured
        // and set version to 3 for disabled/upstream only interface.
        if (IfDp->conf->qry.ip == (uint32_t)-1)
            IfDp->conf->qry.ip = IfDp->InAdr.s_addr;
        if (!IS_DOWNSTREAM(IfDp->state))
            IfDp->conf->qry.ver = 3;
        if (IfDp->conf->qry.ver == 1)
            IfDp->conf->qry.interval = 10, IfDp->conf->qry.responseInterval = 10;

        // Check if filters have changed so that ACLs will be reevaluated.
        if (!IfDp->filCh && (CONFRELOAD || SSIGHUP)) {
            for (fil = confPtr->filters, ofil = oconfPtr ? oconfPtr->filters : NULL;
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
                upsvifcount++;
                BIT_SET(uVifs, IfDp->index);
            }
        }

        // Do maintenance on vifs according to their old and new state.
        if      ( IS_DISABLED(oldstate)   && IS_UPSTREAM(newstate)  )    { ctrlQuerier(1, IfDp); clearGroups(IfDp); }
        else if ( IS_DISABLED(oldstate)   && IS_DOWNSTREAM(newstate))    { ctrlQuerier(1, IfDp);                    }
        else if (!IS_DISABLED(oldstate)   && IS_DISABLED(newstate)  )    { ctrlQuerier(0, IfDp); clearGroups(IfDp); }
        else if ( oldstate != newstate)                                  { ctrlQuerier(2, IfDp); clearGroups(IfDp); }
        else if ( oldstate == newstate    && !IS_DISABLED(newstate) )    {                       clearGroups(IfDp); }
        IfDp->filCh = false;

        // Check if vif needs to be removed.
        if (IS_DISABLED(newstate) && IfDp->index != (uint8_t)-1) {
            k_delVIF(IfDp);
            if (vifcount)
                vifcount--;
            if (IS_DOWNSTREAM(oldstate) && downvifcount)
                downvifcount--;
            if (IS_UPSTREAM(oldstate)   && upsvifcount)
                upsvifcount--;
        }
    }

    // All vifs created / updated, check if there is an upstream and at least one downstream.
    if (!SHUTDOWN && (vifcount < 2 || upsvifcount == 0 || downvifcount == 0))
        LOG((STARTUP ? LOG_ERR : LOG_WARNING), 0, "There must be at least 2 interfaces, 1 Vif as upstream and 1 as dowstream.");
}
