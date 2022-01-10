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
*   Generic config file reader. Used to open a config file, and read the tokens from it.
*   The parser is really simple nd does no backlogging. This means that no form of text escaping
*   and qouting is currently supported. '#' chars are read as comments, which lasts until a newline.
*/

#include "igmpv3proxy.h"

// Local Prototypes.
static FILE             *configFile(char *fileName, int open);
static bool              nextConfigToken(char *token);
static void              initCommonConfig();
static void              parseFilters(char *token, struct filters ***filP, struct filters ***rateP);
static struct vifConfig *parsePhyintToken(char *token);

// Daemon Configuration.
static struct Config commonConfig, oldcommonConfig;

// All valid configuration options. Pre- and Append whitespace to allow for strstr() exact token matching.
static const char *options = " phyint quickleave maxorigins hashtablesize routetables defaultdown defaultup defaultupdown defaultthreshold defaultratelimit defaultquerierver defaultquerierip defaultrobustness defaultqueryinterval defaultqueryrepsonseinterval defaultlastmemberinterval defaultlastmembercount bwcontrol rescanvif rescanconf loglevel logfile proxylocalmc defaultnoquerierelection upstream downstream disabled ratelimit threshold querierver querierip robustness queryinterval queryrepsonseinterval lastmemberinterval lastmembercount noquerierelection defaultfilterany nodefaultfilter filter altnet whitelist reqqueuesize kbufsize pbufsize ";
static const char *phyintopt = " updownstream upstream downstream disabled ratelimit threshold noquerierelection querierip querierver robustnessvalue queryinterval queryrepsonseinterval lastmemberinterval lastmembercount defaultfilter filter altnet whitelist ";

// Structures to keep vif configuration and black/whitelists.
static struct vifConfig   *vifConf, *ovifConf;
uint32_t                   uVifs;

// Keeps timer ids for configurable timed functions.
static struct timers {
    uint64_t rescanConf;
    uint64_t rescanVif;
    uint64_t bwControl;
} timers = { 0, 0, 0 };

// Macro to get a token which should be integer.
#define INTTOKEN (nextConfigToken(token) && ((intToken = atoll(token)) || !intToken))

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
        if (!old || !(cConf->state & 0x80)) {
            // Do not remove and free filters, if interface config should be reused.
            for (; cConf->filters && cConf->filters != dFil; tFil = cConf->filters->next, free(cConf->filters), cConf->filters = tFil);
            for (; cConf->rates && cConf->rates != dRate; tRate = cConf->rates->next, free(cConf->rates), cConf->rates = tRate);
        }
        if (old && (cConf->state & 0x80)) {
            // If interface was flagged, because of interface config error reset flag.
            cConf->state &= ~0x80;
        } else if ((cConf->state & 0x80) && !cConf->noDefaultFilter) {
            // If interface was flagged and config reload failed enterely, reset to old default filters.
            for (fil = cConf->filters; fil && fil->next != dFil; fil = fil->next);
            fil ? (fil->next = oldcommonConfig.defaultFilters) : (cConf->filters = oldcommonConfig.defaultFilters);
        } else
            free(cConf);

    }
    if (old || SHUTDOWN) {
        // Free default filters when clearing old config, or on shutdown.
        for (; dFil; tFil = dFil->next, free(dFil), dFil = tFil);
        for (; dRate; tRate = dRate->next, free(dRate), dRate = tRate);
    }
    if (SHUTDOWN) {
        timer_clearTimer(timers.rescanConf);
        timer_clearTimer(timers.rescanVif);
        timer_clearTimer(timers.bwControl);
        timers = (struct timers){ 0, 0, 0 };
    }

    LOG(LOG_DEBUG, 0, "freeConfig: %s cleared.", (old ? "Old configuration" : "Configuration"));
}

/**
*   Opens or closes config file specified by fileName.
*   When opening a file and file was not closed, retry and bail if it fails again.
*   When called with NULL pointer to filename, return current config file pointer.
*/
static FILE *configFile(char *fileName, int open) {
    static FILE *confFilePtr = NULL;
    if (!open && confFilePtr && fclose(confFilePtr) == 0)
        confFilePtr = NULL;
    else if (open && confFilePtr && fclose(confFilePtr) != 0)
        LOG(LOG_ERR, errno, "Failed to close config file %s.", fileName);

    return !open || !(! fileName || (confFilePtr = fopen(fileName, "r"))) ? NULL : confFilePtr;
}

/**
*   Read next token from config file. Return false if EOF.
*/
static bool nextConfigToken(char *token) {
    static uint16_t bufPtr = 0, readSize = 0, tokenPtr;
    static char     cBuffer[READ_BUFFER_SIZE];
    bool            finished = false, overSized = false, commentFound = false;

    token[(tokenPtr = 1) - 1] = ' ';  // First char of token is whitespace.
    while (!finished) {
        // Outer loop, If read pointer is at the end of the buffer, we should read next chunk.
        if (bufPtr == readSize) {
            // Fill buffer. If 0 bytes read, or less then BUFFER bytes were read, assume EOF.
            bufPtr = 0;
            if (   (readSize > 0 && readSize < READ_BUFFER_SIZE)
                || (readSize = fread(cBuffer, sizeof(char), READ_BUFFER_SIZE, configFile(NULL, 1))) == 0) {
                finished = true;
                readSize = 0;
            }
        }

        while (!finished && !(cBuffer[bufPtr] == '\0') && bufPtr < readSize) {
            // Inner loop, character processing. \0 means EOF.
            switch (cBuffer[bufPtr]) {
            case '#':
                // Found a comment start.
                commentFound = true;
                break;

            case '\n':
                commentFound = false;  /* FALLTHRU */
            case '\r':
            case '\t':
            case ' ':
                // Newline, CR, Tab and space are end of token, or ignored.
                finished = true;
                break;

            default:
                // Append char to token. When token is oversized do not increase tokenPtr, but keep parsing until whitespace.
                if (!commentFound && !overSized)
                    token[tokenPtr++] = tolower(cBuffer[bufPtr]);
                if (tokenPtr == MAX_TOKEN_LENGTH - 2)
                    overSized = true;
            }
            bufPtr++;
        }
    }

    token[tokenPtr++] = ' ';   // Add trailing whitespace.
    token[tokenPtr]   = '\0';  // Make sure token is null terminated string.
    return (tokenPtr > 2);     // Valid token is more than 2 white spaces.
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
    if (!loadConfig(CONFIG->configFilePath)) {
        LOG(LOG_WARNING, 0, "Unable to load config file %s, keeping current.", commonConfig.configFilePath);
        if (vifConf)
            freeConfig(0);
        vifConf = ovifConf;
        commonConfig = oldcommonConfig;
    } else {
        // Rebuild the interfaces config, then free the old configuration.
        rebuildIfVc(NULL);
        freeConfig(1);

        LOG(LOG_INFO, 0, "reloadConfig: Config Reloaded. OldConfPtr: %x, NewConfPtr, %x", ovifConf, vifConf);
    }
    if (sigstatus == GOT_CONFREL && commonConfig.rescanConf)
        *tid = timer_setTimer(TDELAY(commonConfig.rescanConf * 10), "Reload Configuration", (timer_f)reloadConfig, tid);

    sigstatus = 0;
}

/**
*   Initializes default configuration.
*/
static void initCommonConfig(void) {
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

    // Defaul maximum nr of sources for route. Always a minimum of 64 sources is allowed
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
    commonConfig.socketGroup = *getgrgid(0);
}

/*
*   Parsing of filters. If an error is made in a list, the whole list will be ignored.
*/
static void parseFilters(char *token, struct filters ***filP, struct filters ***rateP) {
    int64_t  intToken;
    uint32_t addr, mask;
    char     list[MAX_TOKEN_LENGTH], *filteropt = " allow a block b ratelimit r rl up down updown both 0 1 2 ";
    struct filters filNew = { {0xFFFFFFFF, 0xFFFFFFFF}, {0xFFFFFFFF, 0xFFFFFFFF}, (uint8_t)-1, (uint8_t)-1, (uint64_t)-1, NULL },
                   filErr = { {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint8_t)-1, (uint8_t)-1, (uint64_t)-1, NULL },
                   fil    = filNew;
    strcpy(list, token);
    for (;nextConfigToken(token) && (strstr(filteropt, token) || !strstr(options, token));) {
        if (strcmp(" filter ", list) == 0 && fil.dst.ip != 0xFFFFFFFF && fil.action == (uint64_t)-1) {
            if (fil.dir == (uint8_t)-1) {
                if (strcmp(" up ", token) == 0 || strcmp(" 1 ", token) == 0)
                    fil.dir = 1;
                else if (strcmp(" down ", token) == 0 || strcmp(" 2 ", token) == 0)
                    fil.dir = 2;
                else
                    fil.dir = 3;
            }
            if ((strcmp("ratelimit", token) == 0 || strcmp(" r ", token) == 0 || strcmp(" rl ", token) || strcmp(" 2 ", token) == 0) && INTTOKEN) {
                if (! commonConfig.bwControlInterval || (fil.src.ip != 0 && fil.src.ip != 0xFFFFFFFF)) {
                    LOG(LOG_INFO, 0, "Config: FIL: %s Ignoring %s - %s %lld.", ! commonConfig.bwControlInterval ?
                        "BW Control disabled." : "Ratelimit rules must have INADDR_ANY as source.",
                         inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), intToken);
                    fil = filNew;
                    continue;
                } else
                    fil.action = intToken >= 2 ? intToken : 2;
            } else if (strcmp(" allow ", token) == 0 || strcmp(" a ", token) == 0 || strcmp(" 1 ", token) == 0)
                fil.action = ALLOW;
            else if (strcmp(" block ", token) == 0 || strcmp(" b ", token) == 0 || strcmp(" 0 ", token) == 0)
                fil.action = BLOCK;
            else if (!strstr(filteropt, token)) {
                LOG(LOG_WARNING, 0, "Config: FIL: %s is not a valid filter action or direction.", token);
                fil = filErr;
            }
        } else if (!parseSubnetAddress(token, &addr, &mask)) {
            // Unknown token. Ignore...
            LOG(LOG_WARNING, 0, "Config: FIL: Uparsable subnet '%s'.", token, list);
            fil = filErr;
        } else if ((strcmp(" whitelist ", list) == 0 || (strcmp(" filter ", list) == 0 && fil.src.ip != 0xFFFFFFFF))
                   && !IN_MULTICAST(ntohl(addr))) {
            // Check if valid MC group for whitelist are filter dst.
            LOG(LOG_WARNING, 0, "Config: FIL: %s is not a valid multicast address.", inetFmt(addr, 1));
            fil = filErr;
        } else if ((addr | mask) != mask) {
            // Check if valid sn/mask pair.
            LOG(LOG_WARNING, 0, "Config: FIL: %s is not valid subnet/mask pair.", inetFmts(addr, mask, 1));
            fil = filErr;
        } else if (strcmp(" altnet ", list) == 0) {
            // altnet is not usefull or compatible with igmpv3, ignore.
            fil = filErr;
        } else if (strcmp(" whitelist ", list) == 0) {
            fil = (struct filters){ {INADDR_ANY, 0}, {addr, mask}, 3, 3, ALLOW, NULL };
        } else if (fil.src.ip == 0xFFFFFFFF) {
            if (! IN_MULTICAST(ntohl(addr))) {
                fil.src.ip   = addr;
                fil.src.mask = mask;
            } else {
                LOG(LOG_WARNING, 0, "Config: FIL: Source address %s cannot be multicast.", inetFmts(addr, mask, 1));
                fil = filErr;
            }
        } else if (fil.dst.ip == 0xFFFFFFFF) {
            fil.dst.ip   = addr;
            fil.dst.mask = mask;
        }

        if (fil.src.ip == 0xFFFFFFFF && fil.src.mask == 0) {
            // Error in list detected, go to next.
            while (nextConfigToken(token) && ! strstr(options, token));
            break;
        } else if (   (fil.src.ip != 0xFFFFFFFF || (fil.src.ip == 0xFFFFFFFF && fil.action > ALLOW))
                   &&  fil.dst.ip != 0xFFFFFFFF && ! (fil.action == (uint64_t)-1)) {
            // Correct filter, add and reset fil to process next entry.
            LOG(LOG_INFO, 0, "Config: FIL: Adding filter Src: %s, Dst: %s, Dir: %s, Action: %s.",
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
*   Loads the configuration from file, and stores the config in respective holders.
*/
bool loadConfig(char *cfgFile) {
    static char        token[MAX_TOKEN_LENGTH];
    struct  vifConfig *tmpPtr;
    int64_t            intToken;

    // Initialize common config
    initCommonConfig();

    // Open config file and read first token.
    if (! configFile(cfgFile, 1) || !nextConfigToken(token))
        return false;
    LOG(LOG_INFO, 0, "loadConfig: Loading config from %s.", commonConfig.configFilePath);

    // Set pointer to pointer to filters list.
    struct filters **filP = &commonConfig.defaultFilters, **rateP = &commonConfig.defaultRates;

    // Loop until all configuration is read.
    while (true) {
        if (strcmp(" phyint ", token) == 0 && (tmpPtr = parsePhyintToken(token))) {
            // Got a valid interface config.
            LOG(LOG_NOTICE, 0, "Config: IF: %s, Ratelimit: %d, Threshold: %d, State: %d, Ptrs: %p: %p",
                                tmpPtr->name, tmpPtr->ratelimit, tmpPtr->threshold, tmpPtr->state, tmpPtr, tmpPtr->filters);
            // Insert config, and move temppointer to next location...
            tmpPtr->next = vifConf;
            vifConf      = tmpPtr;
            continue;

        } else if (STARTUP && strcmp(" kbufsize ", token) == 0 && INTTOKEN) {
            // Got a reqqueuesize token....
            commonConfig.kBufsz = intToken > 0 && intToken < 65536 ? intToken : K_BUF_SIZE;
            LOG(LOG_NOTICE, 0, "Config: Setting kernel ring buffer to %dKB.", intToken);

        } else if (STARTUP && strcmp(" pbufsize ", token) == 0 && INTTOKEN) {
            // Got a reqqueuesize token....
            commonConfig.pBufsz = intToken > 0 && intToken < 65536 ? intToken : BUF_SIZE;
            LOG(LOG_NOTICE, 0, "Config: Setting kernel ring buffer to %dB.", intToken);

        } else if (strcmp(" reqqueuesize ", token) == 0 && INTTOKEN) {
            // Got a reqqueuesize token....
            commonConfig.reqQsz = intToken > 0 && intToken < 65535 ? intToken : REQQSZ;
            LOG(LOG_NOTICE, 0, "Config: Setting request queue size to %d.", intToken);

        } else if (strcmp(" timerqueuesize ", token) == 0 && INTTOKEN) {
            // Got a reqqueuesize token....
            commonConfig.tmQsz = intToken > 0 && intToken < 65535 ? intToken : REQQSZ;
            LOG(LOG_NOTICE, 0, "Config: Setting timer queue size to %d.", intToken);

        } else if (strcmp(" quickleave ", token) == 0) {
            // Got a quickleave token....
            LOG(LOG_NOTICE, 0, "Config: Quick leave mode enabled.");
            commonConfig.fastUpstreamLeave = true;

        } else if (strcmp(" maxorigins ", token) == 0 && INTTOKEN) {
            // Got a maxorigins token...
            if (intToken >= DEFAULT_MAX_ORIGINS || intToken <= 65535 || intToken == 0)
                commonConfig.maxOrigins = intToken;
            LOG(LOG_NOTICE, 0, "Config: Setting max multicast group sources to %d.", commonConfig.maxOrigins);

        } else if (strcmp(" hashtablesize ", token) == 0 && INTTOKEN) {
            // Got a hashtablesize token...
            if (! commonConfig.fastUpstreamLeave)
                LOG(LOG_WARNING, 0, "Config: hashtablesize is specified but quickleave not enabled. Ignoring.");
            else if (intToken < 8 || intToken > 131072)
                LOG(LOG_WARNING, 0, "Config: hashtablesize must be 8 to 131072 bytes (multiples of 8), using default %d.",
                                     commonConfig.dHostsHTSize);
            else {
                commonConfig.dHostsHTSize = (intToken - intToken % 8) * 8;
                LOG(LOG_NOTICE, 0, "Config: Hash table size for quickleave is %d.", commonConfig.dHostsHTSize / 8);
            }

        } else if (STARTUP && strcmp(" mctables ", token) == 0 && INTTOKEN) {
            // Got a routetables token...
            commonConfig.mcTables = intToken < 1 || intToken > 65536 ? DEFAULT_ROUTE_TABLES : intToken;
            LOG(LOG_NOTICE, 0, "Config: %d multicast table hash entries.", commonConfig.mcTables);

        } else if (strcmp(" defaultupdown ", token) == 0) {
            // Got a defaultupdown token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_UPDOWNSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to updownstream.");
            }

        } else if (strcmp(" defaultup ", token) == 0) {
            // Got a defaultup token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_UPSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to upstream.");
            }

        } else if (strcmp(" defaultdown ", token) == 0) {
            // Got a defaultdown token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_DOWNSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to downstream.");
            }

        } else if (strcmp(" defaultfilterany ", token) == 0) {
            // Got a defaultfilterany token...
            if (commonConfig.defaultFilters)
                LOG(LOG_WARNING, 0, "Config: Default filters cannot be combined with defaultfilterany.");
            else {
                LOG(LOG_NOTICE, 0, "Config: Interface default filter any.");
                if (! (commonConfig.defaultFilters = calloc(1, sizeof(struct filters))))
                    LOG(LOG_ERR, errno, "loadConfig: Out of Memory.");
                *commonConfig.defaultFilters = FILTERANY;
            }

        } else if (strcmp(" defaultfilter ", token) == 0) {
            // Got a defaultfilterany token...
            if (commonConfig.defaultFilters && *filP == commonConfig.defaultFilters) {
                LOG(LOG_WARNING, 0, "Config: Defaultfilterany cannot be combined with default filters.");
                while (nextConfigToken(token) && !strstr(options, token));
            } else {
                LOG(LOG_NOTICE, 0, "Config: Parsing default filters.");
                strcpy(token, "filter");
                parseFilters(token, &filP, &rateP);
            }
            continue;

        } else if (strcmp(" defaultratelimit ", token) == 0 && INTTOKEN) {
            // Default Ratelimit
            if (intToken < 0)
                LOG(LOG_WARNING, 0, "Config: Ratelimit must be more than 0.");
            else {
                commonConfig.defaultRatelimit = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default ratelimit %d.", intToken);
            }

        } else if (strcmp(" defaultthreshold ", token) == 0 && INTTOKEN) {
            // Default Threshold
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Threshold must be between 1 and 255.");
            else {
                commonConfig.defaultThreshold = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default threshold %d.", intToken);
            }

        } else if (strcmp(" defaultquerierip ", token) == 0 && nextConfigToken(token)) {
            // Got a querierip token.
            commonConfig.querierIp = inet_addr(token);
            LOG(LOG_NOTICE, 0, "Config: Setting default querier ip address to %s.", inetFmt(commonConfig.querierIp, 1));

        } else if (strcmp(" defaultquerierver ", token) == 0 && INTTOKEN) {
            // Got a querierver token.
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config: Querier version %d invalid.", intToken);
            else {
                commonConfig.querierVer = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default querier version to %d.", intToken);
            }

        } else if (strcmp(" defaultrobustness ", token) == 0 && INTTOKEN) {
            // Got a robustnessvalue token...
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config IF: Robustness value must be between 1 and 7.");
            else {
                commonConfig.robustnessValue = intToken;
                commonConfig.lastMemberQueryCount = commonConfig.lastMemberQueryCount != DEFAULT_ROBUSTNESS
                                                  ? commonConfig.lastMemberQueryCount : commonConfig.robustnessValue;
                LOG(LOG_NOTICE, 0, "Config: Setting default robustness value to %d.", intToken);
            }

        } else if (strcmp(" defaultqueryinterval ", token) == 0 && INTTOKEN) {
            // Got a queryinterval token...
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Query interval must be between 1 and 255.");
            else {
                commonConfig.queryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default query interval to %ds.", commonConfig.queryInterval);
            }

        } else if (strcmp(" defaultqueryrepsonseinterval ", token) == 0 && INTTOKEN) {
            // Got a queryresponsenterval token...
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Query response interval must be between 1 and 255.");
            else {
                commonConfig.queryResponseInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default query response interval to %d.", intToken);
            }

        } else if (strcmp(" defaultlastmemberinterval ", token) == 0 && INTTOKEN) {
            // Got a lastmemberinterval token...
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Last member query interval must be between 1 and 255.");
            else {
                commonConfig.lastMemberQueryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default last member query interval to %d.", intToken);
            }

        } else if (strcmp(" defaultlastmembercount ", token) == 0 && INTTOKEN) {
            // Got a lastmembercount token...
            commonConfig.lastMemberQueryCount = intToken < 1 || intToken > 7 ? DEFAULT_ROBUSTNESS : intToken;
            LOG(LOG_NOTICE, 0, "Config: Setting default last member query count to %d.", intToken);

        } else if (strcmp(" bwcontrol ", token) == 0 && INTTOKEN) {
            // Got a bcontrolinterval token...
            commonConfig.bwControlInterval = intToken < 3 ? 3 : intToken;
            LOG(LOG_NOTICE, 0, "Config: Setting bandwidth control interval to %ds.", intToken);

        } else if (strcmp(" rescanvif ", token) == 0 && INTTOKEN) {
            // Got a rescanvif token...
            commonConfig.rescanVif = intToken > 0 ? intToken : 0;
            LOG(LOG_NOTICE, 0, "Config: Need detect new interface every %ds.", intToken);

        } else if (strcmp(" rescanconf ", token) == 0 && INTTOKEN) {
            // Got a rescanconf token...
            commonConfig.rescanConf = intToken > 0 ? intToken : 0;
            LOG(LOG_NOTICE, 0, "Config: Need detect config change every %ds.", intToken);

        } else if (strcmp(" loglevel ", token) == 0 && INTTOKEN) {
            // Got a loglevel token...
            commonConfig.logLevel = !commonConfig.log2Stderr && intToken > 0 && intToken < 8 ? intToken : commonConfig.logLevel;
            LOG(LOG_NOTICE, 0, "Config: Log Level %d", commonConfig.logLevel);

        } else if (strcmp(" logfile ", token) == 0 && nextConfigToken(token)) {
            // Got a logfile token. Only use log file if not logging to stderr.
            FILE *fp;
            if (commonConfig.logFilePath)
                free(commonConfig.logFilePath);  // Alloced by self
            if (strstr(options, token))
                LOG(LOG_WARNING, 0, "Config: No logfile path specified.");
            else if (!commonConfig.log2Stderr && (! (fp = fopen(token, "w")) || fclose(fp)))
                LOG(LOG_WARNING, errno, "Config: Cannot open log file %s.", token);
            else if (!commonConfig.log2Stderr && ! (commonConfig.logFilePath = malloc(strlen(token))))
                // Freed by igmpProxyCleanUp() or self
                LOG(LOG_ERR, errno, "loadConfig: Out of Memory.");
            else if (!commonConfig.log2Stderr) {
                strcpy(commonConfig.logFilePath, token);
                time_t rawtime = time(NULL);
                utcoff.tv_sec = timegm(localtime(&rawtime)) - rawtime;
                LOG(LOG_NOTICE, 0, "Config: Log File: %s", commonConfig.logFilePath);
            }

        } else if (strcmp(" proxylocalmc ", token) == 0) {
            // Got a proxylocalmc token....
            commonConfig.proxyLocalMc = true;
            LOG(LOG_NOTICE, 0, "Config: Will proxy local multicast range 224.0.0.0/8.");

        } else if (strcmp(" defaultnoquerierelection ", token) == 0) {
            // Got a noquerierelection token....
            commonConfig.querierElection = false;
            LOG(LOG_NOTICE, 0, "Config: Will not participate in IGMP querier election by default.");

        } else if (strcmp(" cligroup ", token) == 0 && nextConfigToken(token)) {
            // Got a cligroup token....
            if (! getgrnam(token))
                LOG(LOG_WARNING, errno, "Config: Incorrect CLI group %s.", token);
            else {
                commonConfig.socketGroup = *getgrnam(token);
                if (!STARTUP)
                    cliSetGroup(commonConfig.socketGroup.gr_gid);
                LOG(LOG_NOTICE, 0, "Config: Group for cli access: %s.", commonConfig.socketGroup.gr_name);
            }

        } else if (strstr(phyintopt, token)) {
            LOG(LOG_WARNING, 0, "Config: %s without phyint. Ignoring.", token);
            while (nextConfigToken(token) && !strstr(options, token));
            continue;

        } else {
            // Unparsable token.
            LOG(LOG_WARNING, 0, "Config: Unknown token '%s' in config file.", token);
            if (!STARTUP)
                return false;
        }

        if (!nextConfigToken(token))
            break;
    }

    // Close the configfile.
    configFile(NULL, 0);

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
                                          (timer_f)rebuildIfVc, &timers.rescanVif);
    } else if (! commonConfig.rescanVif && timers.rescanVif != 0) {
        timer_clearTimer(timers.rescanVif);
        timers.rescanVif = 0;

    }

    // Check rescanconf status and start or clear timers if necessary.
    if (commonConfig.rescanConf && timers.rescanConf == 0)
        timers.rescanConf = timer_setTimer(TDELAY(commonConfig.rescanConf * 10), "Reload Configuration",
                                           (timer_f)reloadConfig, &timers.rescanConf);
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
                                              (timer_f)bwControl, &timers.bwControl);
    }

    // Set hashtable size to 0 when quickleave is disabled.
    if (!commonConfig.fastUpstreamLeave)
        commonConfig.dHostsHTSize = 0;

    // Check if quickleave was enabled or disabled due to config change.
    if (!STARTUP && oldcommonConfig.fastUpstreamLeave != commonConfig.fastUpstreamLeave) {
        LOG(LOG_NOTICE, 0, "Config: Quickleave mode was %s, reinitializing routes.",
                            commonConfig.fastUpstreamLeave ? "disabled" : "enabled");
        clearGroups(CONFIG);
    }

    // Check if hashtable size was changed due to config change.
    if (!STARTUP && commonConfig.fastUpstreamLeave
                 && oldcommonConfig.dHostsHTSize != commonConfig.dHostsHTSize) {
        LOG(LOG_NOTICE, 0, "Config: Downstream host hashtable size changed from %i to %i, reinitializing routes.",
                            oldcommonConfig.dHostsHTSize, commonConfig.dHostsHTSize);
        clearGroups(CONFIG);
    }

    return true;
}

/**
*   Internal function to parse phyint config.
*/
static struct vifConfig *parsePhyintToken(char *token) {
    struct vifConfig *tmpPtr;
    int64_t           intToken;

    if (!nextConfigToken(token)) {
        // First token should be the interface name.
        LOG(LOG_WARNING, 0, "Config: You should at least name your interfeces.");
        return NULL;
    } else if (! (tmpPtr = malloc(sizeof(struct vifConfig))))
        // Allocate and initialize memory for new configuration.
        LOG(LOG_ERR, errno, "parsePhyintToken: Out of memory.");  // Freed by freeConfig()
    *tmpPtr = DEFAULT_VIFCONF;
    LOG(LOG_NOTICE, 0, "Config (%s): Configuring interface.", token);

    // Make a copy of the token to store the IF name. Make sure it is NULL terminated.
    memcpy(tmpPtr->name, token, IF_NAMESIZE);
    tmpPtr->name[IF_NAMESIZE - 1] = '\0';
    if (strlen(token) >= IF_NAMESIZE)
        LOG(LOG_WARNING, 0, "Config (%s): %s larger than system IF_NAMESIZE(%d).", tmpPtr->name, IF_NAMESIZE, token);

    // Set pointer to pointer to filters list.
    struct filters **filP = &tmpPtr->filters, **rateP = &tmpPtr->rates;

    // Parse the rest of the config..
    if (nextConfigToken(token)) while (true) {
        if (strcmp(" filter ", token) == 0 || strcmp(" altnet ", token) == 0 || strcmp(" whitelist ", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config (%s): Parsing %s.", tmpPtr->name, token);
            parseFilters(token, &filP, &rateP);
            continue;

        } else if (strcmp(" nodefaultfilter ", token) == 0) {
            tmpPtr->noDefaultFilter = true;
            LOG(LOG_NOTICE, 0, "Config (%s): Not setting default filters.", tmpPtr->name);

        } else if (strcmp(" updownstream ", token) == 0) {
            tmpPtr->state = IF_STATE_UPDOWNSTREAM;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting to Updownstream.", tmpPtr->name);

        } else if (strcmp(" upstream ", token) == 0) {
            tmpPtr->state = IF_STATE_UPSTREAM;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting to Upstream.", tmpPtr->name);

        } else if (strcmp(" downstream ", token) == 0) {
            tmpPtr->state = IF_STATE_DOWNSTREAM;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting to Downstream.");

        } else if (strcmp(" disabled ", token) == 0) {
            tmpPtr->state = IF_STATE_DISABLED;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting to Disabled.", tmpPtr->name);

        } else if (strcmp(" ratelimit ", token) == 0 && INTTOKEN) {
            if (intToken < 0)
                LOG(LOG_WARNING, 0, "Config (%s): Ratelimit must 0 or more.", tmpPtr->name);
            else {
                tmpPtr->ratelimit = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting ratelimit to %lld.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" threshold ", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config (%s): Threshold must be between 1 and 255.", tmpPtr->name);
            else {
                tmpPtr->threshold = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting threshold to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" querierip ", token) == 0 && nextConfigToken(token)) {
            tmpPtr->qry.ip = inet_addr(token);
            LOG(LOG_NOTICE, 0, "Config (%s): Setting querier ip address to %s.",tmpPtr->name,  inetFmt(tmpPtr->qry.ip, 1));

        } else if (strcmp(" querierver ", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config (%s): IGMP version %d not valid.", tmpPtr->name, intToken);
            else {
                tmpPtr->qry.ver = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting querier version %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" noquerierelection ", token) == 0) {
            tmpPtr->qry.election = false;
            LOG(LOG_NOTICE, 0, "Config (%s): Will not participate in IGMP querier election.", tmpPtr->name);

        } else if (strcmp(" robustness ", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config (%s): Robustness value mus be between 1 and 7.", tmpPtr->name);
            else {
                tmpPtr->qry.robustness = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Settings robustness to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" queryinterval ", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config (%s): Query interval value should be between 1 than 255.", tmpPtr->name);
            else {
                tmpPtr->qry.interval = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting query interval to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" queryresponseinterval ", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config (%s): Query response interval value should be between 1 than 255.", tmpPtr->name);
            else {
                tmpPtr->qry.responseInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting query response interval to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" lastmemberinterval ", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config (%s): Last member interval value should be between 1 than 255.", tmpPtr->name);
            else {
                tmpPtr->qry.lmInterval =  intToken;
                LOG(LOG_NOTICE, 0, "Config (%s): Setting last member query interval to %d.", tmpPtr->name, intToken);
            }

        } else if (strcmp(" lastmembercount ", token) == 0 && INTTOKEN) {
            tmpPtr->qry.lmCount = intToken < 1 || intToken > 7 ? DEFAULT_ROBUSTNESS : intToken;
            tmpPtr->qry.lmCount = intToken;
            LOG(LOG_NOTICE, 0, "Config (%s): Setting last member query count to %d.", tmpPtr->name, tmpPtr->qry.lmCount);

        } else if (! strstr(options, token)) {
            // Unknown token, return error.
            LOG(LOG_WARNING, 0, "Config (%s): Unknown token '%s', discarding configuration.", tmpPtr->name, token);
            if (!STARTUP) {
                // When reloading config, find old vifconf and return that.
                char   name[IF_NAMESIZE];
                struct filters *fil;
                strcpy(name, tmpPtr->name);
                for (tmpPtr = ovifConf; tmpPtr && strcmp(name, tmpPtr->name) != 0; tmpPtr = tmpPtr->next);
                if (tmpPtr) {
                    LOG(LOG_WARNING, 0, "Config (%s): Reusing old configuration.", tmpPtr->name);
                    tmpPtr->state |= 0x80;   // Flag interface, it must not be freed after reload.
                    if (!tmpPtr->noDefaultFilter) {
                        for (fil = tmpPtr->filters; fil && fil->next != oldcommonConfig.defaultFilters; fil = fil->next);
                        fil ? (fil->next = NULL, filP = &fil->next) : (tmpPtr->filters = NULL, filP = &tmpPtr->filters);
                    }
                    break;
                }
            }
            return NULL;
        }

        if (!nextConfigToken(token))
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
        LOG(LOG_NOTICE, 0, "Config: Setting default query interval to %ds. Default response interval %.1fs",
                            tmpPtr->qry.interval, f);
    }

    if (!tmpPtr->noDefaultFilter)
        *filP = commonConfig.defaultFilters;

    return tmpPtr;
}

/**
*   Configures all multicast vifs and links to interface configuration. This function is responsible for:
*   - All active interfaces have a matching configuration. Either explicit through config file or implicit defaults.
*   - Default filters are created for the interface if necessary.
*   - Establish correct old and new state of interfaces.
*   - Control querier process and do route maintenance on interface transitions.
*   - Add and remove vifs from the kernel if needed.
*/
void configureVifs(void) {
    struct IfDesc    *IfDp = NULL;
    struct vifConfig *confPtr = NULL, *oconfPtr = NULL;
    struct filters   *fil, *ofil;
    uint32_t          vifcount = 0, upsvifcount = 0, downvifcount = 0;

    if (! vifConf)
        LOG(LOG_WARNING, 0, "No valid interfaces configuration. Beware, everything will be default.");
    // Loop through all interfaces and find matching config.
    for (uVifs = 0, IFL(IfDp)) {
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
            strcpy(confPtr->name, IfDp->Name);
            confPtr->next = vifConf;
            vifConf = confPtr;
        }

        // Link the configuration to the interface. And update the states.
        IfDp->conf = confPtr;
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
        if (confPtr->qry.ip == (uint32_t)-1)
            confPtr->qry.ip = IfDp->InAdr.s_addr;
        if (!IS_DOWNSTREAM(IfDp->state))
            confPtr->qry.ver = 3;
        if (confPtr->qry.ver == 1)
            confPtr->qry.interval = 10, confPtr->qry.responseInterval = 10;

        // Check if filters have changed so that ACLs will be reevaluated.
        if (!IfDp->filCh && (CONFRELOAD || SSIGHUP)) {
            for (oconfPtr = ovifConf; oconfPtr && strcmp(IfDp->Name, oconfPtr->name); oconfPtr = oconfPtr->next);
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
