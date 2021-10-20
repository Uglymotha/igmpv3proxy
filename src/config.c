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
static bool              configFile(char *filename, int open);
static char             *nextConfigToken(void);
static void              initCommonConfig();
static struct vifConfig *parsePhyintToken(void);
static void              parseFilters(struct filters ***filP);

// Daemon Configuration.
static struct Config commonConfig, oldcommonConfig;

// All valid configuration options.
static const char *options = "phyint quickleave maxorigins hashtablesize routetables defaultdown defaultup defaultupdown defaultthreshold defaultratelimit defaultquerierver defaultquerierip defaultrobustness defaultqueryinterval defaultqueryrepsonseinterval defaultlastmemberinterval defaultlastmembercount bwcontrol rescanvif rescanconf loglevel logfile proxylocalmc defaultnoquerierelection upstream downstream disabled ratelimit threshold querierver querierip robustness queryinterval queryrepsonseinterval lastmemberinterval lastmembercount noquerierelection defaultfilterany nodefaultfilter filter altnet whitelist reqqueuesize";
static const char *phyintopt = "updownstream upstream downstream disabled ratelimit threshold noquerierelection querierip querierver robustnessvalue queryinterval queryrepsonseinterval lastmemberinterval lastmembercount defaultfilter filter altnet whitelist";

// Configuration file reading.
static FILE           *confFilePtr = NULL;                                      // File handle pointer.
static char           *iBuffer = NULL, cToken[MAX_TOKEN_LENGTH], *token = NULL; // Input buffer, token buffer and token.
static unsigned int    bufPtr, readSize;                                        // Buffer position pointer and nr of bytes in buffer.

// Structures to keep vif configuration and black/whitelists.
static struct vifConfig   *vifConf, *oldvifConf;

// Keeps timer ids for configurable timed functions.
static struct timers {
    uint64_t rescanConf;
    uint64_t rescanVif;
    uint64_t bwControl;
} timers = { 0, 0, 0 };

#define INTTOKEN ((intToken = atoll(nextConfigToken())) || !intToken)

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
    struct filters   *tFil,  *dFil = old ? oldcommonConfig.defaultFilters : commonConfig.defaultFilters;

    // Free vifconf and (default) filters, Alloced by parsePhyintToken() and parseFilters()
    for (cConf = old ? oldvifConf : vifConf; cConf; cConf = tConf) {
        tConf = cConf->next;
        for (; cConf->filters && cConf->filters != dFil; tFil = cConf->filters->next, free(cConf->filters), cConf->filters = tFil);
        free(cConf);
    }
    for (; dFil; tFil = dFil->next, free(dFil), dFil = tFil);

    LOG(LOG_DEBUG, 0, "freeConfig: %s cleared.", (old ? "Old configuration" : "Configuration"));
}

/**
*   Opens or closes config file specified by filename.
*/
static bool configFile(char *filename, int open) {
    // Open config file and allocate memory for inputbuffer. Freed by closeConfigFile()
    if (! open || ! (confFilePtr = fopen(filename, "r")) || ! (iBuffer = malloc(sizeof(char) * READ_BUFFER_SIZE))) {
        if (confFilePtr)
            fclose(confFilePtr);
        if (iBuffer)
            free(iBuffer);   // Alloced by self
        confFilePtr = NULL;
        iBuffer = NULL;
        return open ? false : true;
    }

    // Reset bufferpointer and readsize
    bufPtr = 0;
    readSize = 0;

    return true;
}

/**
*   Returns the next token from the configfile or NULL if there are no more tokens in the file.
*/
static char *nextConfigToken(void) {
    unsigned int   tokenPtr = 0;
    bool           finished = false, oversized = false, commentFound = false;

    // If no file or buffer, return NULL
    if (! confFilePtr || ! iBuffer)
        return NULL;

    // Outer buffer fill loop...
    while (! finished) {
        // If readpointer is at the end of the buffer, we should read next chunk...
        if (bufPtr == readSize) {
            // Fill up the buffer...
            readSize = fread(iBuffer, sizeof(char), READ_BUFFER_SIZE, confFilePtr);
            bufPtr = 0;

            // If the readsize is 0, we should just return...
            if (readSize == 0)
                return NULL;
        }

        // Inner char loop...
        while (bufPtr < readSize && ! finished) {
            // Break loop on \0
            if (iBuffer[bufPtr] == '\0') {
                break;
            } else if (commentFound) {
                if (iBuffer[bufPtr] == '\n') {
                    commentFound = false;
                }
            } else {
                // Check current char...
                switch (iBuffer[bufPtr]) {
                case '#':
                    // Found a comment start...
                    commentFound = true;
                    break;

                case '\n':
                case '\r':
                case '\t':
                case ' ':
                    // Newline, CR, Tab and space are end of token, or ignored.
                    if (tokenPtr > 0) {
                        cToken[tokenPtr] = '\0';    // EOL
                        finished = true;
                    }
                    break;

                default:
                    // Append char to token. When token is oversized do not increase tokenPtr, but keep parsing until whitespace.
                    cToken[tokenPtr] = ! oversized ? iBuffer[bufPtr] : cToken[tokenPtr];
                    tokenPtr = ! oversized ? tokenPtr + 1 : tokenPtr;
                    break;
                }
            }

            // Check end of token buffer !!!
            if (tokenPtr == MAX_TOKEN_LENGTH) {
                // Prevent buffer overrun...
                tokenPtr--;
                oversized = true;
            }
            // Next char...
            bufPtr++;
        }
        // If the readsize is less than buffersize, we assume EOF.
        if (readSize < READ_BUFFER_SIZE && bufPtr == readSize) {
            if (tokenPtr > 0)
                finished = true;
            else
                return NULL;
        }
    }
    if (tokenPtr > 0) {
        cToken[tokenPtr] = '\0';  // Make sure token is null terminated string.
        return cToken;
    }

    return NULL;
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
    commonConfig.downstreamHostsHashTableSize = DEFAULT_HASHTABLE_SIZE;

    // Number of (hashed) route tables.
    commonConfig.routeTables = STARTUP ? DEFAULT_ROUTE_TABLES : oldcommonConfig.routeTables;

    // Default interface state and parameters.
    commonConfig.defaultInterfaceState = IF_STATE_DISABLED;
    commonConfig.defaultThreshold = DEFAULT_THRESHOLD;
    commonConfig.defaultRatelimit = DEFAULT_RATELIMIT;
    commonConfig.defaultFilterAny = false;
    commonConfig.defaultFilters   = NULL;

    // Log to file disabled by default.
    commonConfig.log2File = false;
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

/**
*   Reloads the configuration file and removes interfaces which were removed from config.
*/
void reloadConfig(uint64_t *tid) {
    // Check and set sigstatus to what we are actually doing right now.
    if (NOSIG)
        sigstatus = GOT_CONFREL;
    oldvifConf      = vifConf;
    vifConf         = NULL;
    oldcommonConfig = commonConfig;

    // Load the new configuration keep reference to the old.
    if (!loadConfig()) {
        LOG(LOG_WARNING, 0, "reloadConfig: Unable to load config file, keeping current.");
        commonConfig = oldcommonConfig;
        if (vifConf)
            freeConfig(0);
        vifConf = oldvifConf;
    } else {
        // Rebuild the interfaces config, then free the old configuration.
        rebuildIfVc(NULL);
        freeConfig(1);

        LOG(LOG_DEBUG, 0, "reloadConfig: Config Reloaded. OldConfPtr: %x, NewConfPtr, %x", oldvifConf, vifConf);
    }
    if (sigstatus == GOT_CONFREL && commonConfig.rescanConf)
        *tid = timer_setTimer(TDELAY(commonConfig.rescanConf * 10), "Reload Configuration", (timer_f)reloadConfig, tid);

    sigstatus = 0;
}

/**
*   Loads the configuration from file, and stores the config in respective holders.
*/
bool loadConfig(void) {
    struct  vifConfig *tmpPtr, **currPtr = &vifConf;
    int64_t            intToken;

    // Initialize common config
    initCommonConfig();

    // Open config file and read first token.
    if (! configFile(commonConfig.configFilePath, 1) || ! (token = nextConfigToken()))
        return false;
    LOG(LOG_DEBUG, 0, "Loading config from '%s'", commonConfig.configFilePath);

    // Set pointer to pointer to filters list.
    struct filters **filP = &commonConfig.defaultFilters;

    // Loop until all configuration is read.
    while (token) {
        if (strcasecmp("phyint", token) == 0) {
            // Got a phyint token... Call phyint parser
            tmpPtr = parsePhyintToken();
            if (tmpPtr) {
                LOG(LOG_NOTICE, 0, "Config: IF name : %s", tmpPtr->name);
                LOG(LOG_NOTICE, 0, "Config: IF Ratelimit : %d", tmpPtr->ratelimit);
                LOG(LOG_NOTICE, 0, "Config: IF Threshold : %d", tmpPtr->threshold);
                LOG(LOG_NOTICE, 0, "Config: IF State : %d", tmpPtr->state);
                LOG(LOG_NOTICE, 0, "Config: IF Ptrs : %p: %p", tmpPtr, tmpPtr->filters);

                // Insert config, and move temppointer to next location...
                *currPtr = tmpPtr;
                currPtr = &tmpPtr->next;
                continue;
            } else if (!STARTUP)
                return false;

        } else if (strcasecmp("reqqueuesize", token) == 0 && INTTOKEN) {
            // Got a reqqueuesize token....
            commonConfig.reqQsz = intToken > 0 && intToken < 65535 ? intToken : REQQSZ;
            LOG(LOG_NOTICE, 0, "Config: Setting request queue size to %d.", intToken);

        } else if (strcasecmp("timerqueuesize", token) == 0 && INTTOKEN) {
            // Got a reqqueuesize token....
            commonConfig.tmQsz = intToken > 0 && intToken < 65535 ? intToken : REQQSZ;
            LOG(LOG_NOTICE, 0, "Config: Setting timer queue size to %d.", intToken);

        } else if (strcasecmp("quickleave", token) == 0) {
            // Got a quickleave token....
            LOG(LOG_NOTICE, 0, "Config: Quick leave mode enabled.");
            commonConfig.fastUpstreamLeave = true;

        } else if (strcasecmp("maxorigins", token) == 0 && INTTOKEN) {
            // Got a maxorigins token...
            commonConfig.maxOrigins = intToken < DEFAULT_MAX_ORIGINS || intToken > 65535 ? DEFAULT_MAX_ORIGINS : intToken;
            LOG(LOG_NOTICE, 0, "Config: Setting max multicast group sources to %d.", commonConfig.maxOrigins);

        } else if (strcasecmp("hashtablesize", token) == 0 && INTTOKEN) {
            // Got a hashtablesize token...
            if (! commonConfig.fastUpstreamLeave)
                LOG(LOG_WARNING, 0, "Config: hashtablesize is specified but quickleave not enabled. Ignoring.");
            else if (intToken < 8 || intToken > 131072)
                LOG(LOG_WARNING, 0, "Config: hashtablesize must be 8 to 131072 bytes (multiples of 8), using default %d.",
                                     commonConfig.downstreamHostsHashTableSize);
            else {
                commonConfig.downstreamHostsHashTableSize = (intToken - intToken % 8) * 8;
                LOG(LOG_NOTICE, 0, "Config: Hash table size for quickleave is %d.", commonConfig.downstreamHostsHashTableSize / 8);
            }

        } else if (strcasecmp("routetables", token) == 0 && INTTOKEN) {
            // Got a routetables token...
            if (STARTUP) {
                commonConfig.routeTables = intToken < 1 || intToken > 65536 ? DEFAULT_ROUTE_TABLES : intToken;
                LOG(LOG_NOTICE, 0, "Config: %d route table hash entries.", commonConfig.routeTables);
            }

        } else if (strcasecmp("defaultupdown", token) == 0) {
            // Got a defaultupdown token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_UPDOWNSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to updownstream.");
            }

        } else if (strcasecmp("defaultup", token) == 0) {
            // Got a defaultup token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_UPSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to upstream.");
            }

        } else if (strcasecmp("defaultdown", token) == 0) {
            // Got a defaultdown token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED)
                LOG(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_DOWNSTREAM;
                LOG(LOG_NOTICE, 0, "Config: Interfaces default to downstream.");
            }

        } else if (strcasecmp("defaultfilterany", token) == 0) {
            // Got a defaultfilterany token...
            if (commonConfig.defaultFilters)
                LOG(LOG_WARNING, 0, "Config: Default filters cannot be combined with defaultfilterany.");
            else {
                commonConfig.defaultFilterAny = true;
                LOG(LOG_NOTICE, 0, "Config: Interface default filter any.");
            }

        } else if (strcasecmp("defaultfilter", token) == 0) {
            // Got a defaultfilterany token...
            if (commonConfig.defaultFilterAny)
                LOG(LOG_WARNING, 0, "Config: Defaultfilterany cannot be combined with default filters.");
            else {
                LOG(LOG_NOTICE, 0, "Config: Parsing default filters.");
                strcpy(token, "filter");
                parseFilters(&filP);
            }

        } else if (strcasecmp("defaultratelimit", token) == 0 && INTTOKEN) {
            // Default Ratelimit
            if (intToken < 0) LOG(LOG_WARNING, 0, "Config: Ratelimit must be more than 0.");
            else {
                commonConfig.defaultRatelimit = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default ratelimit %d.", intToken);
            }

        } else if (strcasecmp("defaultthreshold", token) == 0 && INTTOKEN) {
            // Default Threshold
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Threshold must be between 1 and 255.");
            else {
                commonConfig.defaultThreshold = intToken;
                LOG(LOG_NOTICE, 0, "Config: Default threshold %d.", intToken);
            }

        } else if (strcasecmp("defaultquerierip", token) == 0 && (token = nextConfigToken())) {
            // Got a querierip token.
            commonConfig.querierIp = inet_addr(token);
            LOG(LOG_NOTICE, 0, "Config: Setting default querier ip address to %s.", inetFmt(commonConfig.querierIp, 1));

        } else if (strcasecmp("defaultquerierver", token) == 0 && INTTOKEN) {
            // Got a querierver token.
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config: Querier version %d invalid.", intToken);
            else {
                commonConfig.querierVer = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default querier version to %d.", intToken);
            }

        } else if (strcasecmp("defaultrobustness", token) == 0 && INTTOKEN) {
            // Got a robustnessvalue token...
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config IF: Robustness value must be between 1 and 7.");
            else {
                commonConfig.robustnessValue = intToken;
                commonConfig.lastMemberQueryCount = commonConfig.lastMemberQueryCount != DEFAULT_ROBUSTNESS
                                                  ? commonConfig.lastMemberQueryCount : commonConfig.robustnessValue;
                LOG(LOG_NOTICE, 0, "Config: Setting default robustness value to %d.", intToken);
            }

        } else if (strcasecmp("defaultqueryinterval", token) == 0 && INTTOKEN) {
            // Got a queryinterval token...
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Query interval must be between 1 and 255.");
            else {
                commonConfig.queryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default query interval to %ds.", commonConfig.queryInterval);
            }

        } else if (strcasecmp("defaultqueryrepsonseinterval", token) == 0 && INTTOKEN) {
            // Got a queryresponsenterval token...
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Query response interval must be between 1 and 255.");
            else {
                commonConfig.queryResponseInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default query response interval to %d.", intToken);
            }

        } else if (strcasecmp("defaultlastmemberinterval", token) == 0 && INTTOKEN) {
            // Got a lastmemberinterval token...
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config: Last member query interval must be between 1 and 255.");
            else {
                commonConfig.lastMemberQueryInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting default last member query interval to %d.", intToken);
            }

        } else if (strcasecmp("defaultlastmembercount", token) == 0 && INTTOKEN) {
            // Got a lastmembercount token...
            commonConfig.lastMemberQueryCount = intToken < 1 || intToken > 7 ? DEFAULT_ROBUSTNESS : intToken;
            LOG(LOG_NOTICE, 0, "Config: Setting default last member query count to %d.", intToken);

        } else if (strcasecmp("bwcontrol", token) == 0 && INTTOKEN) {
            // Got a bcontrolinterval token...
            commonConfig.bwControlInterval = intToken < 3 ? 3 : intToken;
            LOG(LOG_NOTICE, 0, "Config: Setting bandwidth control interval to %ds.", intToken);

        } else if (strcasecmp("rescanvif", token) == 0 && INTTOKEN) {
            // Got a rescanvif token...
            commonConfig.rescanVif = intToken > 0 ? intToken : 0;
            LOG(LOG_NOTICE, 0, "Config: Need detect new interface every %ds.", intToken);

        } else if (strcasecmp("rescanconf", token) == 0 && INTTOKEN) {
            // Got a rescanconf token...
            commonConfig.rescanConf = intToken > 0 ? intToken : 0;
            LOG(LOG_NOTICE, 0, "Config: Need detect config change every %ds.", intToken);

        } else if (strcasecmp("loglevel", token) == 0 && INTTOKEN) {
            // Got a loglevel token...
            if (!commonConfig.log2Stderr) {
                commonConfig.logLevel = intToken > 7 ? 7 : intToken < 0 ? 0 : intToken;
                LOG(LOG_NOTICE, 0, "Config: Log Level %d", intToken);
            }

        } else if (strcasecmp("logfile", token) == 0 && (token = nextConfigToken())) {
            // Got a logfile token. Only use log file if not logging to stderr.
            if (!commonConfig.log2Stderr) {
                // Freed by igmpProxyCleanUp()
                commonConfig.logFilePath = ! commonConfig.logFilePath ? malloc(MAX_TOKEN_LENGTH) : commonConfig.logFilePath;
                if (strstr(options, token)) {
                    LOG(LOG_WARNING, 0, "Config: No logfile path specified. Ignoring.");
                    continue;
                }
                FILE *fp = fopen(token, "a");
                if (! fp) {
                    LOG(LOG_WARNING, errno, "Config: Cannot open log file %s.", token);
                    commonConfig.logFilePath = "";
                } else {
                    fclose(fp);
                    strcpy(commonConfig.logFilePath, token);
                    LOG(LOG_NOTICE, 0, "Config: Log File: %s", commonConfig.logFilePath);
                    time_t rawtime = time(NULL);
                    utcoff.tv_sec = timegm(localtime(&rawtime)) - rawtime;
                    commonConfig.log2File = true;
                }
            }

        } else if (strcasecmp("proxylocalmc", token) == 0) {
            // Got a proxylocalmc token....
            commonConfig.proxyLocalMc = true;
            LOG(LOG_NOTICE, 0, "Config: Will proxy local multicast range 224.0.0.0/8.");

        } else if (strcasecmp("defaultnoquerierelection", token) == 0) {
            // Got a noquerierelection token....
            commonConfig.querierElection = false;
            LOG(LOG_NOTICE, 0, "Config: Will not participate in IGMP querier election by default.");

        } else if (strcasecmp("cligroup", token) == 0 && (token = nextConfigToken())) {
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
            for (token = nextConfigToken(); !strstr(options, token); token = nextConfigToken());
            continue;

        } else {
            // Unparsable token.
            LOG(LOG_WARNING, 0, "Config: Unknown token '%s' in config file", token);
            if (!STARTUP)
                return false;
        }

        token = nextConfigToken();
    }

    // Close the configfile.
    configFile(NULL, 0);

    // Create default filter any.
    if (commonConfig.defaultFilterAny) {
        if (! (commonConfig.defaultFilters = malloc(sizeof(struct filters))))
            LOG(LOG_ERR, errno, "loadConfig: Out of Memory.");
        *commonConfig.defaultFilters = FILTERANY;
    }

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
            clearRoutes(getConfig);
#endif
        if (commonConfig.bwControlInterval)
            timers.bwControl = timer_setTimer(TDELAY(commonConfig.bwControlInterval * 10), "Bandwidth Control",
                                              (timer_f)bwControl, &timers.bwControl);
    }

    // Set hashtable size to 0 when quickleave is disabled.
    if (!commonConfig.fastUpstreamLeave)
        commonConfig.downstreamHostsHashTableSize = 0;

    // Check if quickleave was enabled or disabled due to config change.
    if (!STARTUP && oldcommonConfig.fastUpstreamLeave != commonConfig.fastUpstreamLeave) {
        LOG(LOG_NOTICE, 0, "Config: Quickleave mode was %s, reinitializing routes.",
                            commonConfig.fastUpstreamLeave ? "disabled" : "enabled");
        clearRoutes(CONFIG);
    }

    // Check if hashtable size was changed due to config change.
    if (!STARTUP && commonConfig.fastUpstreamLeave
                 && oldcommonConfig.downstreamHostsHashTableSize != commonConfig.downstreamHostsHashTableSize) {
        LOG(LOG_NOTICE, 0, "Config: Downstream host hashtable size changed from %i to %i, reinitializing routes.",
                            oldcommonConfig.downstreamHostsHashTableSize, commonConfig.downstreamHostsHashTableSize);
        clearRoutes(CONFIG);
    }

    return true;
}


/*
*   Parsing of filters. If an error is made in a list, the whole list will be ignored.
*/
static void parseFilters(struct filters ***filP) {
    char list[MAX_TOKEN_LENGTH], *filteropt = "allow block ratelimit up down updown both";
    uint32_t addr, mask;
    struct filters fil    = { {0xFFFFFFFF, 0xFFFFFFFF}, {0xFFFFFFFF, 0xFFFFFFFF}, (uint64_t)-1, (uint8_t)-1, NULL },
                   filErr = { {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, (uint8_t)-1, NULL };

    for (strcpy(list, token), token = nextConfigToken(); token && (strstr(filteropt, token) || ! strstr(options, token));
                              token = nextConfigToken()) {
        if (strcasecmp("filter", list) == 0 && fil.dst.ip != 0xFFFFFFFF && fil.action == (uint64_t)-1) {
            if (fil.dir == (uint8_t)-1) {
                if (strcasecmp("up", token) == 0)
                    fil.dir = 1;
                else if (strcasecmp("down", token) == 0)
                    fil.dir = 2;
                else if (strcasecmp("updown", token) == 0 || strcasecmp("both", token) == 0)
                    fil.dir = 3;
            }
            if (strcasecmp("ratelimit", token) == 0 || strcasecmp("r", token) == 0 || strcasecmp("2", token) == 0) {
                token = nextConfigToken();
                uint64_t rl = atol(token);
                if (! commonConfig.bwControlInterval)
                    LOG(LOG_INFO, 0, "Config: IF: BW Control disabled, ignoring ratelimit rule %s - %s %lld.",
                                      inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), rl);
                else if (fil.src.ip != 0 && fil.src.ip != 0xFFFFFFFF)
                    LOG(LOG_WARNING, 0, "Config: IF: Ratelimit rules must have INADDR_ANY as source. Ignoring %s - %s %lld.",
                                         inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), rl);
                else
                    fil.action = rl >= 2 ? rl : 2;
            } else if (strcasecmp("allow", token) == 0 || strcasecmp("a", token) == 0 || strcasecmp("1", token) == 0)
                fil.action = ALLOW;
            else if (strcasecmp("block", token) == 0 || strcasecmp("b", token) == 0 || strcasecmp("0", token) == 0)
                fil.action = BLOCK;
            else if (!strstr(filteropt, token)) {
                LOG(LOG_WARNING, 0, "Config: IF: %s is not a valid filter action or direction. Ignoring %s.", token, list);
                fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, (uint8_t)-1, NULL };
            }
        } else if (!parseSubnetAddress(token, &addr, &mask)) {
            // Unknown token. Ignore...
            LOG(LOG_WARNING, 0, "Config: IF: Uparsable subnet '%s'. Ignoring %s.", token, list);
            fil = filErr;
        } else if ((strcasecmp("whitelist", list) == 0 || (strcasecmp("filter", list) == 0 && fil.src.ip != 0xFFFFFFFF))
                   && !IN_MULTICAST(ntohl(addr))) {
            // Check if valid MC group for whitelist are filter dst.
            LOG(LOG_WARNING, 0, "Config: IF: %s is not a valid multicast address. Ignoring %s.", inetFmt(addr, 1), list);
            fil = filErr;
        } else if ((addr | mask) != mask) {
            // Check if valid sn/mask pair.
            LOG(LOG_WARNING, 0, "Config: IF: %s is not valid subnet/mask pair. Ignoring %s.", inetFmts(addr, mask, 1), list);
            fil = filErr;
        } else if (strcasecmp("altnet", list) == 0) {
            // altnet is not usefull or compatible with igmpv3, ignore.
            fil = filErr;
        } else if (strcasecmp("whitelist", list) == 0) {
            fil = (struct filters){ {INADDR_ANY, 0}, {addr, mask}, ALLOW, (uint8_t)-1, NULL };
        } else if (fil.src.ip == 0xFFFFFFFF) {
            if (! IN_MULTICAST(ntohl(addr))) {
                fil.src.ip   = addr;
                fil.src.mask = mask;
            } else {
                fil.dst.ip   = addr;
                fil.dst.mask = mask;
            }
        } else if (fil.dst.ip == 0xFFFFFFFF) {
            fil.dst.ip   = addr;
            fil.dst.mask = mask;
        }

        if (fil.src.ip == 0xFFFFFFFF && fil.src.mask == 0) {
            // Error in list detected, go to next.
            for (token = nextConfigToken(); token && ! strstr(options, token); token = nextConfigToken());
            break;
        } else if (   (fil.src.ip != 0xFFFFFFFF || (fil.src.ip == 0xFFFFFFFF && fil.action > ALLOW))
                   &&  fil.dst.ip != 0xFFFFFFFF && ! (fil.action == (uint64_t)-1)) {
            // Correct filter, add and reset fil to process next entry.
            if (fil.dir == (uint8_t)-1)
                fil.dir = 3;
            if (fil.src.ip == 0xFFFFFFFF)
                fil.src.ip = fil.src.mask = 0;
            LOG(LOG_NOTICE, 0, "Config: IF: Adding filter Src: %s Dst: %s Dir: %s Action: %lld.",
                                inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2),
                                fil.dir == 1 ? "up" : fil.dir == 2 ? "down" : "updown", fil.action);
            // Allocate memory for filter and copy from argument.
            if (! (**filP = malloc(sizeof(struct filters))))
                LOG(LOG_ERR, errno, "allocSubnet: Out of Memory.");  // Freed by freeConfig()
            ***filP = fil;

            *filP = &(***filP).next;
            fil = (struct filters){ {0xFFFFFFFF, 0xFFFFFFFF}, {0xFFFFFFFF, 0xFFFFFFFF}, (uint64_t)-1, (uint8_t)-1, NULL };
        }
    }
}

/**
*   Internal function to parse phyint config.
*/
static struct vifConfig *parsePhyintToken(void) {
    struct vifConfig *tmpPtr;
    int64_t           intToken;

    // First token should be the interface name....
    if (! (token = nextConfigToken())) {
        LOG(LOG_WARNING, 0, "Config: IF: You should at least name your interfeces.");
        return NULL;
    }
    LOG(LOG_NOTICE, 0, "Config: IF: Config for interface %s.", token);

    // Allocate and initialize memory for new configuration.
    if (! (tmpPtr = malloc(sizeof(struct vifConfig))))
        LOG(LOG_ERR, errno, "parsePhyintToken: Out of memory.");  // Freed by freeConfig()
    *tmpPtr = DEFAULT_VIFCONF;

    // Make a copy of the token to store the IF name. Make sure it is NULL terminated.
    memcpy(tmpPtr->name, token, IF_NAMESIZE);
    tmpPtr->name[IF_NAMESIZE - 1] = '\0';
    if (strlen(token) >= IF_NAMESIZE)
        LOG(LOG_WARNING, 0, "Config: IF: Interface name %s larger than system IF_NAMESIZE(%d), truncated to %s."
                             ,token, IF_NAMESIZE, tmpPtr->name);

    // Set pointer to pointer to filters list.
    struct filters **filP = &tmpPtr->filters;

    // Parse the rest of the config..
    token = nextConfigToken();
    while (token) {
        if (strcasecmp("filter", token) == 0 || strcasecmp("altnet", token) == 0 || strcasecmp("whitelist", token) == 0) {
            LOG(LOG_NOTICE, 0, "Config: IF: Parsing %s.", token);
            parseFilters(&filP);
            continue;

        } else if (strcasecmp("nodefaultfilter", token) == 0) {
            tmpPtr->nodefaultfilter = true;
            LOG(LOG_NOTICE, 0, "Config: IF: Not setting default filters.");

        } else if (strcasecmp("updownstream", token) == 0) {
            tmpPtr->state = IF_STATE_UPDOWNSTREAM;
            LOG(LOG_NOTICE, 0, "Config: IF: Updownstream.");

        } else if (strcasecmp("upstream", token) == 0) {
            tmpPtr->state = IF_STATE_UPSTREAM;
            LOG(LOG_NOTICE, 0, "Config: IF: Upstream.");

        } else if (strcasecmp("downstream", token) == 0) {
            tmpPtr->state = IF_STATE_DOWNSTREAM;
            LOG(LOG_NOTICE, 0, "Config: IF: Downstream.");

        } else if (strcasecmp("disabled", token) == 0) {
            tmpPtr->state = IF_STATE_DISABLED;
            LOG(LOG_NOTICE, 0, "Config: IF: Disabled.");

        } else if (strcasecmp("ratelimit", token) == 0 && INTTOKEN) {
            if (intToken < 0)
                LOG(LOG_WARNING, 0, "Config: IF: Ratelimit must 0 or more.");
            else {
                tmpPtr->ratelimit = intToken;
                LOG(LOG_NOTICE, 0, "Config: IF: Setting ratelimit to %lld.", intToken);
            }

        } else if (strcasecmp("threshold", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config IF: Threshold must be between 1 and 255.");
            else {
                tmpPtr->threshold = intToken;
                LOG(LOG_NOTICE, 0, "Config: IF: Setting threshold to %d.", intToken);
            }

        } else if (strcasecmp("querierip", token) == 0 && (token = nextConfigToken())) {
            tmpPtr->qry.ip = inet_addr(token);
            LOG(LOG_NOTICE, 0, "Config IF: Setting querier ip address to %s.", inetFmt(tmpPtr->qry.ip, 1));

        } else if (strcasecmp("querierver", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 3)
                LOG(LOG_WARNING, 0, "Config IF: IGMP version %d not valid.", intToken);
            else {
                tmpPtr->qry.ver = intToken;
                LOG(LOG_NOTICE, 0, "Config IF: Setting querier version %d.", intToken);
            }

        } else if (strcasecmp("noquerierelection", token) == 0) {
            tmpPtr->qry.election = false;
            LOG(LOG_NOTICE, 0, "Config IF: Will not participate in IGMP querier election.");

        } else if (strcasecmp("robustness", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 7)
                LOG(LOG_WARNING, 0, "Config IF: Robustness value mus be between 1 and 7.");
            else {
                tmpPtr->qry.robustness = intToken;
                LOG(LOG_NOTICE, 0, "Config: IF: Settings robustness to %d.", intToken);
            }

        } else if (strcasecmp("queryinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config IF: Query interval value should be between 1 than 255.");
            else {
                tmpPtr->qry.interval = intToken;
                LOG(LOG_NOTICE, 0, "Config: IF: Setting query interval to %d.", intToken);
            }

        } else if (strcasecmp("queryresponseinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config IF: Query response interval value should be between 1 than 255.");
            else {
                tmpPtr->qry.responseInterval = intToken;
                LOG(LOG_NOTICE, 0, "Config: IF: Setting query response interval to %d.", intToken);
            }

        } else if (strcasecmp("lastmemberinterval", token) == 0 && INTTOKEN) {
            if (intToken < 1 || intToken > 255)
                LOG(LOG_WARNING, 0, "Config IF: Last member interval value should be between 1 than 255.");
            else {
                tmpPtr->qry.lmInterval =  intToken;
                LOG(LOG_NOTICE, 0, "Config: Setting last member query interval to %d.", intToken);
            }

        } else if (strcasecmp("lastmembercount", token) == 0 && INTTOKEN) {
            tmpPtr->qry.lmCount = intToken < 1 || intToken > 7 ? DEFAULT_ROBUSTNESS : intToken;
            tmpPtr->qry.lmCount = intToken;
            LOG(LOG_NOTICE, 0, "Config: IF: Setting last member query count to %d.", tmpPtr->qry.lmCount);

        } else if (! strstr(options, token)) {
            // Unknown token.
            LOG(LOG_WARNING, 0, "Config: IF; Unknown token '%s' in configfile.", token);
            if (!STARTUP) return NULL;

        } else
            break;   // Send pointer and return to main config parser.

        token = nextConfigToken();
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
    struct vifConfig *confPtr = NULL;
    register int      vifcount = 0, upsvifcount = 0, downvifcount = 0;

    if (! vifConf)
        LOG(LOG_WARNING, 0, "No valid interfaces configuration. Beware, everything will be default.");
    // Loop through all interfaces and find matching config.
    for (GETIFL(IfDp)) {
        if (CONFRELOAD)
            IfDp->oldconf = IfDp->conf;
        for (confPtr = vifConf; confPtr && strcmp(IfDp->Name, confPtr->name) != 0; confPtr = confPtr->next);
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
        if (! IfDp->oldconf) {
            // If no old config at this point it is because buildIfVc detected new or removed interface.
            IfDp->oldconf = confPtr;
            if (!(IfDp->state & 0x80)) {
                // Removed interface, oldstate is current state, newstate is disabled, flagged for removal.
                IfDp->oldconf->state = IfDp->state;
                IfDp->state          = IF_STATE_DISABLED | 0x80;
            } else {
                // New interface, oldstate is disabled, newstate is configured state.
                IfDp->state          = IfDp->mtu && IfDp->Flags & IFF_MULTICAST ? IfDp->conf->state : IF_STATE_DISABLED;
                IfDp->oldconf->state = IF_STATE_DISABLED;
            }
        } else {
            // Existing interface, oldstate is current state, newstate is configured state.
            IfDp->oldconf->state = IfDp->state;
            IfDp->state          = IfDp->mtu && IfDp->Flags & IFF_MULTICAST ? IfDp->conf->state : IF_STATE_DISABLED;
        }
        register uint8_t oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);

        // Set configured querier ip to interface address if not configured
        // and set version to 3 for disabled/upstream only interface.
        if (confPtr->qry.ip == (uint32_t)-1)
            confPtr->qry.ip = IfDp->InAdr.s_addr;
        if (!IS_DOWNSTREAM(IfDp->state))
            confPtr->qry.ver = 3;
        if (confPtr->qry.ver == 1)
            confPtr->qry.interval = 10, confPtr->qry.responseInterval = 10;

        // Link default filters for interface when reloading config,
        // or when new interface is detected and no configuration reload has yet occured.
        if (!IfDp->conf->defaultfilter && !confPtr->nodefaultfilter) {
            struct filters *fil;
            for (fil = IfDp->conf->filters; fil && fil->next; fil = fil->next);
            if (! fil)
                IfDp->conf->filters = commonConfig.defaultFilters;
            else
                fil->next = commonConfig.defaultFilters;
            IfDp->conf->defaultfilter = true;
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
            if (IS_UPSTREAM(newstate))
                upsvifcount++;
        }

        // Do maintenance on vifs according to their old and new state.
        if      ( IS_DISABLED(oldstate)   && IS_UPSTREAM(newstate)  )    { ctrlQuerier(1, IfDp); clearRoutes(IfDp); }
        else if ( IS_DISABLED(oldstate)   && IS_DOWNSTREAM(newstate))    { ctrlQuerier(1, IfDp);                    }
        else if (!IS_DISABLED(oldstate)   && IS_DISABLED(newstate)  )    { ctrlQuerier(0, IfDp); clearRoutes(IfDp); }
        else if ( oldstate != newstate)                                  { ctrlQuerier(2, IfDp); clearRoutes(IfDp); }
        else if ( oldstate == newstate    && !IS_DISABLED(newstate) )    {                       clearRoutes(IfDp); }

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

    // All vifs created / updated, check if there is an upstream and at least one downstream on rebuild interface.
    if (!SHUTDOWN && (vifcount < 2 || upsvifcount == 0 || downvifcount == 0))
        LOG((STARTUP ? LOG_ERR : LOG_WARNING), 0, "There must be at least 2 interfaces, 1 Vif as upstream and 1 as dowstream.");
}
