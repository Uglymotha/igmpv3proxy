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
*   Generic config file reader. Used to open a config file, and read the tokens from it. The parser is really simple nd does no backlogging.
*   This means that no form of text escaping and qouting is currently supported. '#' chars are read as comments, and the comment lasts until a newline or EOF.
*   text escaping and qouting is currently supported.
*/

#include "igmpproxy.h"

// Local Prototypes.
static bool              configFile(char *filename, int open);
static char             *nextConfigToken(void);
static void              initCommonConfig();
static struct vifConfig *parsePhyintToken(void);
static bool              parseSubnetAddress(char *addrstr, uint32_t *addr, uint32_t *mask);
static void              allocFilter(struct filters fil);

// Daemon Configuration.
static struct Config commonConfig, oldcommonConfig;

// All valid configuration options.
static const char *options = "phyint quickleave maxorigins hashtablesize defaultdown defaultup defaultupdown defaultthreshold defaultratelimit querierip robustnessvalue queryinterval queryrepsonseinterval lastmemberinterval lastmembercount bwcontrol rescanvif rescanconf loglevel logfile proxylocalmc noquerierelection upstream downstream disabled ratelimit threshold defaultfilterany nodefaultfilter filter altnet whitelist";
static const char *phyintopt = "updownstream upstream downstream disabled ratelimit threshold noquerierelection querierip robustnessvalue queryinterval queryrepsonseinterval lastmemberinterval lastmembercount defaultfilter filter altnet whitelist";

// Configuration file reading.
static FILE           *confFilePtr = NULL;                                      // File handle pointer.
static char           *iBuffer = NULL, cToken[MAX_TOKEN_LENGTH], *token = NULL; // Input buffer, token buffer and token.
static unsigned int    bufPtr, readSize;                                        // Buffer position pointer and nr of bytes in buffer.

// Structures to keep vif configuration and black/whitelists.
static struct vifConfig   *vifConf, *oldvifConf;
static struct filters    **filPtr;

// Keeps timer ids for configurable timed functions.
static struct timers {
    uint64_t rescanConf;
    uint64_t rescanVif;
    uint64_t bwControl;
} timers = { 0, 0, 0 };

/**
*   Returns pointer to the configuration.
*/
struct Config *getConfig(void) {
    return &commonConfig;
}

/**
*   Frees the old vifconf list and associated filters.
*/
void freeConfig(int old) {
    struct vifConfig *tmpConfPtr, *clrConfPtr;

    for (clrConfPtr = old ? oldvifConf : vifConf; clrConfPtr; clrConfPtr = tmpConfPtr) {
        tmpConfPtr = clrConfPtr->next;
        struct filters *tmpFilPtr;
        for (; clrConfPtr->filters; clrConfPtr->filters = tmpFilPtr) {
            tmpFilPtr = clrConfPtr->filters->next;
            free(clrConfPtr->filters);  // Alloced by allocFilter()
        }
        free(clrConfPtr);   // Alloced by parsePhyintToken()
    }

    myLog(LOG_DEBUG, 0, "freeConfig: %s cleared.", (old ? "Old configuration" : "Configuration"));
}

/**
*   Opens or closes config file specified by filename.
*/
static bool configFile(char *filename, int open) {
    // Open config file and allocate memory for inputbuffer. Freed by closeConfigFile()
    if (! open || ! (confFilePtr = fopen(filename, "r")) || ! (iBuffer = (char*)malloc(sizeof(char) * READ_BUFFER_SIZE))) {
        fclose(confFilePtr);
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
    if (! confFilePtr || ! iBuffer) return NULL;

    // Outer buffer fill loop...
    while (! finished) {
        // If readpointer is at the end of the buffer, we should read next chunk...
        if (bufPtr == readSize) {
            // Fill up the buffer...
            readSize = fread(iBuffer, sizeof(char), READ_BUFFER_SIZE, confFilePtr);
            bufPtr = 0;

            // If the readsize is 0, we should just return...
            if (readSize == 0) return NULL;
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
            if (tokenPtr > 0) {
                finished = true;
            } else {
                return NULL;
            }
        }
    }
    if (tokenPtr > 0) {
        cToken[tokenPtr] = '\0';  // Make sure token is null terminated string.
        return cToken;
    }

    return NULL;
}

/**
   Allocate and set the subnetlist for the requested list.
*/
static void allocFilter(struct filters fil) {
    struct filters ***tmpFil = &filPtr;

    // Allocate memory for filter and copy from argument.
    if (! (**tmpFil = (struct filters*)malloc(sizeof(struct filters)))) myLog(LOG_ERR, errno, "allocSubnet: Out of Memory.");  // Freed by freeConfig() or parsePhyIntToken()
    ***tmpFil = fil;

    *tmpFil = &(***tmpFil).next;
}

/**
*   Parses a subnet address string on the format a.b.c.d/n into a subnet addr and mask.
*/
static bool parseSubnetAddress(char *addrstr, uint32_t *addr, uint32_t *mask) {
    // First get the network part of the address...
    char *tmpStr = strtok(addrstr, "/");
    *addr = inet_addr(tmpStr);
    if (*addr == (uint32_t)-1) return false;

    // Next parse the subnet mask.
    tmpStr = strtok(NULL, "/");
    if (tmpStr) {
        int bitcnt = atoi(tmpStr);
        if (bitcnt < 0 || bitcnt > 32) return false;
        else *mask = bitcnt == 0 ? 0 : ntohl(0xFFFFFFFF << (32 - bitcnt));
    } else return false;

    return true;
}

/**
*   Initializes default configuration.
*/
static void initCommonConfig(void) {
    commonConfig.robustnessValue = DEFAULT_ROBUSTNESS;
    commonConfig.queryInterval = DEFAULT_INTERVAL_QUERY;
    commonConfig.queryResponseInterval = DEFAULT_INTERVAL_QUERY_RESPONSE;
    commonConfig.bwControlInterval = 0;

    // The defaults are calculated from other settings.
    commonConfig.startupQueryInterval = STARTUP ? (unsigned int)(DEFAULT_INTERVAL_QUERY / 4) : commonConfig.startupQueryInterval;

    // Default values for leave intervals...
    commonConfig.lastMemberQueryInterval = DEFAULT_INTERVAL_QUERY_RESPONSE / 10;
    commonConfig.lastMemberQueryCount    = DEFAULT_ROBUSTNESS;

    // If 1, a leave message is sent upstream on leave messages from downstream.
    commonConfig.fastUpstreamLeave = false;

    // Defaul maximum nr of sources for route. Always a minimum of 4 sources is allowed
    // This is controlable by the maxorigins config parameter.
    // Only applicable when BW control is not enabled, in which case sources will be aged if no data is received.
    commonConfig.maxOrigins = DEFAULT_MAX_ORIGINS;

    // Default size of hash table is 32 bytes (= 256 bits) and can store
    // up to the 256 non-collision hosts, approximately half of /24 subnet
    commonConfig.downstreamHostsHashTableSize = DEFAULT_HASHTABLE_SIZE;

    // Default interface state and parameters.
    commonConfig.defaultInterfaceState = IF_STATE_DISABLED;
    commonConfig.defaultThreshold = DEFAULT_THRESHOLD;
    commonConfig.defaultRatelimit = DEFAULT_RATELIMIT;
    commonConfig.defaultFilterAny = false;
    commonConfig.nodefaultFilter  = false;

    // Log to file disabled by default.
    commonConfig.logFile = false;

    // Default no timed rebuild interfaces / reload config.
    commonConfig.rescanVif  = 0;
    commonConfig.rescanConf = 0;

    // Do not proxy local mc by default.
    commonConfig.proxyLocalMc = false;

    // Participate in querier election by default.
    commonConfig.querierElection = true;

    // Default no group for socket (use root's).
    commonConfig.socketGroup = *getgrgid(0);
}

/**
*   Reloads the configuration file and removes interfaces which were removed from config.
*/
void reloadConfig(uint64_t *tid) {
    // Check and set sigstatus to what we are actually doing right now.
    if (NOSIG) sigstatus = GOT_CONFREL;
    oldvifConf      = vifConf;
    vifConf         = NULL;
    oldcommonConfig = commonConfig;

    // Load the new configuration keep reference to the old.
    if (!loadConfig()) {
        myLog(LOG_WARNING, 0, "reloadConfig: Unable to load config file, keeping current.");
        commonConfig = oldcommonConfig;
        if (vifConf) freeConfig(0);
        vifConf = oldvifConf;
    } else {
        // Rebuild the interfaces config, then free the old configuration.
        rebuildIfVc(NULL);
        freeConfig(1);

        myLog(LOG_DEBUG, 0, "reloadConfig: Config Reloaded. OldConfPtr: %x, NewConfPtr, %x", oldvifConf, vifConf);
    }
    if (sigstatus == GOT_CONFREL && commonConfig.rescanConf) *tid = timer_setTimer(0, commonConfig.rescanConf * 10, "Reload Configuration", (timer_f)reloadConfig, tid);

    sigstatus = 0;
}

/**
*   Loads the configuration from file, and stores the config in respective holders.
*/
bool loadConfig(void) {
    struct vifConfig  *tmpPtr, **currPtr = &vifConf;

    // Initialize common config
    initCommonConfig();

    // Open config file and read first token.
    if (! configFile(commonConfig.configFilePath, 1) || ! (token = nextConfigToken())) return false;
    myLog(LOG_DEBUG, 0, "Loading config from '%s'", commonConfig.configFilePath);

    // Loop until all configuration is read.
    while (token) {
        if (strcasecmp("phyint", token) == 0) {
            // Got a phyint token... Call phyint parser
            myLog(LOG_DEBUG, 0, "Config: Got a phyint token.");
            tmpPtr = parsePhyintToken();
            if (tmpPtr) {
                myLog(LOG_NOTICE, 0, "Config: IF name : %s", tmpPtr->name);
                myLog(LOG_NOTICE, 0, "Config: IF Ratelimit : %d", tmpPtr->ratelimit);
                myLog(LOG_NOTICE, 0, "Config: IF Threshold : %d", tmpPtr->threshold);
                myLog(LOG_NOTICE, 0, "Config: IF State : %d", tmpPtr->state);
                myLog(LOG_NOTICE, 0, "Config: IF Ptrs : %p: %p", tmpPtr, tmpPtr->filters);

                // Insert config, and move temppointer to next location...
                *currPtr = tmpPtr;
                currPtr = &tmpPtr->next;
                continue;
            } else if (!STARTUP) return false;

        } else if (strcasecmp("quickleave", token) == 0) {
            // Got a quickleave token....
            myLog(LOG_NOTICE, 0, "Config: Quick leave mode enabled.");
            commonConfig.fastUpstreamLeave = true;

        } else if (strcasecmp("maxorigins", token) == 0 && (token = nextConfigToken())) {
            // Got a maxorigins token...
            unsigned int intToken = atoi(token);
            commonConfig.maxOrigins = intToken < DEFAULT_MAX_ORIGINS ? DEFAULT_MAX_ORIGINS : intToken;
            myLog(LOG_NOTICE, 0, "Config: Setting max multicast group sources to %d.", commonConfig.maxOrigins);

        } else if (strcasecmp("hashtablesize", token) == 0 && (token = nextConfigToken())) {
            // Got a hashtablesize token...
            unsigned int intToken = atoi(token);
            if (! commonConfig.fastUpstreamLeave) {
                myLog(LOG_WARNING, 0, "Config: hashtablesize is specified but quickleave not enabled. Ignoring.");
            } else if (intToken < 1 || intToken > 536870912) {
                myLog(LOG_WARNING, 0, "Config: hashtablesize must be between 1 and 536870912 bytes, using default %d.", commonConfig.downstreamHostsHashTableSize);
            } else {
                commonConfig.downstreamHostsHashTableSize = intToken;
                myLog(LOG_NOTICE, 0, "Config: Got hashtablesize for quickleave is %d.", commonConfig.downstreamHostsHashTableSize);
            }

        } else if (strcasecmp("defaultupdown", token) == 0) {
            // Got a defaultupdown token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED) myLog(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_UPDOWNSTREAM;
                myLog(LOG_NOTICE, 0, "Config: Interface default to updownstream.");
            }

        } else if (strcasecmp("defaultup", token) == 0) {
            // Got a defaultup token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED) myLog(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_UPSTREAM;
                myLog(LOG_NOTICE, 0, "Config: Interface default to upstream.");
            }

        } else if (strcasecmp("defaultdown", token) == 0) {
            // Got a defaultdown token...
            if (commonConfig.defaultInterfaceState != IF_STATE_DISABLED) myLog(LOG_WARNING, 0, "Config: Default interface state can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultInterfaceState = IF_STATE_DOWNSTREAM;
                myLog(LOG_NOTICE, 0, "Config: Interface default to downstream.");
            }

        } else if (strcasecmp("nodefaultfilter", token) == 0) {
            // Got a defaultfilterany token...
            if (commonConfig.defaultFilterAny == true) myLog(LOG_WARNING, 0, "Config: Nodefaultfilter or defaultfilterany can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.nodefaultFilter = true;
                myLog(LOG_NOTICE, 0, "Config: Interface no default filter.");
            }

        } else if (strcasecmp("defaultfilterany", token) == 0) {
            // Got a defaultfilterany token...
            if (commonConfig.nodefaultFilter == true) myLog(LOG_WARNING, 0, "Config: Nodefaultfilter or defaultfilterany can only be specified once. Ignoring %s.", token);
            else {
                commonConfig.defaultFilterAny = true;
                myLog(LOG_NOTICE, 0, "Config: Interface default filter any.");
            }

        } else if (strcasecmp("defaultratelimit", token) == 0 && (token = nextConfigToken())) {
            // Default Ratelimit
            myLog(LOG_NOTICE, 0, "Config: Got defaultratelimit token '%s'.", token);
            if (atoi(token) < 0) {
                myLog(LOG_WARNING, 0, "Ratelimit must be 0 or more.");
            } else {
                commonConfig.defaultRatelimit = atoi(token);
            }

        } else if (strcasecmp("defaultthreshold", token) == 0 && (token = nextConfigToken())) {
            // Default Threshold
            if (atoi(token) <= 0 || atoi(token) > 255) {
                myLog(LOG_WARNING, 0, "Threshold must be between 1 and 255.");
            } else {
                commonConfig.defaultThreshold = atoi(token);
            }
            myLog(LOG_NOTICE, 0, "Config: Got defaultthreshold token '%s'.", commonConfig.defaultThreshold);

        } else if (strcasecmp("querierip", token) == 0 && (token = nextConfigToken())) {
            // Got a querierip token.
            uint32_t addr = inet_addr(token);
            commonConfig.querierIp = addr != 0 && addr != (uint32_t)-1 ? addr : 0;
            myLog(LOG_NOTICE, 0, "Config: Setting default querier ip address to %s.", inetFmt(addr, 1));

        } else if (strcasecmp("robustnessvalue", token) == 0 && (token = nextConfigToken())) {
            // Got a robustnessvalue token...
            unsigned int intToken = atoi(token);
            commonConfig.robustnessValue = intToken == 0 ? 1 : intToken;
            commonConfig.lastMemberQueryCount = commonConfig.lastMemberQueryCount != DEFAULT_ROBUSTNESS ? commonConfig.lastMemberQueryCount : intToken;
            myLog(LOG_NOTICE, 0, "Config: Setting default robustness value to %d.", commonConfig.robustnessValue);

        } else if (strcasecmp("queryinterval", token) == 0 && (token = nextConfigToken())) {
            // Got a queryinterval token...
            unsigned int intToken = atoi(token);
            if (intToken <= 0 || intToken > 32767) {
                myLog(LOG_WARNING, 0, "Config: Query interval must be between 1 and 32767.");
            } else {
                // Normalize the configured value according to RFC.
                commonConfig.queryInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                commonConfig.startupQueryInterval = STARTUP && commonConfig.queryInterval > 4 ? commonConfig.queryInterval / 4 : 1;

                // Check Query response and reload conf intervals and adjust if necessary.
                commonConfig.queryResponseInterval = commonConfig.queryResponseInterval / 10 > commonConfig.queryInterval ? commonConfig.queryInterval * 10 : commonConfig.queryResponseInterval;
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < commonConfig.queryInterval ? commonConfig.queryInterval : commonConfig.rescanConf;
                myLog(LOG_NOTICE, 0, "Config: Setting default query interval to %ds. Default response interval %ds", commonConfig.queryInterval, commonConfig.queryResponseInterval / 10);
            }

        } else if (strcasecmp("queryrepsonseinterval", token) == 0 && (token = nextConfigToken())) {
            // Got a queryresponsenterval token...
            unsigned int intToken = atoi(token);
            if (intToken <= 0 || intToken > 32767) {
                myLog(LOG_WARNING, 0, "Config: Query response interval must be between 1 and 32767.");
            } else {
                // Normalize the configured value according to RFC.
                commonConfig.queryResponseInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                float i = (float)commonConfig.queryResponseInterval / (float)10;

                // Check query and rescanconf interval and adjust if necessary.
                commonConfig.queryInterval = commonConfig.queryInterval < commonConfig.queryResponseInterval / 10 ? commonConfig.queryResponseInterval / 10 : commonConfig.queryInterval;
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < commonConfig.queryResponseInterval / 10 ? commonConfig.queryResponseInterval : commonConfig.rescanConf;
                myLog(LOG_NOTICE, 0, "Config: Setting default query response interval to %.1fs. Default query interval %ds", i, commonConfig.queryInterval);
        }

        } else if (strcasecmp("lastmemberinterval", token) == 0 && (token = nextConfigToken())) {
            // Got a lastmemberinterval token...
            unsigned int intToken = atoi(token);
            if (intToken <= 0 || intToken > 32767) {
                myLog(LOG_WARNING, 0, "Config: Last member query interval must be between 1 and 32767.");
            } else {
                // Normalize the configured value according to RFC.
                commonConfig.lastMemberQueryInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);

                // Check reload conf intervals and adjust if necessary.
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < commonConfig.lastMemberQueryInterval / 10 ? commonConfig.lastMemberQueryInterval / 10 : commonConfig.rescanConf;
                myLog(LOG_NOTICE, 0, "Config: Setting default last member query interval to %.1fs.", (float)commonConfig.lastMemberQueryInterval / (float)10);
        }

        } else if (strcasecmp("lastmembercount", token) == 0 && (token = nextConfigToken())) {
            // Got a lastmembercount token...
            unsigned int intToken = atoi(token);
            commonConfig.lastMemberQueryCount = intToken == 0 ? 1 : intToken;
            myLog(LOG_NOTICE, 0, "Config: Setting default last member query count to %d.", commonConfig.lastMemberQueryCount);

        } else if (strcasecmp("bwcontrol", token) == 0 && (token = nextConfigToken())) {
            // Got a bcontrolinterval token...
            unsigned int intToken = atoi(token);
            commonConfig.bwControlInterval = intToken > 0 && intToken < 3 ? 3 : intToken;
            myLog(LOG_NOTICE, 0, "Config: Setting bandwidth control interval to %ds.", commonConfig.bwControlInterval);

        } else if (strcasecmp("rescanvif", token) == 0 && (token = nextConfigToken())) {
            // Got a rescanvif token...
            unsigned int intToken = atoi(token);
            commonConfig.rescanVif = intToken;
            myLog(LOG_NOTICE, 0, "Config: Need detect new interface every %ds.", commonConfig.rescanVif);

        } else if (strcasecmp("rescanconf", token) == 0 && (token = nextConfigToken())) {
            // Got a rescanconf token...
            unsigned int intToken = atoi(token);
            unsigned int i = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0) * 10;
            commonConfig.rescanConf = intToken != 0 && (i < commonConfig.queryResponseInterval || i < commonConfig.lastMemberQueryInterval) ? i : intToken;
            myLog(LOG_NOTICE, 0, "Config: Need detect config change every %ds.", commonConfig.rescanConf);


        } else if (strcasecmp("loglevel", token) == 0 && (token = nextConfigToken())) {
            // Got a loglevel token...
            unsigned int intToken = atoi(token);
            commonConfig.logLevel = intToken > 7 ? 7 : intToken;
            myLog(LOG_NOTICE, 0, "Config: Log Level %d", commonConfig.logLevel);

        } else if (strcasecmp("logfile", token) == 0 && (token = nextConfigToken())) {
            if (! commonConfig.log2Stderr) {
                // Got a logfile token. Only use log file if not logging to stderr.
                commonConfig.logFilePath = ! commonConfig.logFilePath ? (char *)malloc(MAX_TOKEN_LENGTH) : commonConfig.logFilePath;   // Freed by igmpProxyCleanUp()
                if (strstr(options, token)) {
                    myLog(LOG_WARNING, 0, "Config: No logfile path specified. Ignoring.");
                    continue;
                }
                FILE *fp = fopen(token, "a");
                if (! fp) {
                    myLog(LOG_WARNING, errno, "Config: Cannot open log file %s.", token);
                    commonConfig.logFilePath = "";
                } else {
                    fclose(fp);
                    strcpy(commonConfig.logFilePath, token);
                    myLog(LOG_NOTICE, 0, "Config: Log File: %s", commonConfig.logFilePath);
                    time_t rawtime = time(NULL);
                    utcoff.tv_sec = timegm(localtime(&rawtime)) - rawtime;
                    commonConfig.logFile = true;
                }
            }

        } else if (strcasecmp("proxylocalmc", token) == 0) {
            // Got a proxylocalmc token....
            commonConfig.proxyLocalMc = true;
            myLog(LOG_NOTICE, 0, "Config: Will proxy local multicast range 224.0.0.0/8.");

        } else if (strcasecmp("noquerierelection", token) == 0) {
            // Got a noquerierelection token....
            commonConfig.querierElection = false;
            myLog(LOG_NOTICE, 0, "Config: Will not participate in IGMP querier election by default.");

        } else if (strcasecmp("cligroup", token) == 0 && (token = nextConfigToken())) {
            // Got a cligroup token....
            if (! getgrnam(token)) myLog(LOG_WARNING, errno, "Config: Incorrect group %s.", token);
            else {
                commonConfig.socketGroup = *getgrnam(token);
                if (!STARTUP) cliSetGroup(commonConfig.socketGroup.gr_gid);
                myLog(LOG_NOTICE, 0, "Config: Group for cli access: %s.", commonConfig.socketGroup.gr_name);
            }

        } else if (strstr(phyintopt, token)) {
            myLog(LOG_WARNING, 0, "Config: %s without phyint. Ignoring.", token);
            for (token = nextConfigToken(); ! strstr(options, token); token = nextConfigToken());
            continue;

        } else {
            // Unparsable token.
            myLog(LOG_WARNING, 0, "Config: Unknown token '%s' in config file", token);
            if (!STARTUP) return false;
        }

        token = nextConfigToken();
    }

    // Close the configfile.
    configFile(NULL, 0);

    // Check rescanvif status and start or clear timers if necessary.
    if (commonConfig.rescanVif && timers.rescanVif == 0) {
        timers.rescanVif = timer_setTimer(0, commonConfig.rescanVif * 10, "Rebuild Interfaces", (timer_f)rebuildIfVc, &timers.rescanVif);
    } else if (! commonConfig.rescanVif && timers.rescanVif != 0) {
        timer_clearTimer(timers.rescanVif);
        timers.rescanVif = 0;
    }
    // Check rescanconf status and start or clear timers if necessary.
    if (commonConfig.rescanConf && timers.rescanConf == 0) {
        timers.rescanConf = timer_setTimer(0, commonConfig.rescanConf * 10, "Reload Configuration", (timer_f)reloadConfig, &timers.rescanConf);
    } else if (! commonConfig.rescanConf && timers.rescanConf != 0) {
        timer_clearTimer(timers.rescanConf);
        timers.rescanConf = 0;
    }
    // Check if bw control interval changed.
    if (oldcommonConfig.bwControlInterval != commonConfig.bwControlInterval) {
        timer_clearTimer(timers.bwControl);
        timers.bwControl = 0;
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        int Va, len = sizeof(Va);
        if (!STARTUP && (getsockopt(getMrouterFD(), IPPROTO_IP, MRT_API_CONFIG, (void *)&Va, (void *)&len) || ! (Va & MRT_MFC_BW_UPCALL))) {
            myLog(LOG_WARNING, errno, "Config: MRT_API_CONFIG Failed. Disabling bandwidth control.");
            commonConfig.bwControlInterval = 0;
        } else {
            clearRoutes(getConfig);
        }
#endif
        if (commonConfig.bwControlInterval) {
            timers.bwControl = timer_setTimer(0, commonConfig.bwControlInterval * 10, "Bandwidth Control", (timer_f)bwControl, &timers.bwControl);
        }
    }
    // Check if quickleave was enabled or disabled due to config change.
    if (!STARTUP && oldcommonConfig.fastUpstreamLeave != commonConfig.fastUpstreamLeave) {
        myLog(LOG_NOTICE, 0, "Config: Quickleave mode was %s, reinitializing routes.", commonConfig.fastUpstreamLeave ? "disabled" : "enabled");
        clearRoutes(CONFIG);
    }
    // Check if hashtable size was changed due to config change.
    if (!STARTUP && commonConfig.fastUpstreamLeave && oldcommonConfig.downstreamHostsHashTableSize != commonConfig.downstreamHostsHashTableSize) {
        myLog(LOG_NOTICE, 0, "Config: Downstream host hashtable size changed from %i to %i, reinitializing routes.",oldcommonConfig.downstreamHostsHashTableSize, commonConfig.downstreamHostsHashTableSize);
        clearRoutes(CONFIG);
    }

    return true;
}

/**
*   Internal function to parse phyint config.
*/
static struct vifConfig *parsePhyintToken(void) {
    struct vifConfig  *tmpPtr;

    // First token should be the interface name....
    if (! (token = nextConfigToken())) {
        myLog(LOG_WARNING, 0, "Config: IF: You should at least name your interfeces.");
        return NULL;
    }
    myLog(LOG_DEBUG, 0, "Config: IF: Config for interface %s.", token);

    // Allocate and initialize memory for new configuration.
    if (! (tmpPtr = (struct vifConfig*)malloc(sizeof(struct vifConfig)))) myLog(LOG_ERR, errno, "parsePhyintToken: Out of memory.");  // Freed by freeConfig()
    *tmpPtr = (struct vifConfig){ "", commonConfig.defaultInterfaceState, commonConfig.defaultThreshold, commonConfig.defaultRatelimit, {commonConfig.querierIp, commonConfig.querierElection, commonConfig.robustnessValue, commonConfig.queryInterval, commonConfig.queryResponseInterval, commonConfig.lastMemberQueryInterval, commonConfig.lastMemberQueryCount}, true, false, NULL, NULL };

    // Make a copy of the token to store the IF name. Make sure it is NULL terminated.
    memcpy(tmpPtr->name, token, IF_NAMESIZE);
    tmpPtr->name[IF_NAMESIZE - 1] = '\0';
    if (strlen(token) >= IF_NAMESIZE) myLog(LOG_WARNING, 0, "parsePhyintToken: Interface name %s larger than system IF_NAMESIZE(%d), truncated to %s.", token, IF_NAMESIZE, tmpPtr->name);

    // Set pointer to pointer to filters list.
    filPtr = &tmpPtr->filters;

    // Parse the rest of the config..
    token = nextConfigToken();
    while (token) {
        // Check compatibily options for old version filtering. Is any filter option is encountered any altnet/whitelists will be ignored.
        // If there are already altnet/whitelists before a filter is encountered, they need to be freed.
        if ((strcasecmp("altnet", token) == 0 || strcasecmp("whitelist", token) == 0) && ! tmpPtr->compat) {
            myLog(LOG_WARNING, 0, "Config IF: %s cannot be combined with filters. Ignoring altnet/whitelist.", token);
            for (token = nextConfigToken(); token && ! strstr(options, token); token = nextConfigToken());
            continue;
        } else if (strcasecmp("filter", token) == 0 && tmpPtr->compat) {
            tmpPtr->compat = false;
            while (tmpPtr->filters) {
                struct filters *fFil = tmpPtr->filters;
                myLog(LOG_WARNING, 0, "Config IF: Altnet/whitelist cannot be combined with filters. Ignoring %s - %s.", token, inetFmts(fFil->src.ip, fFil->src.mask, 1), inetFmts(fFil->dst.ip, fFil->dst.mask, 2));
                tmpPtr->filters = tmpPtr->filters->next;
                free (fFil);
            }
        }

        if (strcasecmp("filter", token) == 0 || strcasecmp("altnet", token) == 0 || strcasecmp("whitelist", token) == 0) {
            // Black / Whitelist Parsing. If an error is made in a list, the whole list will be ignored.
            myLog(LOG_DEBUG, 0, "Config: IF: Parsing %s.", token);
            char list[MAX_TOKEN_LENGTH], *filteropt = "allow block ratelimit up down updown both";
            uint32_t addr, mask;
            struct filters fil = { {0xFFFFFFFF, 0xFFFFFFFF}, {0xFFFFFFFF, 0xFFFFFFFF}, (uint64_t)-1, (uint8_t)-1, NULL };

            for (strcpy(list, token), token = nextConfigToken(); token && (strstr(filteropt, token) || ! strstr(options, token)); token = nextConfigToken()) {
                if (strcasecmp("filter", list) == 0 && fil.dst.ip != 0xFFFFFFFF && fil.action == (uint64_t)-1) {
                    if (fil.dir == (uint8_t)-1) {
                        if (strcasecmp("UP", token) == 0 || strcasecmp("up", token) == 0) fil.dir = 1;
                        else if (strcasecmp("down", token) == 0) fil.dir = 2;
                        else if (strcasecmp("updown", token) == 0 || strcasecmp("both", token) == 0) fil.dir = 3;
                    }
                    if (strcasecmp("ratelimit", token) == 0 || strcasecmp("r", token) == 0 || strcasecmp("2", token) == 0) {
                        token = nextConfigToken();
                        uint64_t rl = atol(token);
                        if (! commonConfig.bwControlInterval) {
                            myLog(LOG_INFO, 0, "Config: IF: BW Control disabled, ignoring ratelimit rule %s - %s %lld.", inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), rl);
                        } else if (fil.src.ip != 0 && fil.src.ip != 0xFFFFFFFF) {
                            myLog(LOG_WARNING, 0, "Config: IF: Ratelimit rules must have INADDR_ANY as source. Ignoring %s - %s %lld.", inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), rl);
                        } else {
                            fil.action = rl >= 2 ? rl : 2;
                        }
                    } else if (strcasecmp("allow", token) == 0 || strcasecmp("a", token) == 0 || strcasecmp("1", token) == 0) {
                        fil.action = ALLOW;
                    } else if (strcasecmp("block", token) == 0 || strcasecmp("b", token) == 0 || strcasecmp("0", token) == 0) {
                        fil.action = BLOCK;
                    } else if (!strstr(filteropt, token)) {
                        myLog(LOG_WARNING, 0, "Config: IF: %s is not a valid filter action or direction. Ignoring %s.", token, list);
                        fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, (uint8_t)-1, NULL };
                    }
                } else if (! parseSubnetAddress(token, &addr, &mask)) {
                    // Unknown token. Ignore...
                    myLog(LOG_WARNING, 0, "Config: IF: Uparsable subnet '%s'. Ignoring %s.", token, list);
                    fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, (uint8_t)-1, NULL };
                } else if ((strcasecmp("whitelist", list) == 0 || (strcasecmp("filter", list) == 0 && fil.src.ip != 0xFFFFFFFF)) && ! IN_MULTICAST(ntohl(addr))) {
                    // Check if valid MC group for whitelist are filter dst.
                    myLog(LOG_WARNING, 0, "Config: IF: %s is not a valid multicast address. Ignoring %s.", inetFmt(addr, 1), list);
                    fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, (uint8_t)-1, NULL };
                } else if ((addr | mask) != mask) {
                    // Check if valid sn/mask pair.
                    myLog(LOG_WARNING, 0, "Config: IF: %s is not valid subnet/mask pair. Ignoring %s.", inetFmts(addr, mask, 1), list);
                    fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, (uint8_t)-1, NULL };
                } else if (strcasecmp("altnet", list) == 0 || strcasecmp("whitelist", list) == 0) {
                    fil = strcasecmp("altnet", list) == 0 ? (struct filters){ {addr, mask}, {INADDR_ANY, 0}, ALLOW, (uint8_t)-1, NULL } : (struct filters){ {INADDR_ANY, 0}, {addr, mask}, ALLOW, (uint8_t)-1, NULL };
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
                } else if ((fil.src.ip != 0xFFFFFFFF || (fil.src.ip == 0xFFFFFFFF && fil.action > ALLOW)) && fil.dst.ip != 0xFFFFFFFF && ! (fil.action == (uint64_t)-1)) {
                    // Correct filter, add and reset fil to process next entry.
                    if (fil.dir == (uint8_t)-1) fil.dir = 3;
                    if (fil.src.ip == 0xFFFFFFFF) fil.src.ip = fil.src.mask = 0;
                    myLog(LOG_DEBUG, 0, "Config: IF: Adding filter Src: %s Dst: %s Dir: %s Action: %lld.", inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), fil.dir == 1 ? "up" : fil.dir == 2 ? "down" : "updown", fil.action);
                    allocFilter(fil);
                    fil = (struct filters){ {0xFFFFFFFF, 0xFFFFFFFF}, {0xFFFFFFFF, 0xFFFFFFFF}, (uint64_t)-1, (uint8_t)-1, NULL };
                }
            }
            continue;

        } else if (strcasecmp("nodefaultfilter", token) == 0) {
            tmpPtr->nodefaultfilter = true;
            myLog(LOG_DEBUG, 0, "Config: IF: Got nodefaultfilter token.");

        } else if (strcasecmp("updownstream", token) == 0) {
            tmpPtr->state = IF_STATE_UPDOWNSTREAM;
            myLog(LOG_DEBUG, 0, "Config: IF: Got updownstream token.");

        } else if (strcasecmp("upstream", token) == 0) {
            tmpPtr->state = IF_STATE_UPSTREAM;
            myLog(LOG_DEBUG, 0, "Config: IF: Got upstream token.");

        } else if (strcasecmp("downstream", token) == 0) {
            tmpPtr->state = IF_STATE_DOWNSTREAM;
            myLog(LOG_DEBUG, 0, "Config: IF: Got downstream token.");

        } else if (strcasecmp("disabled", token) == 0) {
            tmpPtr->state = IF_STATE_DISABLED;
            myLog(LOG_DEBUG, 0, "Config: IF: Got disabled token.");

        } else if (strcasecmp("ratelimit", token) == 0 && (token = nextConfigToken())) {
            if (atoi(token) < 0) {
                myLog(LOG_WARNING, 0, "Config IF: Ratelimit must be 0 or more.");
            } else {
                tmpPtr->ratelimit = atoi(token);
                myLog(LOG_DEBUG, 0, "Config: IF: Got ratelimit token '%lld'.", tmpPtr->ratelimit);
            }

        } else if (strcasecmp("threshold", token) == 0 && (token = nextConfigToken())) {
            if (atoi(token) <= 0 || atoi(token) > 255) {
                myLog(LOG_WARNING, 0, "Config IF: Threshold must be between 1 and 255.");
            } else {
                tmpPtr->threshold = atoi(token);
                myLog(LOG_DEBUG, 0, "Config: IF: Got threshold token '%d'.", tmpPtr->threshold);
            }

        } else if (strcasecmp("querierip", token) == 0 && (token = nextConfigToken())) {
            uint32_t addr = inet_addr(token);
            tmpPtr->qry.ip = addr != 0 && addr != (uint32_t)-1 ? addr : 0;
            myLog(LOG_DEBUG, 0, "Config IF: Setting querier ip address on %s to %s.", tmpPtr->name, inetFmt(addr, 1));

        } else if (strcasecmp("noquerierelection", token) == 0) {
            tmpPtr->qry.election = false;
            myLog(LOG_DEBUG, 0, "Config IF: Will not participate in IGMP querier election on %s.", tmpPtr->name);

        } else if (strcasecmp("robustness", token) == 0 && (token = nextConfigToken())) {
            if (atoi(token) <= 0) {
                myLog(LOG_WARNING, 0, "Config IF: Robustness value should be more than 1.");
            } else {
                tmpPtr->qry.robustness = atoi(token);
                myLog(LOG_DEBUG, 0, "Config: IF: Got robustness token '%d'.", tmpPtr->qry.robustness);
            }

        } else if (strcasecmp("queryinterval", token) == 0 && (token = nextConfigToken())) {
            unsigned int intToken = atoi(token);
            if (intToken < 1 || intToken > 32767) {
                myLog(LOG_WARNING, 0, "Config IF: Query interval value should be between 1 than 32767.");
            } else {
                tmpPtr->qry.interval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                myLog(LOG_DEBUG, 0, "Config: IF: Got queryinterval token '%d'.", tmpPtr->qry.interval);
            }

        } else if (strcasecmp("queryresponseinterval", token) == 0 && (token = nextConfigToken())) {
            unsigned int intToken = atoi(token);
            if (intToken < 1 || intToken > 32767) {
                myLog(LOG_WARNING, 0, "Config IF: Query response interval value should be between 1 than 32767.");
            } else {
                tmpPtr->qry.responseInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < tmpPtr->qry.responseInterval / 10 ? tmpPtr->qry.responseInterval / 10 : commonConfig.rescanConf;
                myLog(LOG_DEBUG, 0, "Config: IF: Got queryresponseinterval token '%d'.", tmpPtr->qry.responseInterval);
            }

        } else if (strcasecmp("lastmemberinterval", token) == 0 && (token = nextConfigToken())) {
            unsigned int intToken = atoi(token);
            if (intToken < 1 || intToken > 32767) {
                myLog(LOG_WARNING, 0, "Config IF: Last member interval value should be between 1 than 32767.");
            } else {
                tmpPtr->qry.lmInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < tmpPtr->qry.lmInterval / 10 ? tmpPtr->qry.lmInterval / 10 : commonConfig.rescanConf;
                myLog(LOG_DEBUG, 0, "Config: IF: Got lastmemberinterval token '%d'.", tmpPtr->qry.lmInterval);
            }

        } else if (strcasecmp("lastmembercount", token) == 0 && (token = nextConfigToken())) {
            if (atoi(token) <= 0) {
                myLog(LOG_WARNING, 0, "Config IF: Last member count should be more than 1.");
            } else {
                tmpPtr->qry.lmCount = atoi(token);
                myLog(LOG_DEBUG, 0, "Config: IF: Got lastmembercount token '%d'.", tmpPtr->qry.lmCount);
            }
        } else if (! strstr(options, token)) {
            // Unknown token.
            myLog(LOG_WARNING, 0, "Config: IF; Unknown token '%s' in configfile", token);
            if (!STARTUP) return NULL;

        } else break;   // Send pointer and return to main config parser.

        token = nextConfigToken();
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

    if (! vifConf) myLog(LOG_WARNING, 0, "No valid interfaces configuration. Beware, everything will be default.");
    // Loop through all interfaces and find matching config.
    for (GETIFL(IfDp)) {
        if (CONFRELOAD) IfDp->oldconf = IfDp->conf;
        for (confPtr = vifConf; confPtr && strcmp(IfDp->Name, confPtr->name) != 0; confPtr = confPtr->next);
        if (confPtr) {
            myLog(LOG_DEBUG, 0, "Found config for %s", IfDp->Name);

            // For interfaces with compatibily lists altnet whitelist, build a new filter table.
            if ((! confPtr->filters || !IFREBUILD) && confPtr->compat) {
                // Parse all aliases / altnet / whitelist entries to correct filters for bw compatibility.
                struct filters *ofilters = confPtr->filters, *filter = confPtr->filters, *alias;
                int i = 0;
                filPtr = &confPtr->filters;

                // First go through aliases and build alias -> whitelist allow filters.
                for (alias = IfDp->aliases; alias; alias = alias->next, filter = confPtr->filters) {
                    do {
                        if (! filter && !confPtr->nodefaultfilter && !CONFIG->nodefaultFilter) {
                            // If no altnet / whitelist for interface, add filter for alias -> any allow.
                            allocFilter((struct filters){ {alias->src.ip, alias->src.mask}, {INADDR_ANY, 0}, ALLOW, 3, NULL });
                            myLog(LOG_DEBUG, 0, "configureVifs: Added compat filter %d %s - default updown %d.", ++i, inetFmts(alias->src.ip, alias->src.mask, 1), ALLOW);
                        } else if (filter && filter->dst.ip != INADDR_ANY) {
                            // Add Filter for alias -> group allow.
                            allocFilter((struct filters){ {alias->src.ip, alias->src.mask}, {filter->dst.ip, filter->dst.mask}, ALLOW, 3, NULL });
                            myLog(LOG_DEBUG, 0, "configureVifs: Added compat filter %d %s - %s updown %d.", ++i, inetFmts(alias->src.ip, alias->src.mask, 1), inetFmts(filter->dst.ip, filter->dst.mask, 2), ALLOW);
                        }
                        if (filter) filter = filter->next;
                    } while (filter);
                    if (i == 0 && !confPtr->nodefaultfilter && !CONFIG->nodefaultFilter) {
                        allocFilter((struct filters){ {alias->src.ip, alias->src.mask}, {INADDR_ANY, 0}, ALLOW, 3, NULL });
                        myLog(LOG_DEBUG, 0, "configureVifs: Added compat filter %d %s - default updown %d.", ++i, inetFmts(alias->src.ip, alias->src.mask, 1), ALLOW);
                    }
                }

                // Next go through all altnets and build altnet -> whitelist allow filters.
                for (filter = ofilters; filter; filter = filter->next) {
                    for (alias = ofilters; alias; alias = alias->next) {
                        if (filter->src.ip != INADDR_ANY && alias->dst.ip != INADDR_ANY) {
                            allocFilter((struct filters){ {filter->src.ip, filter->src.mask}, {alias->dst.ip, alias->dst.mask}, ALLOW, 3, NULL });
                            myLog(LOG_DEBUG, 0, "configureVifs: Added compat filter %d %s - %s updown %d.", ++i, inetFmts(filter->src.ip, filter->src.mask, 1), inetFmts(alias->dst.ip, alias->dst.mask, 2), ALLOW);
                        }
                    }
                }

                // Free the previous list made by parsePhyIntToken().
                for (filter = ofilters; filter; filter = alias) {
                    alias = filter->next;
                    free(filter);      // Alloced by allocFilter()
                }
            }

        } else  {
            // Interface has no matching config, create default config.
            myLog(LOG_DEBUG, 0, "configureVifs: Creating default config for %s interface %s.", IS_DISABLED(commonConfig.defaultInterfaceState) ? "disabled" : IS_UPDOWNSTREAM(commonConfig.defaultInterfaceState) ? "updownstream" : IS_UPSTREAM(commonConfig.defaultInterfaceState) ? "upstream" : "downstream", IfDp->Name);
            if (! (confPtr = (struct vifConfig *)malloc(sizeof(struct vifConfig)))) myLog(LOG_ERR, errno, "configureVifs: Out of Memory.");   // Freed by freeConfig()
            *confPtr = (struct vifConfig){ "", commonConfig.defaultInterfaceState, commonConfig.defaultThreshold, commonConfig.defaultRatelimit, {commonConfig.querierIp, commonConfig.querierElection, commonConfig.robustnessValue, commonConfig.queryInterval, commonConfig.queryResponseInterval, commonConfig.lastMemberQueryInterval, commonConfig.lastMemberQueryCount}, false, false, NULL, NULL };
            strcpy(confPtr->name, IfDp->Name);
            confPtr->next = vifConf;
            vifConf = confPtr;
        }

        // Link the configuration to the interface. And update the states.
        IfDp->conf           = confPtr;
        if (! IfDp->oldconf) {
            // If no old config at this point it is because buildIfVc detecetd new or removed interface.
            IfDp->oldconf = confPtr;
            if (!(IfDp->state & 0x80)) {
                // Removed interface, oldstate is current state, newstate is disabled, flagged for removal.
                IfDp->oldconf->state = IfDp->state;
                IfDp->state          = IF_STATE_DISABLED | 0x80;
            } else {
                // New interface, oldstate is disabled, newstate is configured state without default filter flag.
                IfDp->state          = IfDp->conf->state & ~0x80;
                IfDp->oldconf->state = IF_STATE_DISABLED;
            }
        } else {
            // Existing interface, oldstate is current state with default filter flag, newstate is configured state without default filter flag.
            IfDp->oldconf->state = IfDp->state | (IfDp->conf->state & 0x80);
            IfDp->state          = IfDp->conf->state & ~0x80;
        }
        register uint8_t oldstate = IF_OLDSTATE(IfDp), newstate = IF_NEWSTATE(IfDp);

        // Create default filters for aliases -> any allow, when reloading config or when new interface is detected and no configuration reload has yet occured.
        if (!(IfDp->conf->state & 0x80) && !confPtr->compat && !confPtr->nodefaultfilter && !CONFIG->nodefaultFilter) {
            filPtr = &confPtr->filters;
            for (struct filters *filter = confPtr->filters; filter; filPtr = &filter->next, filter = filter->next); // Go to last filter
            for (struct filters *filter = IfDp->aliases; filter; allocFilter(CONFIG->defaultFilterAny ? (struct filters){ {0, 0}, {0,0}, ALLOW, 3, NULL } : *filter), filter = filter->next);
            IfDp->conf->state |= 0x80;   // Flag configuration
        }

        // Set the querier parameters and check if timers need to be stopped and querier process restarted.
        if (! IfDp->conf->qry.election && IS_DOWNSTREAM(newstate) && IS_DOWNSTREAM(oldstate) && IfDp->querier.ip != IfDp->InAdr.s_addr) ctrlQuerier(2, IfDp);

        // Increase counters and call addVif if necessary.
        if (!IS_DISABLED(newstate) && (IfDp->index != (unsigned int)-1 || addVIF(IfDp))) {
            vifcount++;
            if (IS_DOWNSTREAM(newstate)) downvifcount++;
            if (IS_UPSTREAM(newstate))   upsvifcount++;
        }

        // Do maintenance on vifs according to their old and new state.
        if      ( IS_DISABLED(oldstate)   && IS_UPSTREAM(newstate))          { clearRoutes(IfDp);  ctrlQuerier(1, IfDp); }
        else if ( IS_DISABLED(oldstate)   && IS_DOWNSTREAM(newstate))        {                     ctrlQuerier(1, IfDp); }
        else if (!IS_DISABLED(oldstate)   && IS_DISABLED(newstate))          { clearRoutes(IfDp);  ctrlQuerier(0, IfDp); }
        else if ( oldstate != newstate)                                      { clearRoutes(IfDp);  ctrlQuerier(2, IfDp); }
        else if ( oldstate == newstate    && !IS_DISABLED(newstate))         { clearRoutes(IfDp);                        }

        // Check if vif needs to be removed.
        if (IS_DISABLED(newstate) && IfDp->index != (unsigned int)-1) {
            delVIF(IfDp);
            if (vifcount) vifcount--;
            if (IS_DOWNSTREAM(oldstate) && downvifcount) downvifcount--;
            if (IS_UPSTREAM(oldstate)   && upsvifcount)  upsvifcount--;
        }

        // Unlink old configuration from interface.
        IfDp->oldconf = NULL;
    }

    // All vifs created / updated, check if there is an upstream and at least one downstream on rebuild interface.
    if (vifcount < 2 || upsvifcount == 0 || downvifcount == 0) myLog(LOG_ERR, 0, "There must be at least 2 interfaces, 1 Vif as upstream and 1 as dowstream.");
}
