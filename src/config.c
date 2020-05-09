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
static struct vifconfig *parsePhyintToken(void);
static bool              parseSubnetAddress(char *addrstr, uint32_t *addr, uint32_t *mask);
static void              allocFilter(struct filters fil);

// Daemon Configuration.
static struct Config commonConfig;

// All valid configuration options.
static const char *options = "phyint quickleave maxorigins hashtablesize defaultdown defaultthreshold defaultratelimit querierip robustnessvalue queryinterval queryrepsonseinterval lastmemberinterval lastmembercount bwcontrol rescanvif rescanconf loglevel logfile proxylocalmc noquerierelection upstream downstream disabled ratelimit threshold filter altnet whitelist";
static const char *phyintopt = "downstream disabled ratelimit threshold noquerierelection querierip robustnessvalue queryinterval queryrepsonseinterval lastmemberinterval lastmembercount filter altnet whitelist";

// Configuration file reading.
static FILE           *confFilePtr = NULL;                                      // File handle pointer.
static char           *iBuffer = NULL, cToken[MAX_TOKEN_LENGTH], *token = NULL; // Input buffer, token buffer and token.
static unsigned int    bufPtr, readSize;                                        // Buffer position pointer and nr of bytes in buffer.

// Structures to keep vif configuration and black/whitelists.
static struct vifconfig   *vifconf, *oldvifconf;
static struct filters    **filPtr;

// Keep previous state of socketgroup, defaultdown, fastupstreamleave and downstreamhosthashtablesize.
static bool         quickleave = false, defaultdown = false;
static unsigned int hashtablesize = DEFAULT_HASHTABLE_SIZE, bwcontrol = 0;

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
    struct vifconfig *tmpConfPtr, *clrConfPtr;

    for (clrConfPtr = old ? oldvifconf : vifconf; clrConfPtr; clrConfPtr = tmpConfPtr) {
        tmpConfPtr = clrConfPtr->next;
        struct filters *clrFilPtr;
        for (clrFilPtr = clrConfPtr->filters; clrConfPtr->filters; clrConfPtr->filters = clrFilPtr) {
            clrFilPtr = clrConfPtr->filters->next;
            free(clrFilPtr);  // Alloced by allocFilter()
        }
        free(clrConfPtr);   // Alloced by parsePhyintToken()
    }

    my_log(LOG_DEBUG, 0, "freeConfig: %s cleared.", (old ? "Old configuration" : "Configuration"));
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

    // Allocate memory for filter. and copy from argument.
    if (! (**tmpFil = (struct filters*)malloc(sizeof(struct filters)))) my_log(LOG_ERR, 0, "allocSubnet: Out of Memory.");  // Freed by freeConfig() or parsePhyIntToken()
    memcpy(**tmpFil, &fil, sizeof(struct filters));

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
    sigstatus = NOSIG ? GOT_CONFREL : sigstatus;

    // Load the new configuration keep reference to the old.
    oldvifconf = vifconf;
    if (! loadConfig()) {
        my_log(LOG_WARNING, 0, "reloadConfig: Unable to load config file. Keeping current config.");
        return;
    }

    // Rebuild the interfaces config.
    rebuildIfVc(NULL);

    // Free all the old mallocd subnets and vifconf list.
    my_log(LOG_DEBUG, 0, "reloadConfig: Config Reloaded. OldConfPtr %x, NewConfPtr, %x", oldvifconf, vifconf);
    freeConfig(1);
    if (sigstatus == GOT_CONFREL && commonConfig.rescanConf) *tid = timer_setTimer(0, commonConfig.rescanConf * 10, "Reload Configuration", (timer_f)reloadConfig, tid);

    sigstatus = 0;
}

/**
*   Loads the configuration from file, and stores the config in respective holders.
*/
bool loadConfig(void) {
    struct vifconfig  *tmpPtr, **currPtr = &vifconf;

    // Initialize common config
    initCommonConfig();

    // Open config file and read first token.
    if (! configFile(commonConfig.configFilePath, 1) || ! (token = nextConfigToken())) return false;
    my_log(LOG_DEBUG, 0, "Loading config from '%s'", commonConfig.configFilePath);

    // Loop until all configuration is read.
    while (token) {
        if (strcmp("phyint", token) == 0) {
            // Got a phyint token... Call phyint parser
            my_log(LOG_DEBUG, 0, "Config: Got a phyint token.");
            tmpPtr = parsePhyintToken();
            if (tmpPtr) {
                my_log(LOG_DEBUG, 0, "IF name : %s", tmpPtr->name);
                my_log(LOG_DEBUG, 0, "Ratelimit : %d", tmpPtr->ratelimit);
                my_log(LOG_DEBUG, 0, "Threshold : %d", tmpPtr->threshold);
                my_log(LOG_DEBUG, 0, "State : %d", tmpPtr->state);
                my_log(LOG_DEBUG, 0, "Ptrs : %p: %p", tmpPtr, tmpPtr->filters);

                // Insert config, and move temppointer to next location...
                *currPtr = tmpPtr;
                currPtr = &tmpPtr->next;
            }
            continue;

        } else if (strcmp("quickleave", token) == 0) {
            // Got a quickleave token....
            my_log(LOG_DEBUG, 0, "Config: Quick leave mode enabled.");
            commonConfig.fastUpstreamLeave = true;
            quickleave = STARTUP ? true : quickleave;

        } else if (strcmp("maxorigins", token) == 0) {
            // Got a maxorigins token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            commonConfig.maxOrigins = intToken < DEFAULT_MAX_ORIGINS ? DEFAULT_MAX_ORIGINS : intToken;
            my_log(LOG_DEBUG, 0, "Config: Setting max multicast group sources to %d.", commonConfig.maxOrigins);

        } else if (strcmp("hashtablesize", token) == 0) {
            // Got a hashtablesize token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            if (! commonConfig.fastUpstreamLeave) {
                my_log(LOG_WARNING, 0, "Config: hashtablesize is specified but quickleave not enabled. Ignoring.");
            } else if (intToken < 1 || intToken > 536870912) {
                my_log(LOG_WARNING, 0, "Config: hashtablesize must be between 1 and 536870912 bytes, using default %d.", commonConfig.downstreamHostsHashTableSize);
            } else {
                commonConfig.downstreamHostsHashTableSize = intToken;
                hashtablesize = STARTUP ? intToken : hashtablesize;
                my_log(LOG_DEBUG, 0, "Config: Got hashtablesize for quickleave is %d.", commonConfig.downstreamHostsHashTableSize);
            }

        } else if (strcmp("defaultdown", token) == 0) {
            // Got a defaultdown token...
            commonConfig.defaultInterfaceState = IF_STATE_DOWNSTREAM;
            defaultdown = STARTUP ? true : defaultdown;
            my_log(LOG_DEBUG, 0, "Config: Interface default to downstream.");

        } else if (strcmp("defaultratelimit", token) == 0) {
            // Default Ratelimit
            token = nextConfigToken();
            my_log(LOG_DEBUG, 0, "Config: Got defaultratelimit token '%s'.", token);
            if (atoi(token) < 0) {
                my_log(LOG_WARNING, 0, "Ratelimit must be 0 or more.");
            } else {
                commonConfig.defaultRatelimit = atoi(token);
            }

        } else if (strcmp("defaultthreshold", token) == 0) {
            // Default Threshold
            token = nextConfigToken();
            if (atoi(token) <= 0 || atoi(token) > 255) {
                my_log(LOG_WARNING, 0, "Threshold must be between 1 and 255.");
            } else {
                commonConfig.defaultThreshold = atoi(token);
            }
            my_log(LOG_DEBUG, 0, "Config: Got defaultthreshold token '%s'.", commonConfig.defaultThreshold);

        } else if (strcmp("querierip", token) == 0) {
            // Got a querierip token.
            token = nextConfigToken();
            uint32_t addr = inet_addr(token);
            commonConfig.querierIp = addr != 0 && addr != (uint32_t)-1 ? addr : 0;
            my_log(LOG_DEBUG, 0, "Config: Setting default querier ip address to %s.", inetFmt(addr, 1));

        } else if (strcmp("robustnessvalue", token) == 0) {
            // Got a robustnessvalue token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            commonConfig.robustnessValue = intToken == 0 ? 1 : intToken;
            commonConfig.lastMemberQueryCount = commonConfig.lastMemberQueryCount != DEFAULT_ROBUSTNESS ? commonConfig.lastMemberQueryCount : intToken;
            my_log(LOG_DEBUG, 0, "Config: Setting default robustness value to %d.", commonConfig.robustnessValue);

        } else if (strcmp("queryinterval", token) == 0) {
            // Got a queryinterval token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            if (intToken <= 0 || intToken > 32767) {
                my_log(LOG_WARNING, 0, "Config: Query interval must be between 1 and 32767.");
            } else {
                // Normalize the configured value according to RFC.
                commonConfig.queryInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                commonConfig.startupQueryInterval = STARTUP && commonConfig.queryInterval > 4 ? commonConfig.queryInterval / 4 : 1;

                // Check Query response and reload conf intervals and adjust if necessary.
                commonConfig.queryResponseInterval = commonConfig.queryResponseInterval / 10 > commonConfig.queryInterval ? commonConfig.queryInterval * 10 : commonConfig.queryResponseInterval;
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < commonConfig.queryInterval ? commonConfig.queryInterval : commonConfig.rescanConf;
                my_log(LOG_DEBUG, 0, "Config: Setting default query interval to %ds. Default response interval %ds", commonConfig.queryInterval, commonConfig.queryResponseInterval / 10);
            }

        } else if (strcmp("queryrepsonseinterval", token) == 0) {
            // Got a queryresponsenterval token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            if (intToken <= 0 || intToken > 32767) {
                my_log(LOG_WARNING, 0, "Config: Query response interval must be between 1 and 32767.");
            } else {
                // Normalize the configured value according to RFC.
                commonConfig.queryResponseInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                float i = (float)commonConfig.queryResponseInterval / (float)10;

                // Check query and rescanconf interval and adjust if necessary.
                commonConfig.queryInterval = commonConfig.queryInterval < commonConfig.queryResponseInterval / 10 ? commonConfig.queryResponseInterval / 10 : commonConfig.queryInterval;
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < commonConfig.queryResponseInterval / 10 ? commonConfig.queryResponseInterval : commonConfig.rescanConf;
                my_log(LOG_DEBUG, 0, "Config: Setting default query response interval to %.1fs. Default query interval %ds", i, commonConfig.queryInterval);
        }

        } else if (strcmp("lastmemberinterval", token) == 0) {
            // Got a lastmemberinterval token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            if (intToken <= 0 || intToken > 32767) {
                my_log(LOG_WARNING, 0, "Config: Last member query interval must be between 1 and 32767.");
            } else {
                // Normalize the configured value according to RFC.
                commonConfig.lastMemberQueryInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);

                // Check reload conf intervals and adjust if necessary.
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < commonConfig.lastMemberQueryInterval / 10 ? commonConfig.lastMemberQueryInterval / 10 : commonConfig.rescanConf;
                my_log(LOG_DEBUG, 0, "Config: Setting default last member query interval to %.1fs.", (float)commonConfig.lastMemberQueryInterval / (float)10);
        }

        } else if (strcmp("lastmembercount", token) == 0) {
            // Got a lastmembercount token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            commonConfig.lastMemberQueryCount = intToken == 0 ? 1 : intToken;
            my_log(LOG_DEBUG, 0, "Config: Setting default last member query count to %d.", commonConfig.lastMemberQueryCount);

        } else if (strcmp("bwcontrol", token) == 0) {
            // Got a bcontrolinterval token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            commonConfig.bwControlInterval = intToken > 0 && intToken < 3 ? 3 : intToken;
            my_log(LOG_DEBUG, 0, "Config: Setting bandwidth control interval to %ds.", commonConfig.bwControlInterval);

        } else if (strcmp("rescanvif", token) == 0) {
            // Got a rescanvif token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            commonConfig.rescanVif = intToken;
            my_log(LOG_DEBUG, 0, "Config: Need detect new interface every %ds.", commonConfig.rescanVif);

        } else if (strcmp("rescanconf", token) == 0) {
            // Got a rescanconf token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            unsigned int i = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0) * 10;
            commonConfig.rescanConf = intToken != 0 && (i < commonConfig.queryResponseInterval || i < commonConfig.lastMemberQueryInterval) ? i : intToken;
            my_log(LOG_DEBUG, 0, "Config: Need detect config change every %ds.", commonConfig.rescanConf);


        } else if (strcmp("loglevel", token) == 0) {
            // Got a loglevel token...
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            commonConfig.logLevel = intToken > 7 ? 7 : intToken;
            my_log(LOG_DEBUG, 0, "Config: Log Level %d", commonConfig.logLevel);

        } else if (! commonConfig.log2Stderr && strcmp("logfile", token) == 0) {
            commonConfig.logFilePath = ! commonConfig.logFilePath ? (char *)malloc(MAX_TOKEN_LENGTH) : commonConfig.logFilePath;   // Freed by igmpProxyCleanUp()
            // Got a logfile token. Only use log file if not logging to stderr.
            token = nextConfigToken();
            if (strstr(options, token)) {
                my_log(LOG_WARNING, 0, "Config: No logfile path specified. Ignoring.");
                continue;
            }
            FILE *fp = fopen(token, "a");
            if (! fp) {
                my_log(LOG_WARNING, errno, "Config: Cannot open log file %s.", token);
                commonConfig.logFilePath = "";
            } else {
                fclose(fp);
                strcpy(commonConfig.logFilePath, token);
                my_log(LOG_NOTICE, 0, "Config: Log File: %s", commonConfig.logFilePath);
                time_t rawtime = time(NULL);
                utcoff.tv_sec = timegm(localtime(&rawtime)) - rawtime;
                commonConfig.logFile = true;
            }

        } else if (strcmp("proxylocalmc", token) == 0) {
            // Got a proxylocalmc token....
            commonConfig.proxyLocalMc = true;
            my_log(LOG_DEBUG, 0, "Config: Will proxy local multicast range 224.0.0.0/8.");

        } else if (strcmp("noquerierelection", token) == 0) {
            // Got a noquerierelection token....
            commonConfig.querierElection = false;
            my_log(LOG_DEBUG, 0, "Config: Will not participate in IGMP querier election by default.");

        } else if (strcmp("cligroup", token) == 0) {
            // Got a cligroup token....
            token = nextConfigToken();
            if (! getgrnam(token)) my_log(LOG_WARNING, errno, "Config: Incorrect group %s.", token);
            else {
                commonConfig.socketGroup = *getgrnam(token);
                if (!STARTUP) cliSetGroup(commonConfig.socketGroup.gr_gid);
                my_log(LOG_DEBUG, 0, "Config: Group for cli access: %s.", commonConfig.socketGroup.gr_name);
            }

        } else if (strstr(phyintopt, token)) {
            my_log(LOG_WARNING, 0, "Config: %s without phyint. Ignoring.", token);
            for (token = nextConfigToken(); ! strstr(options, token); token = nextConfigToken());
            continue;

        } else {
            // Unparsable token.
            my_log(LOG_WARNING, 0, "Config: Unknown token '%s' in config file", token);
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
    if (bwcontrol != commonConfig.bwControlInterval) {
        timer_clearTimer(timers.bwControl);
        timers.bwControl = 0;
#ifdef HAVE_STRUCT_BW_UPCALL_BU_SRC
        int Va, len = sizeof(Va);
        if (!STARTUP && (getsockopt(getMrouterFD(), IPPROTO_IP, MRT_API_CONFIG, (void *)&Va, (void *)&len) || ! (Va & MRT_MFC_BW_UPCALL))) {
            my_log(LOG_WARNING, errno, "Config: MRT_API_CONFIG Failed. Disabling bandwidth control.");
            commonConfig.bwControlInterval = 0;
        } else {
            clearRoutes(&commonConfig, NULL);
        }
#endif
        if (commonConfig.bwControlInterval) {
            timers.bwControl = timer_setTimer(0, commonConfig.bwControlInterval * 10, "Bandwidth Control", (timer_f)bwControl, &timers.bwControl);
        }
        bwcontrol = commonConfig.bwControlInterval;
    }
    // Check if quickleave was enabled or disabled due to config change.
    if (!STARTUP && quickleave != commonConfig.fastUpstreamLeave) {
        my_log(LOG_NOTICE, 0, "Config: Quickleave mode was %s, reinitializing routes.", quickleave ? "disabled" : "enabled");
        clearRoutes(NULL, &commonConfig);
        quickleave = commonConfig.fastUpstreamLeave;
        hashtablesize = commonConfig.downstreamHostsHashTableSize;
    }
    // Check if hashtable size was changed due to config change.
    if (!STARTUP && commonConfig.fastUpstreamLeave && hashtablesize != commonConfig.downstreamHostsHashTableSize) {
        my_log(LOG_NOTICE, 0, "Config: Downstream host hashtable size changed from %i to %i, reinitializing routes.", hashtablesize, commonConfig.downstreamHostsHashTableSize);
        clearRoutes(NULL, &commonConfig);
        hashtablesize = commonConfig.downstreamHostsHashTableSize;
    }

    return true;
}

/**
*   Internal function to parse phyint config.
*/
static struct vifconfig *parsePhyintToken(void) {
    struct vifconfig  *tmpPtr;

    // First token should be the interface name....
    if (! (token = nextConfigToken())) {
        my_log(LOG_DEBUG, 0, "Config: IF: You should at least name your interfeces.");
        return NULL;
    }
    my_log(LOG_DEBUG, 0, "Config: IF: Config for interface %s.", token);

    // Allocate memory for configuration.
    tmpPtr = (struct vifconfig*)malloc(sizeof(struct vifconfig));  // Freed by freeConfig()
    if (! tmpPtr) {
        my_log(LOG_ERR, 0, "parsePhyintToken: Out of memory.");
    }

    // Set default values...
    *tmpPtr = (struct vifconfig){ "", commonConfig.defaultInterfaceState, commonConfig.defaultThreshold, commonConfig.defaultRatelimit, {commonConfig.querierIp, commonConfig.querierElection, commonConfig.robustnessValue, commonConfig.queryInterval, commonConfig.queryResponseInterval, commonConfig.lastMemberQueryInterval, commonConfig.lastMemberQueryCount}, NULL, true, NULL, NULL };

    // Make a copy of the token to store the IF name. Make sure it is NULL terminated.
    memset(tmpPtr->name, 0, IF_NAMESIZE);
    memcpy(tmpPtr->name, token, strlen(token) < IF_NAMESIZE ? strlen(token) : IF_NAMESIZE);
    if (strlen(token) >= IF_NAMESIZE) {
        tmpPtr->name[IF_NAMESIZE - 1] = '\0';
        my_log(LOG_WARNING, 0, "parsePhyintToken: Interface name %s larger than system IF_NAMESIZE(%d), truncated to %s.", token, IF_NAMESIZE, tmpPtr->name);
    }

    // Set pointer to pointer to filters list.
    filPtr = &tmpPtr->filters;

    // Parse the rest of the config..
    token = nextConfigToken();
    while (token) {
        // Check compatibily options for old version filtering. Is any filter option is encountered any altnet/whitelists will be ignored.
        // If there are already altnet/whitelists before a filter is encountered, they need to be freed.
        if ((strcmp("altnet", token) == 0 || strcmp("whitelist", token) == 0) && ! tmpPtr->compat) {
            my_log(LOG_WARNING, 0, "Config IF: %s cannot be combined with filters. Ignoring altnet/whitelist.", token);
            for (token = nextConfigToken(); token && ! strstr(options, token); token = nextConfigToken());
            continue;
        } else if (strcmp("filter", token) == 0 && tmpPtr->compat) {
            tmpPtr->compat = false;
            while (tmpPtr->filters) {
                struct filters *fFil = tmpPtr->filters;
                my_log(LOG_WARNING, 0, "Config IF: Altnet/whitelist cannot be combined with filters. Ignoring %s - %s.", token, inetFmts(fFil->src.ip, fFil->src.mask, 1), inetFmts(fFil->dst.ip, fFil->dst.mask, 2));
                tmpPtr->filters = tmpPtr->filters->next;
                free (fFil);
            }
        }

        if (strcmp("filter", token) == 0 || strcmp("altnet", token) == 0 || strcmp("whitelist", token) == 0) {
            // Black / Whitelist Parsing. If an error is made in a list, the whole list will be ignored.
            my_log(LOG_DEBUG, 0, "Config IF: Parsing %s.", token);
            char list[MAX_TOKEN_LENGTH], *filteropt = "ALLOW allow BLOCK block RATELIMIT ratelimit";
            uint32_t addr, mask;
            struct filters fil = { {0xFFFFFFFF, 0xFFFFFFFF}, {0xFFFFFFFF, 0xFFFFFFFF}, (uint64_t)-1, NULL };

            for (strcpy(list, token), token = nextConfigToken(); token && (strstr(filteropt, token) || ! strstr(options, token)); token = nextConfigToken()) {
                if (strcmp("filter", list) == 0 && fil.dst.ip != 0xFFFFFFFF) {
                    if (strcmp("RATELIMIT", token) == 0 || strcmp("R", token) == 0 || strcmp("ratelimit", token) == 0 || strcmp("r", token) == 0 || strcmp("2", token) == 0) {
                        token = nextConfigToken();
                        uint64_t rl = atol(token);
                        if (! commonConfig.bwControlInterval) {
                            my_log(LOG_INFO, 0, "Config: IF: BW Control disabled, ignoring ratelimit rule %s - %s %lld.", inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), rl);
                        } else if (fil.src.ip != 0 && fil.src.ip != 0xFFFFFFFF) {
                            my_log(LOG_WARNING, 0, "Config: IF: Ratelimit rules must have INADDR_ANY as source. Ignoring %s - %s %lld.", inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), rl);
                        } else {
                            fil.action = rl >= 2 ? rl : 2;
                        }
                    } else if (strcmp("ALLOW", token) == 0 || strcmp("A", token) == 0 || strcmp("allow", token) == 0 || strcmp("a", token) == 0 || strcmp("1", token) == 0) {
                        fil.action = ALLOW;
                    } else if (strcmp("BLOCK", token) == 0 || strcmp("B", token) == 0 || strcmp("block", token) == 0 || strcmp("b", token) == 0 || strcmp("0", token) == 0) {
                        fil.action = BLOCK;
                    } else {
                        my_log(LOG_WARNING, 0, "Config: IF: %s is not a valid filter action. Ignoring %s.", token, list);
                        fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, NULL };
                    }
                } else if (! parseSubnetAddress(token, &addr, &mask)) {
                    // Unknown token. Ignore...
                    my_log(LOG_WARNING, 0, "Config: IF: Uparsable subnet '%s'. Ignoring %s.", token, list);
                    fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, NULL };
                } else if ((strcmp("whitelist", list) == 0 || (strcmp("filter", list) == 0 && fil.src.ip != 0xFFFFFFFF)) && ! IN_MULTICAST(ntohl(addr))) {
                    // Check if valid MC group for whitelist are filter dst.
                    my_log(LOG_WARNING, 0, "Config: IF: %s is not a valid multicast address. Ignoring %s.", inetFmt(addr, 1), list);
                    fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, NULL };
                } else if ((addr | mask) != mask) {
                    // Check if valid sn/mask pair.
                    my_log(LOG_WARNING, 0, "Config: IF: %s is not valid subnet/mask pair. Ignoring %s.", inetFmts(addr, mask, 1), list);
                    fil = (struct filters){ {0xFFFFFFFF, 0}, {0xFFFFFFFF, 0}, (uint64_t)-1, NULL };
                } else if (strcmp("altnet", list) == 0 || strcmp("whitelist", list) == 0) {
                    fil = strcmp("altnet", list) == 0 ? (struct filters){ {addr, mask}, {INADDR_ANY, 0}, ALLOW, NULL } : (struct filters){ {INADDR_ANY, 0}, {addr, mask}, ALLOW, NULL };
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
                    if (fil.src.ip == 0xFFFFFFFF) fil.src.ip = fil.src.mask = 0;
                    my_log(LOG_DEBUG, 0, "Config: IF: Adding filter Src %s Dst %s, %lld.", inetFmts(fil.src.ip, fil.src.mask, 1), inetFmts(fil.dst.ip, fil.dst.mask, 2), fil.action);
                    allocFilter(fil);
                    fil = (struct filters){ {0xFFFFFFFF, 0xFFFFFFFF}, {0xFFFFFFFF, 0xFFFFFFFF}, (uint64_t)-1, NULL };
                }
            }
            continue;

        } else if (strcmp("upstream", token) == 0) {
            tmpPtr->state = IF_STATE_UPSTREAM;
            my_log(LOG_DEBUG, 0, "Config: IF: Got upstream token.");

        } else if (strcmp("downstream", token) == 0) {
            tmpPtr->state = IF_STATE_DOWNSTREAM;
            my_log(LOG_DEBUG, 0, "Config: IF: Got downstream token.");

        } else if (strcmp("disabled", token) == 0) {
            tmpPtr->state = IF_STATE_DISABLED;
            my_log(LOG_DEBUG, 0, "Config: IF: Got disabled token.");

        } else if (strcmp("ratelimit", token) == 0) {
            token = nextConfigToken();
            if (atoi(token) < 0) {
                my_log(LOG_WARNING, 0, "Config IF: Ratelimit must be 0 or more.");
            } else {
                tmpPtr->ratelimit = atoi(token);
                my_log(LOG_DEBUG, 0, "Config: IF: Got ratelimit token '%lld'.", tmpPtr->ratelimit);
            }

        } else if (strcmp("threshold", token) == 0) {
            token = nextConfigToken();
            if (atoi(token) <= 0 || atoi(token) > 255) {
                my_log(LOG_WARNING, 0, "Config IF: Threshold must be between 1 and 255.");
            } else {
                tmpPtr->threshold = atoi(token);
                my_log(LOG_DEBUG, 0, "Config: IF: Got threshold token '%d'.", tmpPtr->threshold);
            }

        } else if (strcmp("querierip", token) == 0) {
            token = nextConfigToken();
            uint32_t addr = inet_addr(token);
            tmpPtr->qry.ip = addr != 0 && addr != (uint32_t)-1 ? addr : 0;
            my_log(LOG_DEBUG, 0, "Config IF: Setting querier ip address on %s to %s.", tmpPtr->name, inetFmt(addr, 1));

        } else if (strcmp("noquerierelection", token) == 0) {
            tmpPtr->qry.election = false;
            my_log(LOG_DEBUG, 0, "Config IF: Will not participate in IGMP querier election on %s.", tmpPtr->name);

        } else if (strcmp("robustness", token) == 0) {
            token = nextConfigToken();
            if (atoi(token) <= 0) {
                my_log(LOG_WARNING, 0, "Config IF: Robustness value should be more than 1.");
            } else {
                tmpPtr->qry.robustness = atoi(token);
                my_log(LOG_DEBUG, 0, "Config: IF: Got robustness token '%d'.", tmpPtr->qry.robustness);
            }

        } else if (strcmp("queryinterval", token) == 0) {
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            if (intToken < 1 || intToken > 32767) {
                my_log(LOG_WARNING, 0, "Config IF: Query interval value should be between 1 than 32767.");
            } else {
                tmpPtr->qry.interval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                my_log(LOG_DEBUG, 0, "Config: IF: Got queryinterval token '%d'.", tmpPtr->qry.interval);
            }

        } else if (strcmp("queryresponseinterval", token) == 0) {
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            if (intToken < 1 || intToken > 32767) {
                my_log(LOG_WARNING, 0, "Config IF: Query response interval value should be between 1 than 32767.");
            } else {
                tmpPtr->qry.responseInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < tmpPtr->qry.responseInterval / 10 ? tmpPtr->qry.responseInterval / 10 : commonConfig.rescanConf;
                my_log(LOG_DEBUG, 0, "Config: IF: Got queryresponseinterval token '%d'.", tmpPtr->qry.responseInterval);
            }

        } else if (strcmp("lastmemberinterval", token) == 0) {
            token = nextConfigToken();
            unsigned int intToken = atoi(token);
            if (intToken < 1 || intToken > 32767) {
                my_log(LOG_WARNING, 0, "Config IF: Last member interval value should be between 1 than 32767.");
            } else {
                tmpPtr->qry.lmInterval = intToken < 128 ? intToken : getIgmpExp(getIgmpExp(intToken, 1), 0);
                commonConfig.rescanConf = commonConfig.rescanConf && commonConfig.rescanConf < tmpPtr->qry.lmInterval / 10 ? tmpPtr->qry.lmInterval / 10 : commonConfig.rescanConf;
                my_log(LOG_DEBUG, 0, "Config: IF: Got lastmemberinterval token '%d'.", tmpPtr->qry.lmInterval);
            }

        } else if (strcmp("lastmembercount", token) == 0) {
            token = nextConfigToken();
            if (atoi(token) <= 0) {
                my_log(LOG_WARNING, 0, "Config IF: Last member count should be more than 1.");
            } else {
                tmpPtr->qry.lmCount = atoi(token);
                my_log(LOG_DEBUG, 0, "Config: IF: Got lastmembercount token '%d'.", tmpPtr->qry.lmCount);
            }
        } else if (! strstr(options, token)) {
            // Unknown token.
            my_log(LOG_WARNING, 0, "Config: IF; Unknown token '%s' in configfile", token);

        } else break;   // Send pointer and return to main config parser.

        token = nextConfigToken();
    }

    return tmpPtr;
}

/**
*   Appends extra VIF configuration from config file.
*/
void configureVifs(void) {
    struct IfDesc    *Dp = NULL;
    struct vifconfig *confPtr = NULL, *oconfPtr= NULL;

    if (! vifconf) {
        my_log(LOG_ERR, 0, "No valid interfaces configuration.");
    }

    // Loop through all interfaces.
    for (getNextIf(&Dp); Dp; getNextIf(&Dp)) {

        // On config reload find old config if any.
        if (CONFRELOAD || SSIGHUP) {
            for (oconfPtr = oldvifconf; oconfPtr && (strcmp(Dp->Name, oconfPtr->name) != 0); oconfPtr = oconfPtr->next);
        }

        // Now try to find a matching config...
        for (confPtr = vifconf; confPtr && strcmp(Dp->Name, confPtr->name) != 0; confPtr = confPtr->next);
        if (confPtr) {
            filPtr = &confPtr->filters;
            my_log(LOG_DEBUG, 0, "Found config for %s", Dp->Name);

            // For interfaces with compatibily lists altnet whitelist, build a new filter table.
            if ((STARTUP || CONFRELOAD || SSIGHUP) && confPtr->compat) {
                // Parse all aliases / altnet / whitelist entries to correct filters for bw compatibility.
                struct filters *ofilters = confPtr->filters, *filter = confPtr->filters, *alias;
                int i = 0;

                // First go through aliases and build alias -> whitelist allow filters.
                for (alias = Dp->aliases; alias; alias = alias->next, filter = confPtr->filters) {
                    do {
                        if (! filter) {
                            // If no altnet / whitelist for interface, add filter for alias -> any allow.
                            allocFilter((struct filters){ {alias->src.ip, alias->src.mask}, {INADDR_ANY, 0}, ALLOW, NULL });
                            my_log(LOG_DEBUG, 0, "configureVifs: Added compat filter %d %s - %s %d.", ++i, inetFmts(alias->src.ip, alias->src.mask, 1), "default", ALLOW);
                        } else if (filter->dst.ip != INADDR_ANY) {
                            // Add Filter for alias -> group allow.
                            allocFilter((struct filters){ {alias->src.ip, alias->src.mask}, {filter->dst.ip, filter->dst.mask}, ALLOW, NULL });
                            my_log(LOG_DEBUG, 0, "configureVifs: Added compat filter %d %s - %s %d.", ++i, inetFmts(alias->src.ip, alias->src.mask, 1), inetFmts(filter->dst.ip, filter->dst.mask, 2), ALLOW);
                        }
                        filter = filter ? filter->next : NULL;
                    } while (filter);
                    if (i == 0) {
                        allocFilter((struct filters){ {alias->src.ip, alias->src.mask}, {INADDR_ANY, 0}, ALLOW, NULL });
                        my_log(LOG_DEBUG, 0, "configureVifs: Added compat filter %d %s - %s %d.", ++i, inetFmts(alias->src.ip, alias->src.mask, 1), "default", ALLOW);
                    }
                }

                // Next go through all altnets and build altnet -> whitelist allow filters.
                for (filter = ofilters; filter; filter = filter->next) {
                    for (alias = ofilters; alias; alias = alias->next) {
                        if (filter->src.ip != INADDR_ANY && alias->dst.ip != INADDR_ANY) {
                            allocFilter((struct filters){ {filter->src.ip, filter->src.mask}, {alias->dst.ip, alias->dst.mask}, ALLOW, NULL });
                            my_log(LOG_DEBUG, 0, "configureVifs: Added compat filter %d %s - %s %d.", ++i, inetFmts(filter->src.ip, filter->src.mask, 1), inetFmts(alias->dst.ip, alias->dst.mask, 2), ALLOW);
                        }
                    }
                }

                // Free the previous list made by parsePhyIntToken().
                for (filter = ofilters; filter; filter = alias) {
                    alias = filter->next;
                    free(filter);      // Alloced by allocFilter()
                }
            } else if (! confPtr->compat && ! confPtr->filters) {
                // When no compat filters defined and default interface config, copy aliases filters to vifconfig for use.
                for (struct filters *filter = Dp->aliases; filter; allocFilter(*filter), filter = filter->next);
            }

        } else {
            // Interface has no matching config, create default config.
            my_log(LOG_DEBUG, 0, "configureVifs: Creating default config for %s interface %s.", Dp->Name, commonConfig.defaultInterfaceState == IF_STATE_DISABLED ? "disabled" : commonConfig.defaultInterfaceState == IF_STATE_DOWNSTREAM ? "downstream" : "disabled");
            confPtr = (struct vifconfig *)malloc(sizeof(struct vifconfig));   // Freed by freeConfig()
            *confPtr = (struct vifconfig){ "", commonConfig.defaultInterfaceState, commonConfig.defaultThreshold, commonConfig.defaultRatelimit, {commonConfig.querierIp, commonConfig.querierElection, commonConfig.robustnessValue, commonConfig.queryInterval, commonConfig.queryResponseInterval, commonConfig.lastMemberQueryInterval, commonConfig.lastMemberQueryCount}, NULL, true, NULL, NULL };
            strcpy(confPtr->name, Dp->Name);
            filPtr = &confPtr->filters;
            for (struct filters *filter = Dp->aliases; filter; allocFilter(*filter), filter = filter->next);
            confPtr->next = vifconf;
            vifconf = confPtr;
        }

        // Set the configured interface paramters and link the correct filter list and vif index to the IfDesc isAddressValidforIf() and getGroupBw() need them.
        Dp->state      = confPtr->state;
        Dp->threshold  = confPtr->threshold;
        Dp->ratelimit  = confPtr->ratelimit;
        Dp->filters    = confPtr->filters;
        confPtr->index = &Dp->index;

        // Set the querier parameters and check if timers need to be stopped and querier process started.
        Dp->qry        = &(confPtr->qry);
        if (! Dp->qry->election && Dp->state == IF_STATE_DOWNSTREAM && Dp->querier.ip != Dp->InAdr.s_addr) {
            timer_clearTimer(Dp->querier.v1Timer);
            timer_clearTimer(Dp->querier.v2Timer);
            sendGeneralMemberQuery(Dp);
        }
    }
}

/**
*   create VIFs for all IP, non-loop interfaces. Use to rebuild the vifdesc table from new IfDesc table (sigstatus 1, 3, 5) or new confiuration (sigstatus 2,4).
*   When rebuilding interfaces or reloading configuration the below state table is used to check which actions to take.
*   The clearRoutes() function is used to do things like joining / leaving groups, updating route vifbits, removing routes etc. when interfaces switch state.
*   The function may return a list of groups to query if necessary because of routes changing state or being removed.
*                     old: disabled    new: disabled    -> do nothing
*                     old: disabled    new: downstream  ->                                                   ,start querier                ,addVIF(new)
*                     old: disabled    new: upstream    ->                                                   ,start querier  ,join groups  ,addVIF(new)
*                     old: downstream  new: disabled    -> clearroutes old vif  ,stop querier  ,delVIF(old)                                              ,query groups
*       state table   old: downstream  new: downstream  -> on config reload & sighup: evalbw                                                             ,query groups
*                     old: downstream  new: upstream    -> clearroutes old vif  ,stop querier  ,delVIF(old)  ,start querier  ,join groups  ,addVIF(new)  ,query groups
*                     old: upstream    new: disabled    -> clearroutes old vif  ,stop querier  ,delVIF(old)                                              ,query groups
*                     old: upstream    new: downstream  -> clearroutes old vif  ,stop querier  ,delVIF(old)  ,start querier                ,addVIF(new)  ,query groups
*                     old: upstream    new: upstream    -> on config reload & sighup: evalbw                                                             ,query groups
*/
void createVifs(void) {
    struct IfDesc    *Dp, *oDp = NULL;
    struct vifconfig *ocDp = NULL;
    struct gvDescL   *gvDescL = NULL, *tmpgvDescL = NULL, *addgvDescL = NULL;
    register int      vifcount = 0, upsvifcount = 0;

    if (IFREBUILD || SSIGHUP) {
        // When rebuild interfaces check if interfaces have dissapeared and call delVIF if necessary.
        for (oDp = (void *)&getNextIf, getNextIf(&oDp); oDp; getNextIf(&oDp)) {
            if (! (Dp = getIfByName(oDp->Name, 0)) && oDp->index != (unsigned int)-1) {
                my_log(LOG_DEBUG, 0, "Interface %s disappeared from system.", oDp->Name);
                addgvDescL = clearRoutes(oDp, NULL);
                // For any dissappeared vif we may have a list of groups to be queried after we are done.
                if (addgvDescL && ! gvDescL) {
                    gvDescL = addgvDescL;
                } else if (addgvDescL && gvDescL) {
                    for (tmpgvDescL = gvDescL; tmpgvDescL && tmpgvDescL->next; tmpgvDescL = tmpgvDescL->next);
                    tmpgvDescL->next = addgvDescL;
                }
                ctrlQuerier(0, oDp);
                delVIF(oDp);
            }
        }
    }

    // Loop through current IfDesc table and (re)build the vivdesc table.
    for (Dp = NULL, getNextIf(&Dp); Dp; getNextIf(&Dp)) {
        struct vifconfig *confPtr;
        void             *crDp;
        register int      oldstate = IF_STATE_DISABLED, newstate = Dp->state;
        addgvDescL = NULL;

        if (CONFRELOAD) {
            // When reloading config lookup the old vifconfig to get the old state.
            for (confPtr = oldvifconf; confPtr && strcmp(Dp->Name, confPtr->name) != 0; confPtr = confPtr->next);
            ocDp = crDp = confPtr;
        } else {
            // When rebuilding interfaces, use old IfDesc, new IfDesc.
            crDp = Dp;
        }
        // On config reload set old ifdesc to current, otherwise it is the old ifdesc, if any.
        oDp = CONFRELOAD ? Dp : getIfByName(Dp->Name, 1);
        // On config reload oldstate is old vifconf state, or when no old vifconf and deafultdown was set interfacse was downstream.
        // When rebuilding interfaces or SIGHUP the oldstate is the olf IfDesc's state, or disabled if no old IfDesc was present.
        oldstate = (CONFRELOAD && ocDp) ? ocDp->state : (CONFRELOAD && ! ocDp && defaultdown) ? IF_STATE_DOWNSTREAM : (!CONFRELOAD && oDp) ? oDp->state : IF_STATE_DISABLED;

        switch (oldstate) {
        case IF_STATE_DISABLED:
            switch (newstate) {
            case IF_STATE_DISABLED:   {                                                                                                                      continue; }
            case IF_STATE_DOWNSTREAM: {                                                                           ctrlQuerier(1, Dp);                        break; }
            case IF_STATE_UPSTREAM:   {                                                                           ctrlQuerier(1, Dp);  clearRoutes(Dp, Dp);  break; }
            }
            break;
        case IF_STATE_DOWNSTREAM:
            switch (newstate) {
            case IF_STATE_DISABLED:   { addgvDescL = clearRoutes(oDp, crDp);  ctrlQuerier(0, oDp);  delVIF(oDp);                                             break; }
            case IF_STATE_DOWNSTREAM: { if (CONFRELOAD || SSIGHUP) addgvDescL = clearRoutes(oDp, crDp);                                                      break; }
            case IF_STATE_UPSTREAM:   { addgvDescL = clearRoutes(oDp, crDp);  ctrlQuerier(0, oDp);  delVIF(oDp);  ctrlQuerier(1, Dp);  clearRoutes(Dp, Dp);  break; }
            }
            break;
        case IF_STATE_UPSTREAM:
            switch (newstate) {
            case IF_STATE_DISABLED:   { addgvDescL = clearRoutes(oDp, crDp);  ctrlQuerier(0, oDp);  delVIF(oDp);                                             break; }
            case IF_STATE_DOWNSTREAM: { addgvDescL = clearRoutes(oDp, crDp);  ctrlQuerier(0, oDp);  delVIF(oDp);  ctrlQuerier(1, Dp);                        break; }
            case IF_STATE_UPSTREAM:   { if (CONFRELOAD || SSIGHUP) addgvDescL = clearRoutes(oDp, crDp);                                                      break; }
            }
        }

        // For any removed vif we may have a list of groups to be queried after we are done.
        if (addgvDescL && ! gvDescL) {
            gvDescL = addgvDescL;
        } else if (addgvDescL && gvDescL) {
            for (tmpgvDescL = gvDescL; tmpgvDescL && tmpgvDescL->next; tmpgvDescL = tmpgvDescL->next);
            tmpgvDescL->next = addgvDescL;
        }

        // Check for (max) upstream interfaces and increase upstream vif count.
        if (newstate == IF_STATE_UPSTREAM && upsvifcount >= MAX_UPS_VIFS) {
            my_log(LOG_WARNING, 0, "Cannot set VIF %s as upstream. Max upstream Vif count is %d.", Dp->Name, MAX_UPS_VIFS);
            memset(&Dp->igmp, 0, sizeof(struct Igmp));
            memset(&Dp->querier, 0, sizeof(struct querier));
            Dp->state   = IF_STATE_DISABLED;
            continue;
        } else if (newstate == IF_STATE_UPSTREAM) {
            my_log(LOG_DEBUG, 0, "Found upstream IF #%d, will assign as upstream Vif %s", upsvifcount++, Dp->Name);
        }

        // Call addVif if necessary.
        if (Dp->index == (unsigned int)-1) {
            addVIF(Dp);
        }
        vifcount++;
    }

    // All vifs created / updated, check if there is an upstream and at least one downstream on rebuild interface.
    if (upsvifcount == 0 || vifcount == upsvifcount) {
        my_log(STARTUP ? LOG_ERR : LOG_WARNING, 0, "There must be at least 1 Vif as upstream and 1 as dowstream.");
    }

    // If we have a lists of groups that have been set to check last member start the group specific querier.
    while (gvDescL) {
        struct gvDescL *FgvDescL = gvDescL;
        my_log(LOG_DEBUG, 0, "createVifs: Starting group specific query for %s from %s", inetFmt(gvDescL->gvDesc->group, 1), gvDescL->gvDesc->sourceVif);
        sendGroupSpecificMemberQuery(gvDescL->gvDesc);
        gvDescL = gvDescL->next;
        free(FgvDescL);   // Alloced by clearRoutes()
    }

    // Set defaultdown to current for next round.
    defaultdown = commonConfig.defaultInterfaceState;
}
