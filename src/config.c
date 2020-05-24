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
*   config.c - Contains functions to load and parse config
*              file, and functions to configure the daemon.
*/

#include "igmpproxy.h"

// Structure to keep configuration for VIFs...
struct vifconfig {
    char*               name;
    short               state;
    int                 ratelimit;
    int                 threshold;

    // Keep allowed nets for VIF.
    struct SubnetList*  allowednets;
    struct SubnetList*  deniednets;

    // Allowed Groups
    struct SubnetList*  allowedgroups;
    struct SubnetList*  deniedgroups;

    // Next config in list...
    struct vifconfig*   next;
};

// Structures to keep vif configuration and black/whitelists.
struct vifconfig *vifconf;
struct SubnetList **anetPtr, **dnetPtr, **agrpPtr, **dgrpPtr;

// Keeps common settings...
static struct Config commonConfig;

// Prototypes...
struct vifconfig *parsePhyintToken(void);
int parseSubnetAddress(char *addrstr, uint32_t *addr, uint32_t *mask);
void allocSubnet(char *list, uint32_t addr, uint32_t mask);

/**
*   Initializes common config..
*/
static void initCommonConfig(void) {
    commonConfig.robustnessValue = DEFAULT_ROBUSTNESS;
    commonConfig.queryInterval = INTERVAL_QUERY;
    commonConfig.queryResponseInterval = INTERVAL_QUERY_RESPONSE;

    // The defaults are calculated from other settings.
    commonConfig.startupQueryInterval = (unsigned int)(INTERVAL_QUERY / 4);
    commonConfig.startupQueryCount = DEFAULT_ROBUSTNESS;

    // Default values for leave intervals...
    commonConfig.lastMemberQueryInterval = INTERVAL_QUERY_RESPONSE;
    commonConfig.lastMemberQueryCount    = DEFAULT_ROBUSTNESS;

    // If 1, a leave message is sent upstream on leave messages from downstream.
    commonConfig.fastUpstreamLeave = 0;

    // Default size of hash table is 32 bytes (= 256 bits) and can store
    // up to the 256 non-collision hosts, approximately half of /24 subnet
    commonConfig.downstreamHostsHashTableSize = 32;

    // aimwang: default value
    commonConfig.defaultInterfaceState = IF_STATE_DISABLED;
    commonConfig.rescanVif  = 0;
    commonConfig.rescanConf = 0;
    commonConfig.proxyLocalMc = 0;
}

/**
*   Returns a pointer to the common config...
*/
struct Config *getCommonConfig(void) {
    return &commonConfig;
}

// Reloads the configuration file and removes interfaces which were removed from config.
void reloadConfig(void) {
    sighandled |= GOT_SIGHUP;
    struct vifconfig *OldConfPtr, *TmpConfPtr;

    // Load the new configuration keep reference to the old.
    OldConfPtr = vifconf;
    if (! loadConfig(configFilePath)) {
        my_log(LOG_ERR, 0, "reloadConfig: Unable to load config file.");
    }

    // Rebuild the interfaces config.
    rebuildIfVc();

    // Free all the old mallocd vifconf list.
    for (TmpConfPtr = OldConfPtr->next; OldConfPtr; OldConfPtr = TmpConfPtr, TmpConfPtr = OldConfPtr->next) {
        free (OldConfPtr);   // Alloced by parsePhyintToken()
    }
    
    my_log(LOG_DEBUG, 0, "reloadConfig: Config Reloaded. OldConfPtr %x, NewConfPtr, %x", OldConfPtr, vifconf);
    sighandled &= ~GOT_SIGHUP;
}

/**
*   Loads the configuration from file, and stores the config in
*   respective holders...
*/
int loadConfig(char *configFile) {
    struct vifconfig  *tmpPtr;
    struct vifconfig  **currPtr = &vifconf;
    char *token;

    // Initialize common config
    initCommonConfig();

    // Test config file reader...
    if (!openConfigFile(configFile)) {
        my_log(LOG_ERR, 0, "Unable to open configfile from %s", configFile);
    }

    // Get first token...
    token = nextConfigToken();
    if (! token) {
        my_log(LOG_ERR, 0, "Config file was empty.");
    }

    // Loop until all configuration is read.
    while (token) {
        // Check token...
        if (strcmp("phyint", token) == 0) {
            // Got a phyint token... Call phyint parser
            my_log(LOG_DEBUG, 0, "Config: Got a phyint token.");
            tmpPtr = parsePhyintToken();
            if (! tmpPtr) {
                // Unparsable token... Exit...
                closeConfigFile();
                my_log(LOG_WARNING, 0, "Unknown token '%s' in configfile", token);
                return 0;
            } else {

                my_log(LOG_DEBUG, 0, "IF name : %s", tmpPtr->name);
                my_log(LOG_DEBUG, 0, "Next ptr : %x", tmpPtr->next);
                my_log(LOG_DEBUG, 0, "Ratelimit : %d", tmpPtr->ratelimit);
                my_log(LOG_DEBUG, 0, "Threshold : %d", tmpPtr->threshold);
                my_log(LOG_DEBUG, 0, "State : %d", tmpPtr->state);
                my_log(LOG_DEBUG, 0, "Net ptrs : %x, %x, %x, %x", tmpPtr->allowednets, tmpPtr->deniednets, tmpPtr->allowedgroups, tmpPtr->deniedgroups);

                // Insert config, and move temppointer to next location...
                *currPtr = tmpPtr;
                currPtr = &tmpPtr->next;
            }
        }
        else if (strcmp("quickleave", token) == 0) {
            // Got a quickleave token....
            my_log(LOG_DEBUG, 0, "Config: Quick leave mode enabled.");
            commonConfig.fastUpstreamLeave = 1;

            // Read next token...
            token = nextConfigToken();
            continue;
        }
        else if (strcmp("hashtablesize", token) == 0) {
            // Got a hashtablesize token...
            token = nextConfigToken();
            my_log(LOG_DEBUG, 0, "Config: hashtablesize for quickleave is %s.", token);
            if (! commonConfig.fastUpstreamLeave) {
                closeConfigFile();
                my_log(LOG_ERR, 0, "Config: hashtablesize is specified but quickleave not enabled.");
                return 0;
            }
            int intToken = atoi(token);
            if (intToken < 1 || intToken > 536870912) {
                closeConfigFile();
                my_log(LOG_ERR, 0, "Config: hashtablesize must be between 1 and 536870912 bytes.");
                return 0;
            }
            commonConfig.downstreamHostsHashTableSize = intToken;

            // Read next token...
            token = nextConfigToken();
            continue;
        }
        else if (strcmp("defaultdown", token) == 0) {
            // Got a defaultdown token...
            my_log(LOG_DEBUG, 0, "Config: interface Default as down stream.");
            commonConfig.defaultInterfaceState = IF_STATE_DOWNSTREAM;

            // Read next token...
            token = nextConfigToken();
            continue;
        }
        else if (strcmp("rescanvif", token) == 0) {
            // Got a rescanvif token...
            token = nextConfigToken();
            int intToken = atoi(token);
            if (intToken != 0) {
                if (intToken < INTERVAL_QUERY_RESPONSE + 1) {
                    intToken = INTERVAL_QUERY_RESPONSE + 1;
                }
                my_log(LOG_DEBUG, 0, "Config: Need detect new interface every %ds.", intToken);
            }
            commonConfig.rescanVif = intToken;

            // Read next token...
            token = nextConfigToken();
            continue;
        }
        else if (strcmp("rescanconf", token) == 0) {
            // Got a rescanconf token...
            token = nextConfigToken();
            int intToken = atoi(token);
            if (intToken != 0) {
                if (intToken < INTERVAL_QUERY_RESPONSE + 1) {
                    intToken = INTERVAL_QUERY_RESPONSE + 1;
                }
                my_log(LOG_DEBUG, 0, "Config: Need detect config change every %ds.", intToken);
            }
            commonConfig.rescanConf = intToken;

            // Read next token...
            token = nextConfigToken();
            continue;
        }
        else if (strcmp("loglevel", token) == 0) {
            // Got a loglevel token...
            token = nextConfigToken();
            int intToken = atoi(token);
            if (intToken < 0 || intToken > 7) {
                my_log(LOG_ERR, 0, "Config: Loglevel must be 0 - 7");
            } else {
                LogLevel = intToken;
                my_log(LOG_DEBUG, 0, "Config: LogLevel %d", LogLevel);
            }

            // Read next token...
            token = nextConfigToken();
            continue;
        }
        else if (strcmp("proxylocalmc", token) == 0) {
            // Got a proxylocalmc token....
            my_log(LOG_DEBUG, 0, "Config: Will forward local multicast range 224.0.0.0/8.");
            commonConfig.proxyLocalMc = 1;

            // Read next token...
            token = nextConfigToken();
            continue;
        } else {
            // Unparsable token... Exit...
            closeConfigFile();
            my_log(LOG_WARNING, 0, "Unknown token '%s' in configfile", token);
            return 0;
        }
        // Get token that was not recognized by phyint parser.
        token = getCurrentConfigToken();
    }

    // Close the configfile...
    closeConfigFile();

    return 1;
}

/**
*   Appends extra VIF configuration from config file.
*/
void configureVifs(void) {
    unsigned Ix;
    struct IfDesc *Dp;
    struct vifconfig *confPtr;

    // If no config is available, just return...
    if (! vifconf) {
        return;
    }

    // Loop through all VIFs...
    for (Ix = 0; (Dp = getIfByIx(Ix, NULL)); Ix++) {
        if (Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) ) {

            // Now try to find a matching config...
            for (confPtr = vifconf; confPtr; confPtr = confPtr->next) {

                // I the VIF names match...
                if (strcmp(Dp->Name, confPtr->name)==0) {
                    struct SubnetList *vifLast;

                    my_log(LOG_DEBUG, 0, "Found config for %s", Dp->Name);

                    // Set the VIF state
                    Dp->state = confPtr->state;

                    Dp->threshold = confPtr->threshold;
                    Dp->ratelimit = confPtr->ratelimit;

                    // Go to last allowed net on VIF...
                    for(vifLast = Dp->allowednets; vifLast->next; vifLast = vifLast->next);

                    // Insert the configured nets...
                    vifLast->next = confPtr->allowednets;

                    // Link the black- and whitelists.
                    Dp->deniednets = confPtr->deniednets;
                    Dp->allowedgroups = confPtr->allowedgroups;
                    Dp->deniedgroups = confPtr->deniedgroups;

                    break;
                }
            }
        }
    }
}

/* create VIFs for all IP, non-loop interfaces.
   When argument is not NULL rebuild the interface table.
*/
void createVifs(struct IfDescP *RebuildP) {
    struct IfDesc *Dp, *oDp = NULL;
    int    vifcount = 0, upsvifcount = 0, Ix = 0;
    struct gvDescL *gvDescL = NULL, *TmpgvDescL = NULL, *AddgvDescL = NULL;

    if (RebuildP) {
        // When rebuild, check if interfaces have dissapeared and call delVIF if necessary.
        for (oDp=RebuildP->S; oDp<RebuildP->E; oDp++) {
            if (! (Dp = getIfByName(oDp->Name, NULL))) {
                my_log(LOG_DEBUG, 0, "Interface %s disappeared from system", oDp->Name);
                if (oDp->index != (unsigned int)-1) {
                    AddgvDescL = clearRoutes(oDp, RebuildP);
                    // For any dissappaerd downstream vif we may have a list of groups to be queried after we are done.
                    if (AddgvDescL) {
                        if (! gvDescL) {
                            gvDescL = AddgvDescL;
                        } else {
                            for (TmpgvDescL = gvDescL; TmpgvDescL && TmpgvDescL->next; TmpgvDescL = TmpgvDescL->next);
                            TmpgvDescL->next = AddgvDescL;
                        }
                    }
                    delVIF(oDp);
                }
            }
        }
    }

    // Loop through all new interfaces and check what has changed.
    for (Ix = 0; (Dp = getIfByIx(Ix, NULL)); Ix++) {
        AddgvDescL = NULL;
        if (! RebuildP && ((Dp->Flags & IFF_LOOPBACK) || Dp->state == IF_STATE_DISABLED)) {
            // Only add vif for valid interfaces on start-up.
            continue;
        } else if ((oDp = getIfByName(Dp->Name, RebuildP))) {
            /* Need rebuild, check if interface is new or already exists (check table below).
                             old: disabled    new: disabled    -> do nothing
                             old: disabled    new: downstream  -> addVIF(new)
                             old: disabled    new: upstream    -> clear routes new vif   ,addVIF(new)                              ,query groups
                             old: downstream  new: disabled    -> clear routes old vif   ,delVIF(old)                              ,query groups
               state table   old: downstream  new: downstream  ->                                                 addvif(new,old)
                             old: downstream  new: upstream    -> clear routes old vif   ,delvif(old)            ,addvif(new)      ,query groups
                             old: upstream    new: disabled    -> clear routes old vif   ,delVIF(old)                              ,query groups
                             old: upstream    new: downstream  -> clear routes old vif   ,delvif(old)            ,addvif(new)      ,query groups
                             old: upstream    new: upstream    -> On config reload, check routes for wl changes  ,addvif(new,old)  ,query groups
            */
            if (oDp->state != IF_STATE_UPSTREAM && Dp->state == IF_STATE_UPSTREAM) {
                // If vif transitions to upstream set relevant routes to not joined.                               
                clearRoutes(Dp, NULL);
            }

            switch (oDp->state) {
            case IF_STATE_DISABLED:
                switch (Dp->state) {
                case IF_STATE_DISABLED:   {                                                                              continue; }
                case IF_STATE_DOWNSTREAM: {                                                         oDp=NULL;            break; }
                case IF_STATE_UPSTREAM:   { AddgvDescL = clearRoutes(Dp, NULL);                     oDp=NULL;            break; }
                }
                break;
            case IF_STATE_DOWNSTREAM:
                switch (Dp->state) {
                case IF_STATE_DISABLED:   { AddgvDescL = clearRoutes(oDp, RebuildP);  delVIF(oDp);                       break; }
                case IF_STATE_DOWNSTREAM: {                                                                              break; }
                case IF_STATE_UPSTREAM:   { AddgvDescL = clearRoutes(oDp, RebuildP);  delVIF(oDp);  oDp=NULL;            break; }
                }
                break;
            case IF_STATE_UPSTREAM:
                switch (Dp->state) {
                case IF_STATE_DISABLED:   { AddgvDescL = clearRoutes(oDp, RebuildP);  delVIF(oDp);                       continue; }
                case IF_STATE_DOWNSTREAM: { AddgvDescL = clearRoutes(oDp, RebuildP);  delVIF(oDp);  oDp=NULL;            break; }
                case IF_STATE_UPSTREAM:   { AddgvDescL = (sighandled & GOT_SIGHUP) ? clearRoutes(oDp, RebuildP) : NULL;  break; }
                }
                break;
            }

            // For any removed downstream vif we may have a list of groups to be queried after we are done.
            if (AddgvDescL && ! gvDescL) {
                gvDescL = AddgvDescL;
            } else if (AddgvDescL && gvDescL) {
                for (TmpgvDescL = gvDescL; TmpgvDescL && TmpgvDescL->next; TmpgvDescL = TmpgvDescL->next);
                TmpgvDescL->next = AddgvDescL;
            }

            // Do not call addvif for loopback or interface switched from downstream to disabled.
            if ((Dp->Flags & IFF_LOOPBACK) || (oDp && oDp->state == IF_STATE_DOWNSTREAM && Dp->state == IF_STATE_DISABLED)) {
                continue;
            }
        } else {
            // New Interface. Only add valid up/downstream vif.
            if ((Dp->Flags & IFF_LOOPBACK) || (Dp->state != IF_STATE_DOWNSTREAM && Dp->state != IF_STATE_UPSTREAM)) {
                continue;
            }
            if (Dp->state == IF_STATE_UPSTREAM) {
                // Join all relevant routes.
                clearRoutes(Dp, NULL);
            }
            oDp=NULL;
        }
        if(Dp->state == IF_STATE_UPSTREAM) {
            if (upsvifcount >= MAX_UPS_VIFS) {
                my_log(LOG_ERR, 0, "Cannot set VIF #%d as upstream as well. Max upstream Vif count is %d",
                Ix, MAX_UPS_VIFS);
            } else {
                my_log(LOG_DEBUG, 0, "Found upstream IF #%d, will assign as upstream Vif %d", upsvifcount, Ix);
                upsvifcount++;
            }
        }
        addVIF(Dp, oDp);
        vifcount++;
    }

    // All vifs created, check if there is an upstream and at least one downstream.
    if (upsvifcount == 0 || vifcount == upsvifcount) {
        my_log(LOG_ERR, 0, "There must be at least 1 Vif as upstream and 1 as dowstream.");
    }

    // If we have a lists of groups that have been set to check last member start the group specific querier.
    while (gvDescL) {
        struct gvDescL *FgvDescL = gvDescL;

        my_log(LOG_DEBUG, 0, "createVifs: Starting group specific query for %s", inetFmt(gvDescL->gvDesc->group,s1));
        sendGroupSpecificMemberQuery(gvDescL->gvDesc);

        // The list may have duplicates, remove them
        for (TmpgvDescL = gvDescL; TmpgvDescL && TmpgvDescL->next; TmpgvDescL = TmpgvDescL->next) {
            if (TmpgvDescL->next->gvDesc->sourceVif == gvDescL->gvDesc->sourceVif && TmpgvDescL->next->gvDesc->group == gvDescL->gvDesc->group) {
                TmpgvDescL->next = TmpgvDescL->next->next;
                free(TmpgvDescL->next->gvDesc);  // Alloced by clearRoutes()
                free(TmpgvDescL->next);          // Alloced by clearRoutes()
            }
        }
        gvDescL = gvDescL->next;
        free(FgvDescL);   // Alloced by clearRoutes()
    }
}

/**
*   Internal function to parse phyint config
*/
struct vifconfig *parsePhyintToken(void) {
    struct vifconfig  *tmpPtr;
    char *token;
    short parseError = 0;

    // First token should be the interface name....
    token = nextConfigToken();

    // Sanitycheck the name...
    if (! token || strlen(token) >= IF_NAMESIZE) {
        return NULL;
    }
    my_log(LOG_DEBUG, 0, "Config: IF: Config for interface %s.", token);

    // Allocate memory for configuration. Freed by reloadConfig().
    tmpPtr = (struct vifconfig*)malloc(sizeof(struct vifconfig));
    if (! tmpPtr) {
        my_log(LOG_ERR, 0, "vifconfig: Out of memory.");
    }

    // Set default values...
    tmpPtr->next = NULL;    // Important to avoid seg fault...
    tmpPtr->ratelimit = 0;
    tmpPtr->threshold = 1;
    tmpPtr->state = commonConfig.defaultInterfaceState;
    tmpPtr->allowednets = NULL;
    tmpPtr->deniednets = NULL;
    tmpPtr->allowedgroups = NULL;
    tmpPtr->deniedgroups = NULL;

    // Make a copy of the token to store the IF name
    tmpPtr->name = strdup(token);
    if (! tmpPtr->name) {
        my_log(LOG_ERR, 0, "Out of memory.");
    }

    // Set pointer to pointer to subnetlist structs.
    anetPtr = &tmpPtr->allowednets;
    dnetPtr = &tmpPtr->deniednets;
    agrpPtr = &tmpPtr->allowedgroups;
    dgrpPtr = &tmpPtr->deniedgroups;

    // Parse the rest of the config..
    token = nextConfigToken();
    while (token) {
        if (strcmp("altnet", token) == 0 || strcmp("allowednet", token) == 0 || strcmp("deniednet", token) == 0
                                         || strcmp("whitelist", token) == 0  || strcmp("blacklist", token) == 0) {
            // Black / Whitelist Parsing...
            uint32_t addr, mask;
            char list[255], tmptoken[255];
            strcpy(list, token);
            for (token = nextConfigToken(), strcpy(tmptoken, token); (parseSubnetAddress(token, &addr, &mask)); token = nextConfigToken(), strcpy(tmptoken, token)) {
                my_log(LOG_DEBUG, 0, "Config: IF: Got %s token %s.", list, tmptoken);
                if ((addr | mask) != mask) {
                    my_log(LOG_WARNING, 0, "Config: IF: %s is not valid subnet/mask pair. Ignoring.", tmptoken);
                } else {
                    allocSubnet(list, addr, mask);
                }
            }
            continue;
        }
        else if (strcmp("upstream", token) == 0) {
            // Upstream
            my_log(LOG_DEBUG, 0, "Config: IF: Got upstream token.");
            tmpPtr->state = IF_STATE_UPSTREAM;
        }
        else if (strcmp("downstream", token) == 0) {
            // Downstream
            my_log(LOG_DEBUG, 0, "Config: IF: Got downstream token.");
            tmpPtr->state = IF_STATE_DOWNSTREAM;
        }
        else if (strcmp("disabled", token) == 0) {
            // Disabled
            my_log(LOG_DEBUG, 0, "Config: IF: Got disabled token.");
            tmpPtr->state = IF_STATE_DISABLED;
        }
        else if (strcmp("ratelimit", token) == 0) {
            // Ratelimit
            token = nextConfigToken();
            my_log(LOG_DEBUG, 0, "Config: IF: Got ratelimit token '%s'.", token);
            tmpPtr->ratelimit = atoi(token);
            if (tmpPtr->ratelimit < 0) {
                my_log(LOG_WARNING, 0, "Ratelimit must be 0 or more.");
                parseError = 1;
                break;
            }
        }
        else if (strcmp("threshold", token) == 0) {
            // Threshold
            token = nextConfigToken();
            my_log(LOG_DEBUG, 0, "Config: IF: Got threshold token '%s'.", token);
            tmpPtr->threshold = atoi(token);
            if (tmpPtr->threshold <= 0 || tmpPtr->threshold > 255) {
                my_log(LOG_WARNING, 0, "Threshold must be between 1 and 255.");
                parseError = 1;
                break;
            }
        }
        else {
            // Unknown token. Break...
            break;
        }
        token = nextConfigToken();
    }

    // Clean up after a parseerror...
    if (parseError) {
        free(tmpPtr->name);   // Alloced by self
        free(tmpPtr);         // Alloced by self
        tmpPtr = NULL;
    }

    return tmpPtr;
}

/**
*   Parses a subnet address string on the format
*   a.b.c.d/n into a SubnetList entry.
*/
int parseSubnetAddress(char *addrstr, uint32_t *addr, uint32_t *mask) {
    char                *tmpStr;

    // First get the network part of the address...
    tmpStr = strtok(addrstr, "/");
    *addr = inet_addr(tmpStr);
    if(*addr == (uint32_t)-1) {
        return 0;
    }

    // Next parse the subnet mask.
    tmpStr = strtok(NULL, "/");
    if(tmpStr != NULL) {
        int bitcnt = atoi(tmpStr);
        if(bitcnt < 0 || bitcnt > 32) {
            return 0;
        }
        if (bitcnt == 0)
            *mask = 0;
        else
            *mask = ntohl(0xFFFFFFFF << (32 - bitcnt));
    }

    return 1;
}

// Allocate and set the subnetlist for the requested list.
void allocSubnet(char *list, uint32_t addr, uint32_t mask) {
    struct SubnetList ***tmpSubnet = (strcmp("altnet", list) == 0)      ? &anetPtr :
                                     (strcmp("allowednet", list) == 0)  ? &anetPtr :
                                     (strcmp("deniednet", list) == 0)   ? &dnetPtr :
                                     (strcmp("whitelist", list) == 0)   ? &agrpPtr :
                                                                          &dgrpPtr;

    // Allocate memory for subnet list. Freed by rebuildIfvc().
    **tmpSubnet = (struct SubnetList*)malloc(sizeof(struct SubnetList));
    if (! **tmpSubnet) {
        my_log(LOG_ERR, 0, "allocSubnet: Out of Memory.");
    }
    (***tmpSubnet).subnet_addr = addr;
    (***tmpSubnet).subnet_mask = mask;
    (***tmpSubnet).next = NULL;

    my_log(LOG_DEBUG, 0, "Config: IF: Parsed subnet to %s.", inetFmts((***tmpSubnet).subnet_addr, (***tmpSubnet).subnet_mask,s1));

    *tmpSubnet = &(**tmpSubnet)->next;
}
