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
*   igmpv3proxy.c - The main file for the IGMPv3 Proxy application.
*                   September 2020 - February 2022 - Sietse van Zanen
*/

#include "igmpv3proxy.h"

// Local function Prototypes
static void signalHandler(int);
static void igmpProxyInit(void);
static void igmpProxyCleanUp(void);
static void igmpProxyRun(void);

// Global Variables Signal Handling / Timekeeping.
uint8_t               sighandled, sigstatus, logwarning;
struct timespec       curtime, utcoff, starttime;
const char           *fileName;

// Polling and buffering local statics.
static struct pollfd  pollFD[2];
static char          *recv_buf;

/**
*   Program main method. Is invoked when the program is started
*   on commandline. The number of commandline arguments, and a
*   pointer to the arguments are received on the line...
*/
int main(int ArgCn, char *ArgVc[]) {
    int          c = 0, h = 0, i = 0, j = 0;
    uint32_t     addr, mask;
    char        *opts[2] = { NULL, NULL }, cmd[20] = "", *arg = NULL,
                 paths[sizeof(CFG_PATHS)] = CFG_PATHS, *path = NULL, *file;
    struct stat  st;
    fileName = basename(ArgVc[0]);

    // Initialize configuration, syslog and rng.
    memset(CONFIG, 0, sizeof(struct Config));
    openlog(fileName, LOG_PID, LOG_DAEMON);
    CONFIG->logLevel = LOG_WARNING;
    srand(time(NULL) * getpid());

    // Parse the commandline options and setup basic settings..
    for (c = getopt(ArgCn, ArgVc, "cvVdnh"); c != -1; c = getopt(ArgCn, ArgVc, "cvVdnh")) {
        switch (c) {
        case 'v':
            CONFIG->logLevel = LOG_INFO; // FALLTHRU
        case 'd':
            CONFIG->logLevel = CONFIG->logLevel == LOG_WARNING ? LOG_DEBUG : CONFIG->logLevel;
            CONFIG->log2Stderr = true; // FALLTHRU
        case 'n':
            CONFIG->notAsDaemon = true;
            break;
        case 'c':
            c = getopt(ArgCn, ArgVc, "cbr::ifth");
            while (c != -1) {
                switch (c) {
                case 'b':
                case 'c':
                    cliCmd((char *)&c);
                    break;
                case 'f':
                case 'i':
                case 't':
                case 'r':
                    arg = optarg;
                    if (optarg && !parseSubnetAddress(optarg, &addr, &mask)) {
                        arg = NULL;
                        if (i == 0) {
                            j = optind;
                            optind = i = 1;
                            opts[1] = malloc(strlen(optarg) - 1);  // Freed by self.
                            sprintf(opts[1], "-%s", optarg);
                        }
                    }
                    h = getopt(i == 0 ? ArgCn : 2, i == 0 ? ArgVc : opts, "cbr::ifth");
                    if (i == 1 && h == -1) {
                        free(opts[1]);  // Alloced by self.
                        i = 0;
                        optind = j;
                        h = getopt(ArgCn, ArgVc, "cbr::ifth");
                    }
                    strncpy(cmd, (char *)&c, 1);
                    if (h == 'h')
                        strcat(cmd, "h");
                    if (arg)
                        strcat(cmd, arg);
                    cliCmd(cmd);
                    memset(cmd, 0, 20);
                }
                c = h == 'h' ? getopt(i == 0 ? ArgCn : 2, i == 0 ? ArgVc : opts, "cbr::ifth") : h;
                if (c == -1 && i == 1) {
                    free(opts[1]);  // Alloced by self.
                    i = 0;
                    optind = j;
                    c = getopt(ArgCn, ArgVc, "cbr::ifth");
                }
                if (c == -1)
                    exit(0);
            }
            cliCmd("cli");
            exit(0);
        case 'V':
            fprintf(stdout, "Igmpproxy %s\n", PACKAGE_VERSION);
            exit(0);
        default:
            fprintf(stdout, Usage, fileName);
            exit(-1);
        }
    }

    if (geteuid() != 0) {
        // Check that we are root.
        fprintf(stderr, "%s: Must be root.\n", fileName);
        exit(-1);
    } else if (! (CONFIG->configFilePath = calloc(1, sizeof(CFG_PATHS) + strlen(ArgVc[optind - !(optind == ArgCn - 1)])))) {
        // Freed by igmpProxyCleanup().
        exit(-1);
    } else if (optind == ArgCn - 1) {
        // Config file specified as last argument.
       strcpy(CONFIG->configFilePath, ArgVc[optind]);
    } else {
        for (path = strtok(paths, " "); path; path = strtok(NULL, " ")) {
            // Search for config in default locations.
            struct stat st;
            strcpy(CONFIG->configFilePath, path);
            if (stat(strcat(strcat(CONFIG->configFilePath, fileName), ".conf"), &st) == 0)
                break;
            path[strlen(CONFIG->configFilePath) - 5] = '/';
            path[strlen(CONFIG->configFilePath) - 4] = '\0';
            if (stat(strcat(strcat(CONFIG->configFilePath, fileName), ".conf"), &st) == 0)
                break;
        }
        CONFIG->configFilePath = NULL;
    }
    if (! CONFIG->configFilePath || stat(CONFIG->configFilePath, &st) != 0 || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)))
        LOG(LOG_ERR, 0, "No config file specified nor found in '%s'.", CFG_PATHS);

    do {
        sighandled = sigstatus = 0;

        // Initializes the deamon.
        igmpProxyInit();

        // Go to the main loop.
        igmpProxyRun();

        // Clean up
        igmpProxyCleanUp();

    // If a SIGURG was caught try to restart.
    } while (sighandled & GOT_SIGURG);
}

/**
*   Handles the initial startup of the daemon.
*/
static void igmpProxyInit(void) {
    struct sigaction sa;
    sigstatus = 1;  // STARTUP

    clock_gettime(CLOCK_REALTIME, &starttime);
    char tS[32] = "", *t = asctime(localtime(&starttime.tv_sec));
    memcpy(tS, t, strlen(t) - 1);
    tS[strlen(t) - 1] = '\0';
    LOG(LOG_WARNING, 0, "Initializing IGMPv3 Proxy on %s.", tS);

    sa.sa_handler = signalHandler;
    sa.sa_flags = 0;                // Interrupt system calls
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGURG,  &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);

    // Detach daemon from stdin/out/err, and fork.
    int f = -1;
    if (!CONFIG->notAsDaemon && (close(0) < 0 || close(1) < 0 || close(2) < 0 || open("/dev/null", 0) != 0
         || dup2(0, 1) < 0 || dup2(0, 2) < 0 || setpgid(0, 0) < 0 || (f = fork()) != 0))
        f < 0 ? LOG(LOG_ERR, errno, "Failed to detach daemon.\n") : exit(0);

    // Load the config file.
    if (!loadConfig(CONFIG->configFilePath))
        LOG(LOG_ERR, 0, "Failed to load configuration from '%s'.", CONFIG->configFilePath);
    LOG(LOG_WARNING, 0, "Loaded configuration from '%s'. Starting IGMPv3 Proxy.", CONFIG->configFilePath);
    CONFIG->hashSeed = ((uint32_t)rand() << 16) | (uint32_t)rand();

    // Enable mroute api open cli socket and set pollFD.
    pollFD[0] = (struct pollfd){ k_enableMRouter(), POLLIN, 0 };
    pollFD[1] = (struct pollfd){ openCliSock(), POLLIN, 0 };

    // Initialize IGMP.
    recv_buf = initIgmp();

    // Loads configuration for Physical interfaces and mcast vifs.
    rebuildIfVc(NULL);
}

/**
*   Clean up all on exit...
*/
static void igmpProxyCleanUp(void) {
    struct timespec endtime;
    sigstatus = 0x20;         // Shutdown

    rebuildIfVc(NULL);        // Shutdown all interfaces, queriers and remove all routes.
    k_disableMRouter();
    if (pollFD[1].fd > 0)
        close(pollFD[1].fd);
    if (CONFIG->runPath) {
        // Remove socket and PID file.
        char rFile[strlen(CONFIG->runPath) + strlen(fileName) + 3];
        sprintf(rFile, "%s/%s.pid", CONFIG->runPath, fileName);
        remove(rFile);
        sprintf(rFile, "%s/cli.sock", CONFIG->runPath);
        remove(rFile);
        rmdir(CONFIG->runPath);
    }
    freeConfig(0);

    clock_gettime(CLOCK_REALTIME, &endtime);
    char tS[32] = "", tE[32] = "", *t = asctime(localtime(&starttime.tv_sec));
    memcpy(tS, t, strlen(t) - 1);
    t = asctime(localtime(&endtime.tv_sec));
    memcpy(tE, t, strlen(t) - 1);
    tS[strlen(t) - 1] = '\0', tE[strlen(t) - 1] = '\0';
    LOG(LOG_WARNING, 0, "Shutting down on %s. Running since %s (%ds).", tE, tS, timeDiff(starttime, endtime).tv_sec);

    free(recv_buf);                // Alloced by initIgmp()
    free(CONFIG->logFilePath);     // Alloced by loadConfig()
    free(CONFIG->runPath);         // Alloced by openCliSock()
    free(CONFIG->configFilePath);  // Alloced by main()
}

/**
*   Main daemon event loop.
*/
static void igmpProxyRun(void) {
    struct timespec timeout;
    int    i = 0, Rt = 0;
    sigstatus = 0;

    while (!(sighandled & GOT_SIGURG)) {
        // Process signaling...
        if (sighandled & GOT_SIGHUP) {
            sigstatus = GOT_SIGHUP;
            LOG(LOG_DEBUG, 0, "SIGHUP: Rebuilding interfaces and reloading config.");
            reloadConfig(NULL);
            sighandled &= ~GOT_SIGHUP;
        } else if (sighandled & GOT_SIGUSR1) {
            sigstatus = GOT_SIGUSR1;
            LOG(LOG_DEBUG, 0, "SIGUSR1: Reloading config.");
            reloadConfig(NULL);
            sighandled &= ~GOT_SIGUSR1;
        } else if (sighandled & GOT_SIGUSR2) {
            sigstatus = GOT_SIGUSR2;
            LOG(LOG_DEBUG, 0, "SIGUSR2: Rebuilding interfaces.");
            rebuildIfVc(NULL);
            sighandled &= ~GOT_SIGUSR2;
        }

        if (Rt <= 0 || i >= CONFIG->reqQsz) {
            const struct timespec nto = { 0, 0 };
            // Run queue aging, it wil return the time until next timer is scheduled.
            timeout = timer_ageQueue();
            // Wait for input, indefinitely if no next timer, do not wait if next timer has already expired.
            Rt = ppoll(pollFD, 2, timeout.tv_sec == -1 ? NULL : timeout.tv_nsec == -1 ? &nto : &timeout, NULL);
            i = 0;
        }

        // log and ignore failures
        const struct timespec nto = { 0, 0 };
        if (Rt < 0 && errno != EINTR)
            LOG(LOG_WARNING, errno, "ppoll() error");
        else if (Rt > 0) do {
            // Read IGMP request, and handle it...
            if (pollFD[0].revents & POLLIN) {
                LOG(LOG_DEBUG, 0, "igmpProxyRun: RECV Queued Packet %d.", i+1);
                union  cmsgU  cmsgUn;
                struct iovec  ioVec[1] = { { recv_buf, CONFIG->pBufsz } };
                struct msghdr msgHdr = (struct msghdr){ NULL, 0, ioVec, 1, &cmsgUn, sizeof(cmsgUn), MSG_DONTWAIT };

                int recvlen = recvmsg(pollFD[0].fd, &msgHdr, 0);
                if (recvlen < 0 || recvlen < (int)sizeof(struct ip) || (msgHdr.msg_flags & MSG_TRUNC))
                    LOG(LOG_WARNING, errno, "recvmsg() truncated datagram received.");
                else if ((msgHdr.msg_flags & MSG_CTRUNC))
                    LOG(LOG_WARNING, errno, "recvmsg() truncated control message received");
                else
                    acceptIgmp(recvlen, msgHdr);
            }

            // Check if any cli connection needs to be handled.
            if (pollFD[1].revents & POLLIN) {
                LOG(LOG_DEBUG, 0, "igmpProxyRun: RECV Cli Connection %d.", i+1);
                processCliCon(pollFD[1].fd);
            }
        } while (i++ < CONFIG->reqQsz && (Rt = ppoll(pollFD, 2, &nto, NULL)) > 0 && !sighandled);
    }
}

/**
*   Signal handler.  Take note of the fact that the signal arrived so that the main loop can take care of it.
*/
static void signalHandler(int sig) {
    switch (sig) {
    case SIGINT:
        if (!CONFIG->notAsDaemon) return;  // Daemon ignores SIGINT
        /* FALLTHRU */
    case SIGTERM:
        LOG(LOG_NOTICE, 0, "%s: Exiting.", sig == SIGINT ? "SIGINT" : "SIGTERM");
        igmpProxyCleanUp();
        exit(1);
    case SIGURG:
        LOG(LOG_NOTICE, 0, "SIGURG: Trying to restart, memory leaks may occur.");
        sighandled |= GOT_SIGURG;
        return;
    case SIGPIPE:
        LOG(LOG_NOTICE, 0, "SIGPIPE: Ceci n'est pas un SIGPIPE.");
        /* FALLTHRU */
    case SIGHUP:
    case SIGUSR1:
    case SIGUSR2:
        sighandled |= sig == SIGHUP ? GOT_SIGHUP : sig == SIGUSR1 ? GOT_SIGUSR1 : sig == SIGUSR2 ? GOT_SIGUSR2 : 0;
        return;
    }
    LOG(LOG_NOTICE, 0, "Caught unhandled signal %d", sig);
}
