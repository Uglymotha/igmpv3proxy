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
*   igmpproxy.c - The main file for the IGMP proxy application.
*
*   February 2005 - Johnny Egeland, September 2020 - Sietse van Zanen
*/

#include "igmpproxy.h"

static const char Usage[] =
"Usage: igmpproxy [-h | -v] [-c [-cbrift...] [-h]] [[-n | -d] <configfile>]\n"
"\n"
"   -h   Display this help screen\n"
"   -v   Display version.\n"
"   -n   Do not run as a daemon\n"
"   -d   Run in debug mode. Output all messages on stderr. Implies -n.\n"
"   -c   Daemon control and statistics.\n"
"        -c   Reload Configuration.\n"
"        -b   Rebuild Interfaces.\n"
"        -r   Display routing table.\n"
"        -i   Display interface statistics.\n"
"        -f   Display configured filters.\n"
"        -t   Display running timers.\n"
"        -h   Do not display headers.\n"
"\n"
PACKAGE_STRING "\n";

// Local function Prototypes
static void signalHandler(int);
static void igmpProxyInit(void);
static void igmpProxyCleanUp(void);
static void igmpProxyRun(void);

// Global Variables Signal Handling / Timekeeping.
uint8_t               sighandled, sigstatus;
struct timespec       curtime, utcoff;

// Polling and buffering local statics.
static struct pollfd  pollFD[2];
static char          *recv_buf;

/**
*   Program main method. Is invoked when the program is started
*   on commandline. The number of commandline arguments, and a
*   pointer to the arguments are received on the line...
*/
int main(int ArgCn, char *ArgVc[]) {
    int            c, h;

    memset(CONFIG, 0, sizeof(struct Config));
    openlog("igmpproxy", LOG_PID, LOG_USER);
    srand(time(NULL) * getpid());

    // Parse the commandline options and setup basic settings..
    for (c = getopt(ArgCn, ArgVc, "cvdnh"); c != -1; c = getopt(ArgCn, ArgVc, "cvdnh")) {
        switch (c) {
        case 'd':
            CONFIG->log2Stderr = true; // FALLTHRU
        case 'n':
            CONFIG->notAsDaemon = true;
            break;
        case 'h':
            fputs(Usage, stderr);
            exit(0);
        case 'c':
            c = getopt(ArgCn, ArgVc, "cbrifth");
            while (c != -1) {
                char cmd[2] = "";
                h = getopt(ArgCn, ArgVc, "cbrifth");
                switch (c) {
                case 'b':
                case 'c':
                    cliCmd((char *)&c);
                    break;
                case 'f':
                case 'i':
                case 't':
                case 'r':
                    cliCmd(h == 'h' ? strcat(strcat(cmd, (char *)&c), (char *)&h) : (char *)&c);
                }
                c = h == 'h' ? getopt(ArgCn, ArgVc, "riftcvdnh") : h;
                if (c == -1) exit(0);
            }
            cliCmd("cli");
            exit(0);
        case 'v':
            fprintf(stdout, "Igmpproxy %s\n", PACKAGE_VERSION);
            exit(0);
        default:
            exit(-1);
        }
    }

    if (geteuid() != 0) {
        // Check that we are root.
        fprintf(stderr, "igmpproxy: must be root\n");
        exit(-1);
    } else if (optind != ArgCn - 1) {
        fprintf(stdout, "You must specify the configuration file.\n");
        exit(-1);
    } else {
        // Write debug notice with file path.
        CONFIG->configFilePath = ArgVc[optind];
        fprintf(stderr, "Searching for config file at '%s'\n", CONFIG->configFilePath);
    }

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

    sa.sa_handler = signalHandler;
    sa.sa_flags = 0;    /* Interrupt system calls */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGURG, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);

    // Detach daemon from stdin/out/err.
    if (!CONFIG->notAsDaemon && (close(0) < 0 || close(1) < 0 || close(2) < 0
        || open("/dev/null", 0) != 0 || dup2(0, 1) < 0 || dup2(0, 2) < 0
        || setpgid(0, 0) < 0)) {
        myLog(LOG_ERR, errno, "Failed to detach daemon.\n");
    }

    // Load the config file.
    if (! loadConfig())
        myLog(LOG_ERR, 0, "Unable to load configuration file %s.", CONFIG->configFilePath);
    CONFIG->downstreamHostsHashSeed = ((uint32_t)rand() << 16) | (uint32_t)rand();

    // Fork daemon.
    if (!CONFIG->notAsDaemon && fork())
        exit(0);

    // Enable mroute api open cli socket and set pollFD.
    pollFD[0] = (struct pollfd){ k_enableMRouter(), POLLIN, 0 };
    pollFD[1] = (struct pollfd){ openCliSock(), POLLIN, 0 };

    // Initialize IGMP.
    recv_buf = initIgmp();

    // Loads configuration for Physical interfaces and mcast vifs.
    rebuildIfVc(NULL);

    sigstatus = 0;
}

/**
*   Clean up all on exit...
*/
static void igmpProxyCleanUp(void) {
    myLog(LOG_DEBUG, 0, "clean handler called");

    struct IfDesc *IfDp;
    for (GETIFL(IfDp)) ctrlQuerier(0, IfDp);
    timer_freeQueue();      // Free all timeouts.
    clearRoutes(NULL);      // Remove all routes.
    freeIfDescL(false);     // Free IfDesc table.
    freeConfig(0);          // Free config.
    k_disableMRouter();       // Disable the MRouter API.
    if (strstr(CONFIG->runPath, "/igmpproxy/")) {
        char rFile[strlen(CONFIG->runPath) + 14];
        remove(strcat(strcpy(rFile, CONFIG->runPath), "igmpproxy.pid"));
        remove(strcat(strcpy(rFile, CONFIG->runPath), "cli.sock"));
        rmdir(CONFIG->runPath);
    }
    free(CONFIG->logFilePath);
    free(CONFIG->runPath);
}

/**
*   Main daemon event loop.
*/
static void igmpProxyRun(void) {
    while (!(sighandled & GOT_SIGURG)) {
        // Process signaling...
        if (sighandled & GOT_SIGHUP) {
            sigstatus = GOT_SIGHUP;
            myLog(LOG_DEBUG, 0, "SIGHUP: Rebuilding interfaces and reloading config.");
            reloadConfig(NULL);
            sighandled &= ~GOT_SIGHUP;
        } else if (sighandled & GOT_SIGUSR1) {
            sigstatus = GOT_SIGUSR1;
            myLog(LOG_DEBUG, 0, "SIGUSR1: Reloading config.");
            reloadConfig(NULL);
            sighandled &= ~GOT_SIGUSR1;
        } else if (sighandled & GOT_SIGUSR2) {
            sigstatus = GOT_SIGUSR2;
            myLog(LOG_DEBUG, 0, "SIGUSR2: Rebuilding interfaces.");
            rebuildIfVc(NULL);
            sighandled &= ~GOT_SIGUSR2;
        }

        // Run queue aging, it wil return the time until next timer is scheduled.
        struct timespec timeout = timer_ageQueue();

        // Wait for input
        int Rt = ppoll(pollFD, 2, timeout.tv_sec != -1 ? &timeout : NULL, NULL);

        // log and ignore failures
        if (Rt < 0 && errno != EINTR) myLog(LOG_WARNING, errno, "select() failure");
        else if (Rt > 0) {
            // Read IGMP request, and handle it...
            if (pollFD[0].revents & POLLIN) {
                union {
                    struct cmsghdr cmsgHdr;
#ifdef IP_PKTINFO
                    char cmsgData[sizeof(struct msghdr) + sizeof(struct in_pktinfo)];
#elif IP_RECVIF
                    char cmsgData[sizeof(struct msghdr) + sizeof(struct sockaddr_dl)];
#endif
                } cmsgUn;
                struct iovec  ioVec[1] = { { recv_buf, BUF_SIZE } };
                struct msghdr msgHdr = (struct msghdr){ NULL, 0, ioVec, 1, &cmsgUn, sizeof(cmsgUn), MSG_DONTWAIT };

                int recvlen = recvmsg(pollFD[0].fd, &msgHdr, 0);
                if (recvlen < 0 || recvlen < (int)sizeof(struct ip) || (msgHdr.msg_flags & MSG_TRUNC)) myLog(LOG_WARNING, errno, "recvmsg() truncated datagram received.");
                else if ((msgHdr.msg_flags & MSG_CTRUNC)) myLog(LOG_WARNING, errno, "recvmsg() truncated control message received");
                else acceptIgmp(recvlen, msgHdr);
            }

            // Check if any cli connection needs to be handled.
            if (pollFD[1].revents & POLLIN) processCliCon(pollFD[1].fd);
        }
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
        myLog(LOG_NOTICE, 0, "%s: Exiting.", sig == SIGINT ? "SIGINT" : "SIGTERM");
        igmpProxyCleanUp();
        exit(1);
    case SIGURG:
        myLog(LOG_NOTICE, 0, "SIGURG: Trying to restart, memory leaks may occur.");
        sighandled |= GOT_SIGURG;
        return;
    case SIGPIPE:
        myLog(LOG_NOTICE, 0, "SIGPIPE: Ceci n'est pas un SIGPIPE.");
        /* FALLTHRU */
    case SIGHUP:
    case SIGUSR1:
    case SIGUSR2:
        sighandled |= sig == SIGHUP ? GOT_SIGHUP : sig == SIGUSR1 ? GOT_SIGUSR1 : sig == SIGUSR2 ? GOT_SIGUSR2 : 0;
        return;
    }
    myLog(LOG_INFO, 0, "Caught unhandled signal %d", sig);
}
