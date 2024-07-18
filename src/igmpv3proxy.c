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
*   igmpv3proxy.c - The main file for the IGMPv3 Proxy application.
*                   September 2020 - February 2022 - Sietse van Zanen
*/

#include "igmpv3proxy.h"

// Local function Prototypes
static void signalHandler(int sig, siginfo_t* siginfo, void* context);
static void igmpProxyInit(void);
static void igmpProxyMonitor(void);
static void igmpProxyRun(void);

// Global Variables Memory / Signal Handling / Timekeeping / Buffers etc.
volatile sig_atomic_t sighandled;  // Should be as private as possible.
uint8_t               sigstatus, logwarning;
struct timespec       curtime, utcoff, starttime;
char                 *rcv_buf = NULL, *fileName, tS[32], tE[32], RUNPATH[] = RUN_PATHS, CFGPATH[] = CFG_PATHS;
struct memstats       memuse = { 0 }, memalloc = { 0 }, memfree = { 0 };
static struct pollfd  pollFD[2] = { {-1, POLLIN, 0}, {-1, POLLIN, 0} };
const struct timespec nto = { 0, 0 };
#ifdef __linux__
int                   mrt_tbl = -1;
struct chld           chld = { 0 };
#endif

/**
*   Program main method. Is invoked when the program is started
*   on commandline. The number of commandline arguments, and a
*   pointer to the arguments are received on the line...
*/
int main(int ArgCn, char *ArgVc[]) {
    int          c = 0, i = 0, j = 0, tbl = 0;
    char        *opts[2] = { ArgVc[0], NULL }, cmd[20] = "", *path = NULL;
    struct stat  st;
    fileName = basename(ArgVc[0]);

    // Initialize configuration, syslog and rng.
    memset(CONF,    0, sizeof(struct Config));
    memset(OLDCONF, 0, sizeof(struct Config));
    openlog(fileName, LOG_PID, LOG_DAEMON);
    srand(time(NULL) * getpid());
    CONF->hashSeed = ((uint32_t)rand() << 16) | (uint32_t)rand();
    CONF->logLevel = LOG_WARNING;

    // Parse the commandline options and setup basic settings..
    for (c = getopt(ArgCn, ArgVc, "cvVdnht:"); c != -1; c = getopt(ArgCn, ArgVc, "cvVdnht:")) {
        switch (c) {
        case 'v':
            if (CONF->logLevel == LOG_WARNING)
                CONF->logLevel = LOG_NOTICE;
            else
                CONF->logLevel = LOG_INFO; // FALLTHRU
        case 'd':
            CONF->logLevel = CONF->logLevel == LOG_WARNING ? LOG_DEBUG : CONF->logLevel;
            CONF->log2Stderr = true; // FALLTHRU
        case 'n':
            CONF->notAsDaemon = true;
            break;
        case 't':
#ifdef __linux__
            tbl = atoll(optarg);
            break;
#else
            fprintf(stderr, "Only linux supports multiple tables.\n");
            exit(1);
#endif
        case 'c':
            c = getopt(ArgCn, ArgVc, "cbr::i::mf::th");
            while (c != -1 && c != '?') {
                uint32_t addr, mask, h = 0;
                memset(cmd, 0, sizeof(cmd));
                cmd[0] = c;
                if (c != 'r' && c != 'i' && c!= 'f' && (h = getopt(j ? 2 : ArgCn, j ? opts : ArgVc, "cbr::i::mf::th")) == 'h')
                    strcat(cmd, "h");
                else if (h == '?')
                    break;
                else if ((c == 'r' || c == 'i' || c == 'f') && optarg) {
                    if (optarg[0] == 'h') {
                        strcat(cmd, "h");
                        optarg++;
                        h = 'h';
                    }
                    if (strlen(optarg) > 0) {
                        if (c == 'r' && !parseSubnetAddress(optarg, &addr, &mask)) {
                            i = optind, j = optind = 1;
                            if (! (opts[1] = malloc(strlen(optarg) + 1))) {  // Freed by Self
                                fprintf(stderr, "Out of Memory!");
                                exit(-1);
                            }
                            sprintf(opts[1], "-%s", optarg);
                        } else if (c == 'r' && !IN_MULTICAST(ntohl(addr))) {
                            fprintf(stderr, "Ignoring %s, not a valid multicast subnet/mask pair.\n", optarg);
                        } else
                            strcat(strcat(cmd, " "), optarg);
                    }
                }
                cliCmd(cmd, tbl);
                c = (h == 'h' || c == 'r' || c == 'i' || c == 'f') ? getopt(j ? 2 : ArgCn, j ? opts : ArgVc, "cbr::i::mf::th") : h;
                if (c == -1 && j == 1) {
                    free(opts[1]); // Alloced by Self
                    optind = i, j = 0;
                    c = getopt(ArgCn, ArgVc, "cbr::i::mf::t");
                }
                if (c != -1 && c != '?')
                    fprintf(stdout, "\n");
            }
            exit(0);
        case 'V':
            fprintf(stdout, "%s %s\n", fileName, PACKAGE_VERSION);
            exit(0);
        default:
            fprintf(stdout, Usage, fileName);
            exit(0);
        }
    }

    // Going to run as daemon. Find configuration.
    if (geteuid() != 0) {
        // Check that we are root.
        fprintf(stderr, "%s: Must be started as root.\n", fileName);
        exit(-1);
    } else if (! (CONF->configFilePath = calloc(1, sizeof(CFG_PATHS) + strlen(ArgVc[optind - !(optind == ArgCn - 1)])))) {
        // Freed by signalHandler()
        fprintf(stderr, "%s. Out of Memory.\n", fileName);
        exit(-1);
    } else if (optind == ArgCn - 1 && !(stat(ArgVc[optind], &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)))) {
        // Config file path specified as last argument. Check if it's ok.
        fprintf(stderr, "%s. Config file path '%s' not found. %s\n", fileName, ArgVc[optind], strerror(errno));
        exit(-1);
    } else if (optind == ArgCn - 1) {
        strcpy(CONF->configFilePath, ArgVc[optind]);
    } else {
        for (path = strtok(CFGPATH, " "); path && strcpy(CONF->configFilePath, path); path = strtok(NULL, " ")) {
            // Search for config in default locations.
            if (stat(strcat(strcat(CONF->configFilePath, fileName), ".conf"), &st) == 0)
                break;
            path[strlen(CONF->configFilePath) - 5] = '/';
            path[strlen(CONF->configFilePath) - 4] = '\0';
            if (stat(strcat(strcat(CONF->configFilePath, fileName), ".conf"), &st) == 0)
                break;
        }
        if (! path) {
            fprintf(stderr, "%s. Config file path not found in %s.\n", fileName, CFG_PATHS);
            exit(-1);
        }
    }

    // Check for valid location to place socket and PID file.
    for (path = strtok(RUNPATH, " "); path; path = strtok(NULL, " ")) {
        if (stat(path, &st) >= 0) {
            if (! (CONF->runPath = malloc(strlen(path) + strlen(fileName) + 8)))
                fprintf(stderr, "Out of memory.");   // Freed by igmpProxyCleanup()
            sprintf(CONF->runPath, "%s/%s/", path, fileName);
            break;
        }
    }
    if ((stat(CONF->runPath, &st) == -1 && (mkdir(CONF->runPath, 0770))) || chmod (CONF->runPath, 01770)) {
        fprintf(stderr, "Failed to create run directory %s. %s", CONF->runPath, strerror(errno));
        exit(-1);
    } else {
        remove(strcat(CONF->runPath, "root"));
        CONF->runPath[strlen(CONF->runPath) - 4] = '\0';
    }

    // Fork daemon and close from stdin/out/err. Initialize, load configuration, spawn proxies etc.
    if (!CONF->notAsDaemon && ((i = fork()) != 0 || close(0) < 0 || close(1) < 0 || close(2) < 0)) {
        if (i < 0)
            fprintf(stderr, "Failed to detach daemon. %s", strerror(errno));
        exit(-(i < 0));
    }

    igmpProxyInit();
    do {
        sighandled = sigstatus = 0;
        igmpProxyRun();
        // Clean up
        igmpProxyCleanUp(0);
        // Itialize IGMP buffers.
        pollFD[0].fd = initIgmp(true);
        // Reload config.
        reloadConfig(NULL);
        // If a SIGURG was caught try to restart.
    } while (RESTART);

    LOG(LOG_ERR, eABNRML, "Main loop exited, this should not happen.");
}

/**
 *   Main daemon event loop.
 */
static void igmpProxyRun(void) {
    int    i = 0, Rt = 0;
    sigstatus = 0;

    LOG(LOG_WARNING, 0, "Starting IGMPv3 Proxy on %s.", tS);
    while (true) {
        // Process signaling.
        struct timespec timeout;
        errno = 0;
        if (sighandled) {
            if (sighandled & GOT_SIGURG || sighandled & GOT_SIGTERM) {
                sigstatus   =  sighandled & GOT_SIGTERM ? GOT_SIGTERM : GOT_SIGURG;
                sighandled &= ~GOT_SIGURG & ~GOT_SIGTERM;
                break;
            } else if (sighandled & GOT_SIGHUP || sighandled & GOT_SIGUSR1) {
                sigstatus = GOT_SIGHUP ? GOT_SIGHUP : GOT_SIGUSR1;
                sighandled &= ~GOT_SIGHUP & GOT_SIGUSR1;
                LOG(LOG_DEBUG, 0, "%s: Reloading config%s.", SHUP ? "SIGHUP" : "SIGUSR1", SHUP ? " and rebuilding interfaces" : "");
                reloadConfig(NULL);
            } else if (sighandled & GOT_SIGUSR2) {
                sighandled &= ~GOT_SIGUSR2;
                sigstatus   =  GOT_SIGUSR2;
                LOG(LOG_DEBUG, 0, "SIGUSR2: Rebuilding interfaces.");
                rebuildIfVc(NULL);
            } else if (sighandled & GOT_SIGPIPE) {
                sighandled &= ~GOT_SIGPIPE;
                LOG(LOG_WARNING, 0, "Ceci n'est pas une SIGPIPE.");
            } else if (sighandled & GOT_SIGCHLD)
                sighandled &= ~GOT_SIGCHLD;  // Proxy ignores SIGCHLD.
            sigstatus = 0;
        }
        if (!sighandled && (Rt <= 0 || i >= CONF->reqQsz)) {
            // Run queue aging (unless sigs pending), it wil return the time until next timer is scheduled.
            timeout = timer_ageQueue();
            // Wait for input, indefinitely if no next timer, do not wait if next timer has already expired.
            Rt = ppoll(pollFD, 2, timeout.tv_sec == -1 ? NULL : timeout.tv_nsec == -1 ? &nto : &timeout, NULL);
            i = 1;
        }

        // log and ignore failures
        if (Rt < 0 && errno != EINTR)
            LOG(LOG_WARNING, errno, "ppoll() error");
        else if (!sighandled && Rt > 0) do {
            errno = 0;
            clock_gettime(CLOCK_REALTIME, &timeout);
            // Handle incoming IGMP request first.
            if (pollFD[0].revents & POLLIN) {
                LOG(LOG_DEBUG, 0, "igmpProxyRun: RECV IGMP Request %d.", i);
                union  cmsg   cmsg;
                struct iovec  ioVec[1] = { { rcv_buf, CONF->pBufsz } };
                struct msghdr msgHdr = (struct msghdr){ NULL, 0, ioVec, 1, &cmsg, sizeof(cmsg), MSG_DONTWAIT };
                int recvlen = recvmsg(pollFD[0].fd, &msgHdr, 0);
                if (recvlen < 0 || recvlen < (int)sizeof(struct ip) || (msgHdr.msg_flags & MSG_TRUNC))
                    LOG(LOG_WARNING, errno, "recvmsg() truncated datagram received.");
                else if ((msgHdr.msg_flags & MSG_CTRUNC))
                    LOG(LOG_WARNING, errno, "recvmsg() truncated control message received.");
                else
                    acceptIgmp(recvlen, msgHdr);
            }
            // Check if any cli connection needs to be handled.
            if (pollFD[1].revents & POLLIN) {
                LOG(LOG_DEBUG, 0, "igmpProxyRun: RECV CLI Request %d.", i);
                acceptCli(pollFD[1].fd);
            }

            clock_gettime(CLOCK_REALTIME, &curtime);
            LOG(LOG_DEBUG, 0, "igmpProxyRun: Fnished request %d in %dus.", i, timeDiff(timeout, curtime).tv_nsec / 1000);
            // Keep handling request until timeout, signal or max nr of queued requests to process in 1 loop.
        } while (!sighandled && i++ <= CONF->reqQsz && (Rt = ppoll(pollFD, 2, &nto, NULL)));
    }
    LOG(LOG_WARNING, 0, "%s", SHUTDOWN ? "SIGTERM: Exiting." : "SIGURG: Restarting");
}

#ifdef __linux__
/**
*   Start a new igmpv3proxy process for route table.
*/
void igmpProxyFork(int tbl) {
    int i, pid, size = 32 * sizeof(struct pt);

    // On first start of new process, initialize the child processes table. Alloc per 32 entries.
    if (chld.nr % 32 == 0 && ! _recalloc(chld.c, var, ((chld.nr / 32) + 1) * size, (chld.nr / 32) * size))
        // Freed by Self or igmpProxyCleanUp()
        LOG(LOG_ERR, eNOMEM, "igmpProxyFork: Out of Memory.");
    // Find a spot for the process in the table, increase child counter.
    // Child table is not shifted, but pid and tbl set to -1, after child exits.
    for (i = 0; i < chld.nr && chld.c[i].tbl != tbl; i++);
    if (i < chld.nr && chld.c[i].pid > 0) {
        LOG(LOG_DEBUG, 0, "igmpProxyFork: Proxy for table %d already active.", tbl);
    } else if ((pid = fork()) < 0) {
        // Do not increase the nr. childs here if an emtpy spot was found and check validity.
        LOG(LOG_ERR, eNOFORK, "igmpProxyFork: Cannot fork() child %d.", chld.nr);
    } else if (pid == 0) {
        // Child initializes its own start time.
        clock_gettime(CLOCK_REALTIME, &starttime);
        strcpy(tS, asctime(localtime(&starttime.tv_sec)));
        tS[strlen(tS) - 1] = '\0';
        mrt_tbl = tbl;    // Set routing table for process.
        chld.nr = i + 1;  // Just so that we know who we are.
        _free(chld.c, var, (((chld.nr - 1) / 32) + 1) * 32 * sizeof(struct pt)); // Alloced by Self.
        chld.c = NULL;
        sigstatus = 1;
        freeIfDescL(true);
    } else {
        // Parent sets the new child info in table.
        chld.c[i].tbl = tbl;
        chld.c[i].pid = pid;
        chld.c[i].sig = chld.c[i].st = 0;
        if (i == chld.nr)
            chld.nr++;
        LOG(LOG_INFO, 0, "Forked child: %d PID: %d for table: %d.", i + 1, chld.c[i].pid, chld.c[i].tbl);
    }
}

/**
*   Monitor process when multiple proxies are running.
*   signalHandler will restart processes if the exit. loadConfig may start new procxies if needed.
*/
static void igmpProxyMonitor(void) {
    rebuildIfVc(NULL);
    struct timespec timeout = timer_ageQueue();
    LOG(LOG_NOTICE, 0, "Monitoring %d proxy processes.", chld.nr);

    sigstatus = 0;
    // Simple busy sleeping loop here, it suits our needs.
    do {
        if (sighandled) {
            if (sighandled & GOT_SIGCHLD) {
                sighandled &= ~GOT_SIGCHLD;
                sigstatus   =  GOT_SIGCHLD;
                FOR_IF(int i = 0; i < chld.nr; i++, chld.c[i].sig == 1) {
                    LOG(chld.c[i].st == 0 ? LOG_NOTICE : LOG_WARNING, 0, "Child: %d PID: %d for table: %d %s (%i)",
                        i + 1, chld.c[i].pid, chld.c[i].tbl, exitmsg[chld.c[i].st], chld.c[i].st);
                    if (chld.c[i].st < 0)
                        chld.c[i].st = 0 - (chld.c[i].st);
                    chld.c[i].pid = chld.c[i].sig = 0;
                    if (chld.c[i].tbl > 0 && !CONF->disableIpMrules)
                        ipRules(chld.c[i].tbl, false);
                    if (chld.c[i].st == 15 || chld.c[i].st == 6 || chld.c[i].st == 11 || chld.c[i].st == 9)
                        // Start new proxy in case of unexpected shutdown.
                        igmpProxyFork(chld.c[i].tbl);
                }
            } else if (sighandled & GOT_SIGTERM || sighandled & GOT_SIGURG || sighandled & GOT_SIGHUP || sighandled & GOT_SIGUSR1) {
                sigstatus    = sighandled & GOT_SIGTERM ? GOT_SIGTERM : sighandled & GOT_SIGURG ? GOT_SIGURG :
                               sighandled & GOT_SIGHUP  ? GOT_SIGHUP  : GOT_SIGUSR1;
                sighandled &= ~GOT_SIGURG & ~GOT_SIGHUP & ~GOT_SIGUSR1;
                LOG(LOG_WARNING, 0, "%s", RESTART  ? "SIGURG: Restarting." : SHUP ? "SIGHUP: Reloading config." :
                                          SHUTDOWN ? "SIGTERM: Exiting."   :        "SIGUSR1: Reloading config.");
                if (RESTART || SHUTDOWN)
                    igmpProxyCleanUp(0);
                reloadConfig(NULL);
            } else if (sighandled & GOT_SIGUSR2) {
                sighandled &= ~GOT_SIGUSR2;
                sigstatus   =  GOT_SIGUSR2;
                LOG(LOG_NOTICE, 0, "SIGUSR1: Rebuilding interfaces.");
                rebuildIfVc(NULL);
            } else if (sighandled & GOT_SIGPIPE) {
                sighandled &= ~GOT_SIGPIPE;
                LOG(LOG_WARNING, 0, "Ceci n'est pas une SIGPIPE.");
            }
            sigstatus = 0;
        }
        if (mrt_tbl < 0)
            timeout = timer_ageQueue();
        if (mrt_tbl >= 0)
            // SIGCHLD, ageQueue() or loadConfig() may have forked new proxy.
            return;  // To igmpProxyInit()
        if (timeout.tv_sec < 0)
            timeout = (struct timespec){ 2147483647, 0 };
    } while (sighandled || timeout.tv_nsec < 0 || nanosleep(&timeout, NULL) >= 0 || true);

    LOG(LOG_ERR, eABNRML, "igmpProxyMonitor: Proceses exited.");
}
#endif

/**
*   Handles the initial startup of the daemon. Contains OS Specics.
*/
static void igmpProxyInit(void) {
    pid_t        pid = -1;
    struct stat  st;
    sigstatus = 1;  // STARTUP

    umask(S_IROTH | S_IWOTH | S_IXOTH);
    clock_gettime(CLOCK_REALTIME, &starttime);
    strcpy(tS, asctime(localtime(&starttime.tv_sec)));
    tS[strlen(tS) - 1] = '\0';

    // Load the config file. If no socket group was configured set it to configured users's group or root.
    if (!loadConfig(CONF->configFilePath))
        LOG(LOG_ERR, eNOCONF, "Failed to load configuration from '%s'.", CONF->configFilePath);
    LOG(LOG_NOTICE, 0, "Loaded configuration from '%s'.", CONF->configFilePath);
    if (! CONF->group && !(CONF->group = getgrgid(CONF->user ? CONF->user->pw_gid : 0)))
        LOG(LOG_WARNING, errno, "Config: Failed to get group for %d.", CONF->user ? CONF->user->pw_gid : 0);
    unsigned int uid = CONF->user ? CONF->user->pw_uid : 0, gid = CONF->group->gr_gid;

#ifdef __linux__
    if (mrt_tbl < 0) {
        // Write PID in main daemon process only.
#endif
      char  pidFile[strlen(CONF->runPath) + strlen(fileName) + 5];
      sprintf(pidFile, "%s/%s.pid", CONF->runPath, fileName);
      remove(pidFile);
      FILE *pidFilePtr = fopen(pidFile, "w");
      fprintf(pidFilePtr, "%d\n", getpid());
      fclose(pidFilePtr);
#ifdef __linux__
    }
#endif
    // Change ownership of run directory.
    if (chown(CONF->runPath, uid, gid) < 0)
        LOG(LOG_ERR, eNOINIT, "Failed to change ownership of %s to %s:%s.",
                             CONF->runPath, CONF->user->pw_name, CONF->group->gr_name);
    // Switch root if chroot is configured. The config file must be placed there.
    if (CONF->chroot) {
        // Truncate config and log file path to /.
        char *b = basename(CONF->configFilePath);
        strcpy(CONF->configFilePath, b);
        if (CONF->logFilePath) {
            b = basename(CONF->logFilePath);
            strcpy(CONF->logFilePath, b);
        }
        // Link the root to the run directory and set runpath to /.
        if (symlink(CONF->chroot, CONF->runPath) != 0 && errno != EEXIST)  // Race with possible childs, it's fine let them win.
            LOG(LOG_ERR, eNOINIT, "Failed to link chroot directory %s to run directory %s.", CONF->chroot, CONF->runPath);
        strcpy(CONF->runPath, "/");
        // Set permissions and swith root directory.
        if (!(stat(CONF->chroot, &st) == 0 && chown(CONF->chroot, uid, gid) == 0 && chmod(CONF->chroot, 0770) == 0
                                           && chroot(CONF->chroot) == 0 && chdir("/") == 0))
            LOG(LOG_ERR, eNOINIT, "Failed to switch root to %s.",CONF->chroot);
        LOG(LOG_WARNING, 0, "Switched root to %s.", CONF->chroot);
    }
    // Finally check log file permissions in case we need to run as user.
    if (CONF->logFilePath && (chown(CONF->logFilePath, uid, gid) || chmod(CONF->logFilePath, 0640)))
        LOG(LOG_WARNING, errno, "Failed to chown log file %s to %s.", CONF->logFilePath, CONF->user->pw_name);

    SETSIGS;
#ifdef __linux__
    // When multiple tables are in use, process for default table 0 is forked off here.
    if (mrt_tbl < 0 && chld.nr)
        igmpProxyMonitor();
    else if (mrt_tbl < 0)
        mrt_tbl = 0;
#endif
    // Enable mroute and open cli socket and add ip mrules while still running as root.
    pollFD[0].fd = initIgmp(true);
    pollFD[1].fd = openCliFd();
    rebuildIfVc(NULL);
#ifdef __linux__
    if (!CONF->disableIpMrules)
        ipRules(mrt_tbl, true);
#endif
    // Make sure logfile and chroot directory are owned by configured user and switch ids.
    if (CONF->user && geteuid() == 0) {
        unsigned int uid = CONF->user ? CONF->user->pw_uid : 0, gid = CONF->group->gr_gid;
        LOG(CONF->logLevel, 0, "Switching user to %s.", CONF->user->pw_name);
        if (setgroups(1, (gid_t *)&gid) != 0 ||
            setresgid(CONF->user->pw_gid, CONF->user->pw_gid, CONF->user->pw_gid) != 0 ||
            setresuid(uid, uid, uid) != 0)
            LOG(LOG_ERR, eNOINIT, "Failed to switch to user %s.", CONF->user->pw_name);
    }
}

/**
*   Clean up all on exit...
*/
void igmpProxyCleanUp(int code) {
    struct timespec endtime;
    // Shutdown all interfaces, queriers, remove all routes, close sockets.
#ifdef __linux__
    int size = (((chld.nr - 1) / 32) + 1) * 32 * sizeof(struct pt);
    if (!code && mrt_tbl < 0)
        code = 0;
    else if (!code)
        code = 15;
    if (mrt_tbl < 0 && chld.c && !RESTART) {
        pid_t pid;
        // Wait for all childs. Cli processes are not tracked, their fds are closed.
        LOG(LOG_INFO, 0, "Waiting for %d processes to finish.", chld.nr);
        while ((pid = wait(NULL)) > 0 && --chld.nr) {
            FOR_IF(int i = 0; i < chld.nr + 1; i++, chld.c[i].pid == pid && chld.c[i].tbl > 0)
                ipRules(chld.c[i].tbl, false);
            LOG(LOG_NOTICE, 0, "Still waiting for %d process%s to finish.", chld.nr, chld.nr > 1 ? "es" : "");
        }
        _free(chld.c, var, size);  // Alloced by igmpProxyFork()
        LOG(LOG_NOTICE, 0, "All processes finished.");
    }
#endif
    // Remove all interfaces.
    rebuildIfVc(NULL);

    // Remove MRT, CLI socket and PID file and Config in main daemon only.
#ifdef __linux__
    if (mrt_tbl >= 0)
#endif
      pollFD[1].fd = closeCliFd(pollFD[1].fd), pollFD[0].fd = initIgmp(false);
#ifdef __linux__
    if (mrt_tbl < 0)
#endif
      if (!RESTART && CONF->runPath) {
          char rFile[strlen(CONF->runPath) + strlen(fileName) + 5];
          sprintf(rFile, "%s%s.pid", CONF->runPath, fileName);
          remove(rFile);
          sprintf(rFile, "%scli.sock", CONF->runPath);
          remove(rFile);
          if (CONF->chroot && rmdir(CONF->runPath) < 0)
              LOG(LOG_WARNING, errno, "Cannot remove run dir %s.", CONF->runPath);
      }
    if (!RESTART)
        // On SIGURG reloadConfig will clear old config.
        freeConfig(false);
    getMemStats(0, -1);

    // Log shutdown.
    clock_gettime(CLOCK_REALTIME, &endtime);
    strcpy(tE, asctime(localtime(&endtime.tv_sec)));
    tE[strlen(tE) - 1] = '\0';
    LOG(LOG_WARNING, 0, "%s on %s. Running since %s (%ds).", RESTART ? "Restarting" : "Shutting down",
                         tE, tS, timeDiff(starttime, endtime).tv_sec);
    if (SHUTDOWN) {
        free(CONF->runPath);         // Alloced by main()
        free(CONF->chroot);          // Alloced by loadConfig()
        free(CONF->logFilePath);     // Alloced by loadConfig()
        free(CONF->configFilePath);  // Alloced by main()
        exit(code);
    }
}

/**
*   Signal handler. Signal arrived set flag so that the main loop can take care of it.
*/
static void signalHandler(int sig, siginfo_t* siginfo, void* context) {
    int i = 0;

    switch (sig) {
    case SIGINT:
#ifdef __linux__
        if (mrt_tbl < 0 || !chld.nr)
#endif
          if (!CONF->notAsDaemon)
              return;  // Daemon / monitor ignores SIGINT
    case SIGTERM:
        if (SHUTDOWN) {
#ifdef __linux__
            // If SIGTERM received more than once, KILL childs and exit.
            IF_FOR_IF(mrt_tbl < 0 && chld.c, i = 0; i < chld.nr; i++, chld.c[i].pid > 0) {
                kill(chld.c[i].pid, SIGKILL);
            }
#endif
            exit(sig);
        }
        BLOCKSIGS;
        sighandled |= GOT_SIGTERM;
        if (sig == SIGINT)
            return;
        break;
    case SIGPIPE:
        sighandled |= GOT_SIGPIPE;
        return;
    case SIGURG:
        sighandled |= GOT_SIGURG;
        break;
    case SIGHUP:
        sighandled |= GOT_SIGHUP;
        break;
    case SIGUSR1:
        sighandled |= GOT_SIGUSR1;
        break;
    case SIGUSR2:
        sighandled |= GOT_SIGUSR2;
        break;
    case SIGCHLD:
        sighandled |= GOT_SIGCHLD;
#ifdef __linux__
        IF_FOR_IF(mrt_tbl < 0 && chld.c, i = 0; i < chld.nr; i++, chld.c[i].pid == siginfo->si_pid) {
            chld.c[i].sig = 1;
            chld.c[i].st  = (int8_t)siginfo->si_status;
            break;
        }
        return;
    }
    // Send SIG to children, except for SIGINT SIGPIPE and SIGCHLD.
    // If monitor is terminating we will end childs with SIGINT.
    IF_FOR_IF(mrt_tbl < 0 && chld.c, i = 0; i < chld.nr; i++, chld.c[i].pid > 0)
        kill(chld.c[i].pid, sig == SIGTERM ? SIGINT : sig);
#else
    }
#endif
}
