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

//  Socket control message union.
union cmsg {
    struct cmsghdr cmsgHdr;
#ifdef IP_PKTINFO
    char cmsgData[sizeof(struct msghdr) + sizeof(struct in_pktinfo)];
#elif IP_RECVIF
    char cmsgData[sizeof(struct msghdr) + sizeof(struct sockaddr_dl)];
#endif
};

// Local function Prototypes
STRSIG;
static void signalHandler(int sig, siginfo_t* siginfo, void* context);
static void igmpProxyInit(void);
static void igmpProxyMonitor(void);
static void igmpProxyStart(void);
static void igmpProxyRun(void);

// Global Variables Memory / Signal Handling / Timekeeping / Buffers etc.
uint8_t               sighandled, sigstatus, logwarning;
struct timespec       curtime, utcoff, starttime;
char                 *fileName, tS[32] = "", tE[32] = "";
struct memstats       memuse = { 0 }, memalloc = { 0 }, memfree = { 0 };
static struct pollfd  pollFD[2] = { {-1, POLLIN, 0}, {-1, POLLIN, 0} };
char                 *rcv_buf = NULL;
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
    char        *opts[2] = { ArgVc[0], NULL }, cmd[20] = "",
                 paths[sizeof(CFG_PATHS) + 1] = CFG_PATHS, *path = NULL;
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
#else
            fprintf(stderr, "Only linux supports multiple tables.");
#endif
            break;
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
                            if (! (opts[1] = malloc(strlen(optarg) + 1))) {
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
                    free(opts[1]);
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
        // Freed by igmpProxyInit() or signalHandler()
        fprintf(stderr, "%s. Out of Memory.\n", fileName);
        exit(-1);
    } else if (optind == ArgCn - 1 && !(stat(ArgVc[optind], &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)))) {
        // Config file path specified as last argument. Check if it's ok.
        fprintf(stderr, "%s. Config file path '%s' not found. %s\n", fileName, ArgVc[optind], strerror(errno));
        exit(-1);
    } else if (optind == ArgCn - 1) {
        strcpy(CONF->configFilePath, ArgVc[optind]);
    } else {
        for (path = strtok(paths, " "); path && strcpy(CONF->configFilePath, path); path = strtok(NULL, " ")) {
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

    // Detach daemon from stdin/out/err, and fork.
    if (!CONF->notAsDaemon && ((i = fork()) != 0 || close(0) < 0 || close(1) < 0 || close(2) < 0))
        i < 0 ? LOG(LOG_ERR, errno, "Failed to detach daemon.") : exit(0);
    igmpProxyInit();
}

#ifdef __linux__
/**
*   Start a new igmpv3proxy process for route table.
*/
void igmpProxyFork(int tbl)
{
    int i, pid;

    // On first start of new process, initialize the child processes table.
    if (chld.nr == 0 && ! (chld.c = calloc(CONF->maxtbl + 1, sizeof(struct pt))))
        // Freed by Self or igmpProxyCleanUp()
        LOG(LOG_ERR, errno, "igmpProxyFork: Out of Memory.");
    if (mrt_tbl < 0) {
        // Find a spot for the process in the table, increase child counter.
        // Child table is not shifted, but pid and tbl set to -1, after child exits.
        for (i = 0; i < chld.nr && i < CONF->maxtbl && chld.c[i].pid != -1
                                && chld.c[i].tbl != tbl; i++);
        if ((STARTUP && i >= (CONF->maxtbl - 1)) || i >= CONF->maxtbl)
            // On startup check max_tbl-1 because the process for main table is forked in igmpProxyInit
            LOG(LOG_WARNING, 0, "Not starting new proxy for table %d. Maximum nr. (%d) of tables in use.", tbl, CONF->maxtbl);
        else if (i <= chld.nr && chld.c[i].tbl != tbl) {
            // If there is an empty spot in the middle (exited child) put it there.
            if ((pid = fork()) < 0 || chld.nr + 1 > CONF->maxtbl) {
                // Do not increase the nr. childs here if an emtpy spot was found and check validity.
                LOG(LOG_ERR, errno, "igmpProxyFork: Cannot fork() child %d.", chld.nr);
            } else if (pid == 0) {
                // Child initializes its own start time.
                clock_gettime(CLOCK_REALTIME, &starttime);
                strcpy(tS, asctime(localtime(&starttime.tv_sec)));
                tS[strlen(tS) - 1] = '\0';
                mrt_tbl = tbl;
                free (chld.c);    // Alloced by Self or loadConfig(), child does not need this.
                chld.c = NULL;    // Set pointer to NULL, good way to detect a child.
                chld.nr = i + 1;  // Just so that we know who we are.
            } else {
                // Parent sets the new child info in table.
                chld.c[i].tbl = tbl;
                chld.c[i].pid = pid;
                chld.nr += i == chld.nr ? 1 : 0;
                LOG(LOG_INFO, 0, "Forked child: %d PID: %d for table: %d.", i + 1, chld.c[i].pid, chld.c[i].tbl);
            }
        } else
            LOG(LOG_DEBUG, 0, "igmpProxyFork: Proxy for table %d already active.", tbl);
    }
}

/**
*   Monitor process when multiple proxies are running.
*   signalHandler will restart processes if the exit. loadConfig may start new procxies if needed.
*/
static void igmpProxyMonitor(void) {
    struct timespec timeout = timer_ageQueue();
    LOG(LOG_NOTICE, 0, "Monitoring %d proxy processes.", chld.nr);

    sigstatus = 0;
    SETSIGS;
    // Simple busy sleeping loop here, it suits our needs.
    while (nanosleep(&timeout, NULL) >= 0 || !(sighandled & GOT_SIGTERM)) {
        if ((sighandled & GOT_SIGURG) || (sighandled & GOT_SIGHUP) || (sighandled & GOT_SIGUSR1) || (sighandled & GOT_SIGUSR2)) {
            // Signal recevied: Restart or reload config.
            sighandled & GOT_SIGURG  ? LOG(LOG_NOTICE, 0, "SIGURG: Restarting.") :
            sighandled & GOT_SIGUSR2 ? LOG(LOG_NOTICE, 0, "SIGUSR1: Rebuilding interfaces.")
                                     : LOG(LOG_NOTICE, 0, "%sReloading config.", sighandled & GOT_SIGHUP ? "SIGHUP: " : "SIGUSR1: ");
            if (sighandled & GOT_SIGURG) {
                igmpProxyCleanUp();
                SETSIGS;
            }
            if ((sighandled & GOT_SIGHUP) || (sighandled & GOT_SIGUSR1))
                reloadConfig(NULL);
            if ((sighandled & GOT_SIGHUP) || (sighandled & GOT_SIGUSR2))
                rebuildIfVc(NULL);
            sighandled &= ~GOT_SIGURG & ~GOT_SIGHUP & ~GOT_SIGUSR1 & ~GOT_SIGUSR2;
        }
        // SIGCHLD or loadConfig() may have forked new process, it will end up here.
        if (mrt_tbl >= 0) {
            // New proxy has config now, so can go to igmpProxyStart().
            sigstatus = 1;
            pollFD[0].fd = initIgmp(true);
            rebuildIfVc(NULL);
            igmpProxyStart();
        }
        timeout = timer_ageQueue();
    }
    LOG(LOG_INFO, 0, "igmpProxyMonitor: All proceses exited.");
    free(CONF->runPath);         // Alloced by igmpProxyInit()
    free(CONF->chroot);          // Alloced by loadConfig()
    free(CONF->logFilePath);     // Alloced by loadConfig() or igmpProxyInit()
    free(CONF->configFilePath);  // Alloced by loadConfig() or igmpProxyInit()
    exit(0);
}
#endif

/**
*   Handles the initial startup of the daemon.
*/
static void igmpProxyInit(void) {
    pid_t            pid = 0;
    sigstatus = 1;  // STARTUP

    umask(S_IROTH | S_IWOTH | S_IXOTH);
    clock_gettime(CLOCK_REALTIME, &starttime);
    strcpy(tS, asctime(localtime(&starttime.tv_sec)));
    tS[strlen(tS) - 1] = '\0';

    // Load the config file. If no socket group was configured set it to configured users's group or root.
    if (!loadConfig(CONF->configFilePath))
        LOG(LOG_ERR, 0, "Failed to load configuration from '%s'.", CONF->configFilePath);
    LOG(LOG_NOTICE, 0, "Loaded configuration from '%s'. Starting IGMPv3 Proxy.", CONF->configFilePath);
    if (!CONF->group && !(CONF->group = getgrgid(CONF->user ? CONF->user->pw_gid : 0)))
        LOG(LOG_WARNING, errno, "Config: Failed to get group for %d.", CONF->user ? CONF->user->pw_gid : 0);
    unsigned int uid = CONF->user ? CONF->user->pw_uid : 0, gid = CONF->group->gr_gid;

    // Check for valid location to place socket and PID file.
    char   paths[sizeof(RUN_PATHS)] = RUN_PATHS, *path;
    struct stat st;
    for (path = strtok(paths, " "); path; path = strtok(NULL, " ")) {
        if (stat(path, &st) != -1) {
            if (! (CONF->runPath = malloc(strlen(path) + strlen(fileName) + 8)))
                LOG(LOG_ERR, 0, "Out of memory.");   // Freed by igmpProxyCleanup()
            sprintf(CONF->runPath, "%s/%s/", path, fileName);
            break;
        }
    }
    if (  (stat(CONF->runPath, &st) == -1 && (mkdir(CONF->runPath, 0770)))
        || chown(CONF->runPath, uid, gid) || chmod (CONF->runPath, 01770))
        if (errno != EEXIST)  // Race with possible childs, it's fine let them win.
            LOG(LOG_ERR, errno, "Failed to create run directory %s.", CONF->runPath);

    // Switch root if chroot is configured. The config file must be placed there.
    if (CONF->chroot) {
        // Truncate config and log file path to /.
        char *b = basename(CONF->configFilePath);
        strcpy(CONF->configFilePath, b);
        if (CONF->logFilePath) {
            b = basename(CONF->logFilePath);
            strcpy(CONF->logFilePath, b);   // Alloced by loadConfig()
        }
        // Link the root to the run directory and set runpath to /..
        remove(strcat(CONF->runPath, "root"));
        if (symlink(CONF->chroot, CONF->runPath) != 0 && errno != EEXIST)  // Race with possible childs, it's fine let them win.
            LOG(LOG_ERR, errno, "Failed to link chroot directory %s to run directory %s.", CONF->chroot, CONF->runPath);
        strcpy(CONF->runPath, "/");
        // Set permissions and swith root directory.
        if (!(stat(CONF->chroot, &st) == 0 && chown("/", uid, gid) == 0 && chmod(CONF->chroot, 0770) == 0
                                           && chroot(CONF->chroot) == 0 && chdir("/") == 0))
            LOG(LOG_ERR, errno, "Failed to switch root to %s.",CONF->chroot);   // Alloced by Self
        LOG(LOG_WARNING, 0, "Switched root to %s.", CONF->chroot);
    }
    // Finally check log file permissions in case we need to run as user.
    if (CONF->logFilePath && (chown(CONF->logFilePath, uid, gid) || chmod(CONF->logFilePath, 0640)))
        LOG(LOG_WARNING, errno, "Failed to chown log file %s to %s.", CONF->logFilePath, CONF->user->pw_name);

#ifdef __linux__
    if (mrt_tbl < 0 || !chld.nr) {
#endif
      // Write PID in main daemon process only.
      char  pidFile[strlen(CONF->runPath) + strlen(fileName) + 5];
      sprintf(pidFile, "%s/%s.pid", CONF->runPath, fileName);
      remove(pidFile);
      FILE *pidFilePtr = fopen(pidFile, "w");
      fprintf(pidFilePtr, "%d\n", getpid());
      fclose(pidFilePtr);
#ifdef __linux__
    }
    // When multiple tables are in use, process for default table 0 is forked off here.
    if (chld.c && (pid = fork()) < 0) {
        LOG(LOG_ERR, errno, "igmpProxyInit: Cannot fork().");
    } else if (chld.c && pid > 0) {
        // Parent becomes monitor.
        chld.c[chld.nr].pid = pid;
        chld.c[chld.nr++].tbl = 0;
        rebuildIfVc(NULL);
        igmpProxyMonitor();
    } else if (chld.c) {
        // Child (or only process) becomes proxy for mrt table 0.
        free(chld.c);   // Alloced by loadConfig() or igmpProxyStart()
        chld.c = NULL;
        chld.nr++;
    }
    if (mrt_tbl < 0)
        mrt_tbl = 0;
#endif
    pollFD[0].fd = initIgmp(true);
    rebuildIfVc(NULL);
    igmpProxyStart();
}

void igmpProxyStart(void) {
    LOG(LOG_WARNING, 0, "Initializing IGMPv3 Proxy on %s.", tS);

    // Enable mroute and open cli socket and add ip mrules while still running as root.
    pollFD[1].fd = pollFD[1].fd != -1 ?: openCliFd();
#ifdef __linux__
    if (mrt_tbl > 0 && !CONF->disableIpMrules)
        ipRules(mrt_tbl, true);
#endif

    // Make sure logfile and chroot directory are owned by configured user and switch ids.
    if (CONF->user && geteuid() == 0) {
        unsigned int uid = CONF->user ? CONF->user->pw_uid : 0, gid = CONF->group->gr_gid;
        LOG(CONF->logLevel, 0, "Switching user to %s.", CONF->user->pw_name);
        if (setgroups(1, (gid_t *)&gid) != 0 ||
            setresgid(CONF->user->pw_gid, CONF->user->pw_gid, CONF->user->pw_gid) != 0 ||
            setresuid(uid, uid, uid) != 0)
            LOG(LOG_ERR, errno, "Failed to switch to user %s.", CONF->user->pw_name);
    }

    do {
        SETSIGS;
        // Go to the main loop.
        sighandled = sigstatus = 0;
        igmpProxyRun();
        // Clean up
        igmpProxyCleanUp();
        // Reload config.
        reloadConfig(NULL);
        // Itialize IGMP buffers.
        initIgmp(true);
        // Add physical interfaces and mcast vifs.
        rebuildIfVc(NULL);
        // If a SIGURG was caught try to restart.
    } while (sighandled & GOT_SIGURG);

    LOG(LOG_ERR, errno, "Main loop exited, this should not happen.");
}

/**
*   Clean up all on exit...
*/
void igmpProxyCleanUp(void) {
    struct timespec endtime;
    sigstatus = 0x20;         // Shutdown
    BLOCKSIGS;

    // Shutdown all interfaces, queriers, remove all routes, close sockets.
#ifdef __linux__
    if (mrt_tbl < 0 && chld.c) {
        pid_t pid;
        // Wait for all childs. Cli processes are not tracked, their fds are closed.
        LOG(LOG_INFO, 0, "Waiting for %d processes to finish.", chld.nr);
        while ((pid = wait(NULL)) > 0 && --chld.nr) {
            FOR_IF(int i = 0; i < chld.nr + 1; i++, chld.c[i].pid == pid && chld.c[i].tbl > 0) {
                ipRules(chld.c[i].tbl, false);
                break;
            }
            LOG(LOG_NOTICE, 0, "Still waiting for %d process%s to finish.", chld.nr, chld.nr > 1 ? "es" : "");
        }
        free(chld.c);            // Alloced by parsePhyIntToken() or igmpProxyStart()
        LOG(LOG_NOTICE, 0, "All processes finished.");
    }
#endif
    rebuildIfVc(NULL);
    if (!(sighandled & GOT_SIGURG) && pollFD[1].fd > 0)
        pollFD[1].fd = closeCliFd(pollFD[1].fd);
    // Remove CLI socket and PID file and Config in main daemon only.

#ifdef __linux__
    if (mrt_tbl < 0) {
#endif
      if (!(sighandled & GOT_SIGURG) && CONF->runPath) {
          // Remove socket and PID file.
          char rFile[strlen(CONF->runPath) + strlen(fileName) + 5];
          sprintf(rFile, "%s%s.pid", CONF->runPath, fileName);
          remove(rFile);
          sprintf(rFile, "%scli.sock", CONF->runPath);
          remove(rFile);
          if (rmdir(CONF->runPath))
              LOG(LOG_DEBUG, errno, "Cannot remove run dir %s.", CONF->runPath);
      }
#ifdef __linux__
    }
    if (mrt_tbl >= 0)
#endif
      pollFD[0].fd = initIgmp(false);

    // Free remaining allocs.
    freeConfig(0);
    getMemStats(0, -1);

    // Log shutdown.
    clock_gettime(CLOCK_REALTIME, &endtime);
    strcpy(tE, asctime(localtime(&endtime.tv_sec)));
    tE[strlen(tE) - 1] = '\0';
    LOG(LOG_WARNING, 0, "%s on %s. Running since %s (%ds).", sighandled & GOT_SIGURG ? "Restarting" : "Shutting down",
                                                             tE, tS, timeDiff(starttime, endtime).tv_sec);
}

/**
*   Main daemon event loop.
*/
static void igmpProxyRun(void) {
    struct timespec timeout;
    int    i = 0, Rt = 0;
    sigstatus = 0;

    while (!(sighandled & GOT_SIGURG)) {
        // Process signaling.
        errno = 0;
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

        if (Rt <= 0 || i >= CONF->reqQsz) {
            const struct timespec nto = { 0, 0 };
            // Run queue aging, it wil return the time until next timer is scheduled.
            timeout = timer_ageQueue();
            // Wait for input, indefinitely if no next timer, do not wait if next timer has already expired.
            Rt = ppoll(pollFD, 2, timeout.tv_sec == -1 ? NULL : timeout.tv_nsec == -1 ? &nto : &timeout, NULL);
            i = 1;
        }

        // log and ignore failures
        const struct timespec nto = { 0, 0 };
        if (Rt < 0 && errno != EINTR)
            LOG(LOG_WARNING, errno, "ppoll() error");
        else if (Rt > 0) do {
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
        } while (i++ <= CONF->reqQsz && (Rt = ppoll(pollFD, 2, &nto, NULL)) > 0 && !sighandled);
    }
    LOG(LOG_NOTICE, 0, "SIGURG: Restarting.");
}

/**
*   Signal handler.  Take note of the fact that the signal arrived so that the main loop can take care of it.
*/
static void signalHandler(int sig, siginfo_t* siginfo, void* context) {
    int i;

#ifdef __linux__
    // Send SIG to children.
    IF_FOR_IF(sig != SIGPIPE && sig !=SIGCHLD && !(sig == SIGINT && !CONF->notAsDaemon)
                             && mrt_tbl < 0, i = 0; i < chld.nr; i++, chld.c[i].pid > 0) {
        LOG(LOG_DEBUG, 0, "%s to PID: %d for table: %d.", SIGS[sig], chld.c[i].pid, chld.c[i].tbl);
        kill(chld.c[i].pid, sig);
    }
#endif
    switch (sig) {
    case SIGINT:
#ifdef __linux__
        if (mrt_tbl < 0)
#endif
          if (!CONF->notAsDaemon)
              return;  // Daemon / monitor ignores SIGINT
    case SIGTERM:
        LOG(LOG_NOTICE, 0, "%s: Exiting.", SIGS[sig]);
        if (!(sighandled & GOT_SIGTERM)) {
            sighandled |= GOT_SIGTERM;
            igmpProxyCleanUp();
#ifdef __linux__
        } else IF_FOR_IF(mrt_tbl < 0, i = 0; i < chld.nr; i++, chld.c[i].pid > 0) {
            // If SIGTERM received more than once, send SIGKILL and exit.
            LOG(LOG_DEBUG, 0, "%s to PID: %d for table: %d.", SIGS[9], chld.c[i].pid, chld.c[i].tbl);
            kill(chld.c[i].pid, SIGKILL);
#endif
        }
        free(CONF->runPath);         // Alloced by igmpProxyInit()
        free(CONF->chroot);          // Alloced by loadConfig()
        free(CONF->logFilePath);     // Alloced by loadConfig()
        free(CONF->configFilePath);  // Alloced by main()
        exit(sig);
    case SIGCHLD:
#ifdef __linux__
        IF_FOR_IF(chld.c, i = 0; i < chld.nr; i++, chld.c[i].pid == siginfo->si_pid) {
            int tbl;
            LOG(siginfo->si_status == 0 ? LOG_NOTICE : LOG_WARNING, 0, "PID: %d (%d) for table: %d exited (%i)",
                siginfo->si_pid, i, chld.c[i].tbl, (int8_t)siginfo->si_status);
            tbl = chld.c[i].tbl;
            chld.c[i].pid = chld.c[i].tbl = -1;
            if (tbl > 0)
                ipRules(tbl, false);
            if (!SHUTDOWN && (siginfo->si_status == 15 || siginfo->si_status == 6 ||
                              siginfo->si_status == 11 || siginfo->si_status == 9))
                // Start new proxy in case of unexpected shutdown.
                igmpProxyFork(tbl);
            return;
        }
        if (! chld.c || i > chld.nr || chld.c[i].pid != -1)
#endif
          LOG(LOG_DEBUG, 0, "SIGCHLD: PID %d exited (%d).", siginfo->si_pid, siginfo->si_status);
        return;
    case SIGPIPE:
        LOG(LOG_NOTICE, 0, "SIGPIPE: Ceci n'est pas un SIGPIPE."); // FALLTHRU
    case SIGURG:
    case SIGHUP:
    case SIGUSR1:
    case SIGUSR2:
        sighandled |= sig == SIGURG  ? GOT_SIGURG  : sig == SIGHUP  ? GOT_SIGHUP
                    : sig == SIGUSR1 ? GOT_SIGUSR1 : sig == SIGUSR2 ? GOT_SIGUSR2 : 0;
        return;
    }

    LOG(LOG_NOTICE, 0, "Caught unhandled signal %s", SIGS[sig]);
}
