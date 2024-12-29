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
char                 *rcv_buf = NULL, *fileName, tS[32], tE[32];
struct memstats       memuse = { 0 }, memalloc = { 0 }, memfree = { 0 };
static struct pollfd  pollFD[2] = { {-1, POLLIN, 0}, {-1, POLLIN, 0} };
const struct timespec nto = { 0, 0 };
int                   mrt_tbl = -1;
struct chld           chld = { 0 };

/**
*   Program main method. Is invoked when the program is started
*   on commandline. The number of commandline arguments, and a
*   pointer to the arguments are received on the line...
*/
int main(int ArgCn, char *ArgVc[]) {
    int          c = 0, i = 0, j = 0, tbl = -1;
    char        *opts[2] = { ArgVc[0], NULL }, cmd[20] = "", *path;
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
    for (c = getopt(ArgCn, ArgVc, "cvVdnht::"); c != -1; c = getopt(ArgCn, ArgVc, "cvVdnht::")) {
        switch (c) {
        case 'v':
            if (CONF->logLevel == LOG_WARNING)
                CONF->logLevel = LOG_NOTICE;
            else
                CONF->logLevel = LOG_INFO; // FALLTHRU
        case 'd':
            CONF->logLevel = CONF->logLevel == LOG_WARNING ? LOG_DEBUG : CONF->logLevel;  // FALLTHRU
        case 'n':
            CONF->log2Stderr = true;
            CONF->notAsDaemon = true;
            break;
        case 't':
#ifdef __linux__
            tbl = ! optarg ? -1 : atoll(optarg);
            break;
#else
            fprintf(stderr, "Only linux supports multiple tables.\n");
            exit(1);
#endif
        case 'c':
            c = getopt(ArgCn, ArgVc, "cbr::i::mf::thp");
            while (c != -1 && c != '?') {
                uint32_t addr, mask, h = 0;
                memset(cmd, 0, sizeof(cmd));
                cmd[0] = c;
                if (c != 'r' && c != 'i' && c!= 'f' && (h = getopt(j ? 2 : ArgCn, j ? opts : ArgVc, "cbr::i::mf::thp")) == 'h')
                    strcat(cmd, "h");
                else if (h == '?')
                    break;
                else if ((c == 'r' || c == 'i' || c == 'f') && optarg) {
                    if (optarg[0] == 'h' && optarg[1] == '\0') {
                        strcat(cmd, "h");
                        optarg++;
                        h = 'h';
                    }
                    if (strlen(optarg) > 0) {
                        if (c == 'r' && !parseSubnetAddress(optarg, &addr, &mask)) {
                            i = optind, j = optind = 1;
                            if (! (opts[1] = malloc(strlen(optarg) + 2))) {  // Freed by Self
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
                c = (h == 'h' || c == 'r' || c == 'i' || c == 'f') ? getopt(j ? 2 : ArgCn, j ? opts : ArgVc, "cbr::i::mf::thp") : h;
                if (c == -1 && j == 1) {
                    free(opts[1]); // Alloced by Self
                    optind = i, j = 0;
                    c = getopt(ArgCn, ArgVc, "cbr::i::mf::tp");
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
        // Freed by igmpProxyInit() or igmpProxyCleanUp()
        fprintf(stderr, "%s. Out of Memory.\n", fileName);
        exit(-1);
    } else if (optind == ArgCn - 1 && !(stat(ArgVc[optind], &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)))) {
        // Config file path specified as last argument. Check if it's ok.
        fprintf(stderr, "%s. Config file path '%s' not found. %s\n", fileName, ArgVc[optind], strerror(errno));
        exit(-1);
    } else if (optind == ArgCn - 1) {
        strcpy(CONF->configFilePath, ArgVc[optind]);
    } else {
        fprintf(stderr, "%s: Looking for %s.conf config in default locations:", fileName, fileName);
        for (i = 0, path = strtok(CFG_PATHS, " "); path && strcpy(CONF->configFilePath, path); path = strtok(NULL, " ")) {
            // Search for config in default locations.
            if (stat(strcat(strcat(CONF->configFilePath, fileName), ".conf"), &st) == 0)
                break;
            fprintf(stderr, " %s", CONF->configFilePath);
            CONF->configFilePath[strlen(CONF->configFilePath) - 5] = '/';
            CONF->configFilePath[strlen(CONF->configFilePath) - 4] = '\0';
            if (stat(strcat(strcat(CONF->configFilePath, fileName), ".conf"), &st) == 0)
                break;
            fprintf(stderr, " %s", CONF->configFilePath);
        }
        if (path)
            fprintf(stderr, "\n%s: Found %s\n", fileName, CONF->configFilePath);
        else {
            fprintf(stderr, "\n%s: None found\n", fileName);
            exit(-1);
        }
    }

    // Check for valid location to place socket and PID file.
    for (path = strtok(RUN_PATHS, " "); path; path = strtok(NULL, " ")) {
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

    igmpProxyInit();
    do {
        igmpProxyRun();
        igmpProxyCleanUp(sighandled & GOT_SIGINT ? SIGINT : 0);
        pollFD[0].fd = initIgmp(1);
        reloadConfig(NULL);
        rebuildIfVc(NULL);
        pollFD[1].fd = initCli(1);
    } while (RESTART);

    LOG(LOG_CRIT, eABNRML, "Main loop exited.");
}

/**
 *   Start a new igmpv3proxy process for route table cli connection (called with -1) or other (-2).
 */
int igmpProxyFork(int tbl) {
    int i, pid, size = 32 * sizeof(struct pt);

    // Initialize the child processes table. Alloc per 32 entries.
    if (chld.nr % 32 == 0)
        _recalloc(chld.c, var, ((chld.nr / 32) + 1) * size, (chld.nr / 32) * size);  // Freed by Self or igmpProxyCleanUp()
    // Find a spot for the process in the table, table is not shifted, but pid set to 0 after child exits.
    if (tbl >= 0)
        for (i = 0; i < chld.nr && tbl != chld.c[i].tbl; i++);
    else
        for (i = 0; i < chld.nr && (mrt_tbl != chld.c[i].tbl || chld.c[i].pid != 0); i++);
    if (tbl >= 0 && i < chld.nr && chld.c[i].pid > 0) {
        pid = chld.c[i].pid;
        LOG(LOG_INFO, 0, "%s for table %d already active.", tbl >= 0 ? "Proxy" : "Child", tbl);
    } else if ((pid = fork()) < 0) {
        LOG(LOG_ERR, eNOFORK, "Cannot fork() %s %d.", tbl >= 0 ? "proxy" : "child", chld.nr);
    } else if (pid == 0) {
        // Child initializes its own start time, Closes sockets in use by monitor and opens new ones.
        TIME_STR(tS, starttime);
        chld.onr = i + 1;     // Just so that we know who we are.
        sigstatus = 1;        // STARTUP
        if (tbl >= 0) {       // Start a new proxy for table tbl.
            mrt_tbl = tbl;    // Set routing table for process.
            pollFD[0].fd = initIgmp(2);
            pollFD[1].fd = initCli(2);
            _free(chld.c, var, (((chld.nr - 1) / 32) + 1) * 32 * sizeof(struct pt)); // Alloced by Self.
            chld.nr = 0;
        }
    } else {
        // Parent sets the new child info in table.
        chld.c[i].tbl = tbl >= 0 ? tbl : mrt_tbl;
        chld.c[i].pid = pid;
        chld.c[i].st = 0;
        if (i == chld.nr)
            chld.nr++;
        LOG(tbl >= 0 ? LOG_NOTICE : LOG_INFO, 0, "Forked %s: %d PID: %d for table: %d.",
            tbl >= 0 ? "proxy" : "child", i + 1, chld.c[i].pid, chld.c[i].tbl);
    }

    return pid;
}

/**
 *   Handles the initial startup of the daemon.
 */
static void igmpProxyInit(void) {
    struct stat  st;
    int          pid;
    sigstatus = 1;  // STARTUP

    if (!CONF->notAsDaemon && (pid = fork() != 0 || close(0) < 0 || close(1) < 0 || close(2) < 0)) {
        if (pid < 0)
            fprintf(stderr, "Failed to detach daemon. %s.\n", strerror(errno));
        exit(-(pid < 0));
    }
    umask(S_IROTH | S_IWOTH | S_IXOTH);
    TIME_STR(tS, starttime);
    SETSIGS;

    // Load the config file. If no socket group was configured set it to configured users's group or root.
    if (!loadConfig(CONF->configFilePath))
        LOG(LOG_CRIT, eNOCONF, "Failed to load configuration from '%s'.", CONF->configFilePath);
    LOG(LOG_NOTICE, 0, "Loaded configuration from '%s'.", CONF->configFilePath);
    if (! CONF->group && !(CONF->group = getgrgid(CONF->user ? CONF->user->pw_gid : 0)))
        LOG(LOG_ERR, 1, "Failed to get group for %d.", CONF->user ? CONF->user->pw_gid : 0);
    unsigned int uid = CONF->user ? CONF->user->pw_uid : 0, gid = CONF->group->gr_gid;
    // If no proxies forked we become table 0 (the default table).
    if (mrt_tbl < 0 && chld.nr == 0)
        mrt_tbl = 0;

    // initialize IGMP socket, write PID.
    pollFD[0].fd = initIgmp(1);
    if (mrt_tbl < 0 || chld.onr == 0) {
        // Main daemon process writes PID.
        char  pidFile[strlen(CONF->runPath) + strlen(fileName) + 6];
        sprintf(pidFile, "%s/%s.pid", CONF->runPath, fileName);
        remove(pidFile);
        FILE *pidFilePtr = fopen(pidFile, "w");
        fprintf(pidFilePtr, "%d\n", getpid());
        fclose(pidFilePtr);
    }

    // Change ownership of run directory.
    if (chown(CONF->runPath, uid, gid) < 0)
        LOG(LOG_CRIT, eNOINIT, "Failed to change ownership of %s to %s:%s.",
            CONF->runPath, CONF->user->pw_name, CONF->group->gr_name);
    // Switch root if chroot is configured. The config file must be placed there.
    if (CONF->chroot) {
        // Truncate config and log file path to /.
        char *b, *c;
        if (! (b = basename(CONF->configFilePath)) || ! (c = calloc(1, strlen(b) + 1)) || ! strcpy(c, b))
            LOG(LOG_CRIT, eNOMEM, "Out of Memory.");
        free(CONF->configFilePath);  // Alloced by main()
        CONF->configFilePath = c;
        if (CONF->logFilePath) {
            if (! (b = basename(CONF->logFilePath)) || ! (c = calloc(1, strlen(b) + 1)) || ! strcpy(c, b))
                LOG(LOG_CRIT, eNOMEM, "Out of Memory.");
            free(CONF->logFilePath);  // Alloced by loadConfig()
            CONF->logFilePath = c;
        }
        // Link the root to the run directory and set runpath to /.
        if (symlink(CONF->chroot, strcat(CONF->runPath, "root")) != 0 && errno != EEXIST)
            // Race with possible childs, it's fine let them win.
            LOG(LOG_CRIT, eNOINIT, "Failed to link chroot directory %s to run directory %s.", CONF->chroot, CONF->runPath);
        strcpy(CONF->runPath, "/");
        // Set permissions and swith root directory.
        if (!(stat(CONF->chroot, &st) == 0 && chown(CONF->chroot, uid, gid) == 0 && chmod(CONF->chroot, 0770) == 0
            && chroot(CONF->chroot) == 0 && chdir("/") == 0))
            LOG(LOG_CRIT, eNOINIT, "Failed to switch root to %s.",CONF->chroot);
        LOG(LOG_WARNING, 0, "Switched root to %s.", CONF->chroot);
    }
    // Finally check log file permissions in case we need to run as user.
    if (CONF->logFilePath && (chown(CONF->logFilePath, uid, gid) || chmod(CONF->logFilePath, 0640)))
        LOG(LOG_ERR, 1, "Failed to chown log file %s to %s.", CONF->logFilePath, CONF->user->pw_name);

    rebuildIfVc(NULL);
    pollFD[1].fd = initCli(1);
    if (mrt_tbl < 0)
        igmpProxyMonitor();

    // Make sure logfile and chroot directory are owned by configured user and switch ids.
    if (CONF->user && geteuid() == 0) {
        unsigned int uid = CONF->user ? CONF->user->pw_uid : 0, gid = CONF->group->gr_gid;
        LOG(CONF->logLevel, 0, "Switching user to %s.", CONF->user->pw_name);
        if (setgroups(1, (gid_t *)&gid) != 0 ||
            setresgid(CONF->user->pw_gid, CONF->user->pw_gid, CONF->user->pw_gid) != 0 ||
            setresuid(uid, uid, uid) != 0)
            LOG(LOG_CRIT, eNOINIT, "Failed to switch to user %s.", CONF->user->pw_name);
    }
}

/**
 *   Monitor process when multiple proxies are running.
 */
static void igmpProxyMonitor(void) {
    struct timespec timeout = (struct timespec){ 0, 0 };
    int             pid, status, i;

    LOG(LOG_WARNING, 0, "Monitoring %d proxy processes.", chld.nr);
    FOR_IF(int i = 0; i < chld.nr; i++, chld.c[i].tbl > 0 && !CONF->disableIpMrules)
        ipRules(chld.c[i].tbl, true);

    sigstatus = 0;
    while (sighandled || ppoll(&pollFD[1], 1, timeout.tv_sec < 0 ? NULL : &timeout, NULL) || true) {
        if (sighandled) {
            if (sighandled & GOT_SIGCHLD) {
                sighandled &= ~GOT_SIGCHLD;
                sigstatus   =  GOT_SIGCHLD;
                while (chld.nr && (pid = waitpid(-1, &status, WNOHANG)) > 0) FOR_IF(i = 0; i < chld.nr; i++, chld.c[i].pid == pid) {
                    chld.c[i].st = WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status);
                    LOG(WIFEXITED(status) ? LOG_INFO : chld.c[i].tbl >= 0 ? LOG_WARNING : LOG_NOTICE, 0,
                        "%s: %d PID: %d for table: %d, %s (%i)", chld.c[i].tbl >= 0 ? "Proxy" : "Child", i + 1, chld.c[i].pid,
                        chld.c[i].tbl, exitmsg[chld.c[i].st], chld.c[i].st);
                    chld.c[i].pid = 0;
                    if (chld.c[i].tbl >= 0 && (   chld.c[i].st == SIGTERM || chld.c[i].st == SIGABRT
                                               || chld.c[i].st == SIGSEGV || chld.c[i].st == SIGKILL)) {
                        // Start new proxy in case of unexpected shutdown.
                        if (igmpProxyFork(chld.c[i].tbl) == 0)
                            break;
                    } else if (chld.c[i].tbl > 0 && !CONF->disableIpMrules)
                        ipRules(chld.c[i].tbl, false);
                }
                if (pid < 0)
                    LOG(LOG_ERR, 1, "SIGCHLD: waitpid() error.");
            } else if (sighandled & (GOT_SIGTERM | GOT_SIGURG | GOT_SIGHUP | GOT_SIGUSR1)) {
                sigstatus    = sighandled & GOT_SIGTERM ? GOT_SIGTERM : sighandled & GOT_SIGURG ? GOT_SIGURG :
                               sighandled & GOT_SIGHUP  ? GOT_SIGHUP  : GOT_SIGUSR1;
                sighandled &= ~GOT_SIGURG & ~GOT_SIGHUP & ~GOT_SIGUSR1;
                LOG(LOG_WARNING, 0, "%s", RESTART  ? "SIGURG: Restarting." : SHUP ? "SIGHUP: Reloading config." :
                                          SHUTDOWN ? "SIGTERM: Exiting."   :        "SIGUSR1: Reloading config.");
                if (RESTART || SHUTDOWN) {
                    igmpProxyCleanUp(0);
                    pollFD[1].fd = initCli(1);
                }
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
        }

        // Check if any cli connection needs to be handled.
        if (mrt_tbl < 0 && pollFD[1].revents & POLLIN)
            acceptCli();
        if (mrt_tbl < 0 && !sighandled)
            timeout = timer_ageQueue();
        if (timeout.tv_nsec < 0)
            timeout.tv_nsec = 0;
        if (mrt_tbl >= 0) {
            // SIGCHLD, ageQueue() or loadConfig() may have forked new proxy.
            rebuildIfVc(NULL);
            return; // To igmpProxyInit()
        }
        errno = sigstatus = pollFD[1].revents = 0;
    }

    LOG(LOG_CRIT, -eABNRML, "Monitor Proceses exited.");
}

/**
 *   Main daemon event loop.
 */
static void igmpProxyRun(void) {
    int    i = 0, Rt = 0, pid, status;
    sigstatus = sighandled = 0;

    LOG(LOG_WARNING, 0, "Starting IGMPv3 Proxy on %s.", tS);
    while (true) {
        // Process signaling.
        struct timespec timeout;
        errno = 0;
        if (sighandled) {
            if (sighandled & GOT_SIGCHLD) {
                sighandled &= ~GOT_SIGCHLD;
                sigstatus   =  GOT_SIGCHLD;
                while ((pid = waitpid(-1, &status, WNOHANG)) > 0) FOR_IF(int i = 0; i < chld.nr; i++, chld.c[i].pid == pid) {
                    chld.c[i].st = WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status);
                    LOG(WIFEXITED(status) ? LOG_INFO : LOG_NOTICE, 0, "Child: %d PID: %d, %s (%i)",
                        i + 1, chld.c[i].pid, exitmsg[chld.c[i].st], chld.c[i].st);
                    chld.c[i].pid = 0;
                }
            } else if (sighandled & GOT_SIGURG || sighandled & GOT_SIGTERM) {
                sigstatus   =  sighandled & GOT_SIGTERM ? GOT_SIGTERM : GOT_SIGURG;
                sighandled &= ~GOT_SIGURG & ~GOT_SIGTERM;
                break;
            } else if (sighandled & GOT_SIGHUP || sighandled & GOT_SIGUSR1) {
                sigstatus = sighandled & GOT_SIGHUP ? GOT_SIGHUP : GOT_SIGUSR1;
                sighandled &= ~GOT_SIGHUP & ~GOT_SIGUSR1;
                LOG(LOG_NOTICE, 0, "%s: Reloading config%s.",
                    SHUP ? "SIGHUP" : "SIGUSR1", SHUP ? " and rebuilding interfaces" : "");
                reloadConfig(NULL);
            } else if (sighandled & GOT_SIGUSR2) {
                sighandled &= ~GOT_SIGUSR2;
                sigstatus   =  GOT_SIGUSR2;
                LOG(LOG_NOTICE, 0, "SIGUSR2: Rebuilding interfaces.");
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
            LOG(LOG_ERR, 1, "ppoll() error.");
        else if (!sighandled && Rt > 0) do {
            errno = 0;
            clock_gettime(CLOCK_REALTIME, &timeout);
            // Handle incoming IGMP request first.
            if (pollFD[0].revents & POLLIN) {
                LOG(LOG_DEBUG, 0, "RECV IGMP Request %d.", i);
                acceptIgmp(pollFD[0].fd);
            }
            // Check if any cli connection needs to be handled.
            if (pollFD[1].revents & POLLIN)
                acceptCli();

            clock_gettime(CLOCK_REALTIME, &curtime);
            LOG(LOG_DEBUG, 0, "Fnished request %d in %dus.", i, timeDiff(timeout, curtime).tv_nsec / 1000);
            // Keep handling request until timeout, signal or max nr of queued requests to process in 1 loop.
        } while (!sighandled && i++ <= CONF->reqQsz && (Rt = ppoll(pollFD, 2, &nto, NULL)));
    }
    LOG(LOG_WARNING, 0, "%s", SHUTDOWN ? "SIGTERM: Exiting." : "SIGURG: Restarting");
}

/**
*   Shutdown all interfaces, queriers, remove all routes, close sockets.
*/
void igmpProxyCleanUp(int code) {
    int    nr = 0, pid, status;
    char   msg[24];

    FOR_IF (int i = 0; i < chld.nr; i++, chld.c[i].pid > 0 && (SHUTDOWN || chld.c[i].tbl == mrt_tbl))
        nr++;
    if (code == 0 && mrt_tbl >= 0)
        code = SIGTERM;
    if (chld.nr) {
        if (nr)
            LOG(LOG_NOTICE, 0, "Waiting for %d process%s to finish.", nr, nr != 1 ? "es" : "");
        while (nr && (pid = waitpid(-1, &status, 0)) > 0) FOR_IF(int i = 0; i < chld.nr; i++, chld.c[i].pid == pid) {
            chld.c[i].st = WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status);
            sprintf(msg, "for table %d, ", chld.c[i].tbl);
            LOG(chld.c[i].tbl != mrt_tbl ? LOG_NOTICE : LOG_INFO, 0, "%s %d, %sPID: %d, %s (%d).",
                chld.c[i].tbl == mrt_tbl ? "Child" : "Proxy", i + 1, chld.c[i].tbl == mrt_tbl ? "" : msg,
                pid, exitmsg[chld.c[i].st], chld.c[i].st);
            chld.c[i].pid = nr = 0;
            if (chld.c[i].tbl > 0 && !CONF->disableIpMrules)
                ipRules(chld.c[i].tbl, false);
            FOR_IF (int i = 0; i < chld.nr; i++, chld.c[i].pid > 0 && (!RESTART || chld.c[i].tbl == mrt_tbl))
                nr++;
            if (nr)
                LOG(LOG_INFO, 0, "Still waiting for %d process%s to finish.", nr, nr != 1 ? "es" : "");
        }

        if (!RESTART || mrt_tbl >= 0)
            _free(chld.c, var, (((chld.nr - 1) / 32) + 1) * 32 * sizeof(struct pt));  // Alloced by igmpProxyFork()
        LOG(LOG_WARNING, 0, "All processes finished.");
    }

    // Remove all interfaces, CLI socket, PID file and Config.
    rebuildIfVc(NULL);
    pollFD[1].fd = initCli(0);
    pollFD[0].fd = initIgmp(0);
    if ((mrt_tbl < 0 || chld.onr == 0) && !RESTART && CONF->runPath) {
        char rFile[strlen(CONF->runPath) + strlen(fileName) + 5];
        sprintf(rFile, "%s%s.pid", CONF->runPath, fileName);
        remove(rFile);
        sprintf(rFile, "%scli.sock", CONF->runPath);
        remove(rFile);
        if (! CONF->chroot && rmdir(CONF->runPath) < 0)
            LOG(LOG_ERR, 1, "Cannot remove run dir %s.", CONF->runPath);
    }
    if (!RESTART)
        // On SIGURG reloadConfig will clear old config.
        freeConfig(false);
    getMemStats(0, -1);

    // Log shutdown.
    TIME_STR(tE, curtime);
    LOG(LOG_WARNING, 0, "%s on %s. Running since %s (%ds).", RESTART ? "Restarting" : "Shutting down",
                         tE, tS, timeDiff(starttime, curtime).tv_sec);
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
        if ((mrt_tbl < 0 || (mrt_tbl == 0 && chld.onr == 0)) && !CONF->notAsDaemon)
            return;  // Daemon / Monitor ignores SIGINT
        sighandled |= GOT_SIGINT;  // Fallthrough
    case SIGTERM:
        sighandled |= GOT_SIGTERM;
        if (SHUTDOWN) {
            // If SIGTERM received more than once, KILL childs and exit.
            IF_FOR_IF(mrt_tbl < 0 && chld.nr, i = 0; i < chld.nr; i++, chld.c[i].pid > 0) {
                kill(chld.c[i].pid, SIGKILL);
            }
            exit(sig);
        }
        BLOCKSIGS;
        if (sig == SIGINT)
            return;
        break;
    case SIGCHLD:
        sighandled |= GOT_SIGCHLD;
        return;
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
    }
    // Send SIG to children, except for SIGINT SIGPIPE and SIGCHLD.
    // If monitor is terminating we will end childs with SIGINT.
    IF_FOR_IF(mrt_tbl < 0 && chld.c, i = 0; i < chld.nr; i++, chld.c[i].pid > 0)
        kill(chld.c[i].pid, sig == SIGTERM ? SIGINT : sig);
}
