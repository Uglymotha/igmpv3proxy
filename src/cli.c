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
*   Contains function for cli control and status of daemon.
*/

#include "igmpv3proxy.h"

// Local Prototypes.
static void cliSignalHandler(int sig);

// Daemon CLI socket address.
static int                   cli_fd = -1;
static struct sockaddr_un    cli_sa;
extern volatile sig_atomic_t sighandled;  // From igmpv3proxy.c signal handler.

/**
*   Opens and binds a socket for cli connections.
*/
int openCliFd(void) {
    struct stat st;
    memset(&cli_sa, 0, sizeof(struct sockaddr_un));
    cli_sa.sun_family = AF_UNIX;

    // Open the socket, set permissions and mode.
    if (cli_fd == -1) {
        if (   ! strcpy(cli_sa.sun_path, CONF->runPath)
        || ! snprintf(cli_sa.sun_path + strlen(cli_sa.sun_path), PATH_MAX - strlen(cli_sa.sun_path),
                      mrt_tbl ? "cli-%d.sock" : "cli.sock", mrt_tbl)
        ||   (stat(cli_sa.sun_path, &st) == 0 && unlink(cli_sa.sun_path) < 0)
        || ! (cli_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0))
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
        || ! (cli_sa.sun_len = SUN_LEN(&cli_sa))
        ||    bind(cli_fd, (struct sockaddr *)&cli_sa, cli_sa.sun_len) < 0
#else
        ||    bind(cli_fd, (struct sockaddr *)&cli_sa, sizeof(struct sockaddr_un)) < 0
#endif
        ||    listen(cli_fd, CONF->reqQsz) < 0
        ||  (     chown(cli_sa.sun_path, CONF->user ? CONF->user->pw_uid : -1, CONF->group->gr_gid))
               || chmod(cli_sa.sun_path, 0660)) {
            LOG(LOG_WARNING, errno, "Cannot open CLI Socket %s. CLI connections will not be available.", cli_sa.sun_path);
            cli_fd = -1;
        } else
            LOG(LOG_INFO, 0, "openCliFd: Opened CLI socket %s.", cli_sa.sun_path);
    }
    return cli_fd;
}

/**
*   Close and unlink CLI socket.
*/
int closeCliFd(void) {
    if (!RESTART && cli_fd >= 0) {
        if (!STARTUP)
            shutdown(cli_fd, SHUT_RDWR);
        if (close(cli_fd) < 0)
            LOG(LOG_WARNING, errno, "closeCliFd: CLOSE %s", cli_sa.sun_path);
        else {
            LOG(LOG_INFO, 0, "closeCliFd: Closed CLI socket %s.", cli_sa.sun_path);
            cli_fd = -1;
        }
        if (!STARTUP)
            unlink(cli_sa.sun_path);
    }
    return cli_fd;
}

/**
*   Processes an incoming cli connection. Requires the fd of the cli socket.
*/
void acceptCli(void)
{
    int                 pid = -1, fd = -1, len = 0, s = sizeof(struct sockaddr);
    uint32_t            addr = (uint32_t)-1, mask = (uint32_t)-1;
    char                buf[CLI_CMD_BUF] = {0}, msg[CLI_CMD_BUF];
    struct sockaddr     cli_sa;
    struct IfDesc      *IfDp = NULL;

    // Receive and answer the cli request.
    if ((fd = accept(cli_fd, &cli_sa, (socklen_t *)&s)) < 0) {
        LOG(LOG_WARNING, errno, "acceptCli: Failed accept()");
        return;
    } else {
        LOG(LOG_DEBUG, 0, "acceptCli: RECV CLI Request.");
        if ((len = recv(fd, &buf, CLI_CMD_BUF, MSG_DONTWAIT)) <= 0 || len > CLI_CMD_BUF ||
            (buf[0] == 'r' && len > 2 &&
            (!parseSubnetAddress(&buf[buf[1] == 'h' ? 3 : 2], &addr, &mask) || !IN_MULTICAST(ntohl(addr))))) {
            LOG(LOG_DEBUG, 0, "acceptCli: Invalid command received.");
        } else if (buf[0] == 'c' || buf[0] == 'b') {
            sighandled |= buf[0] == 'c' ? GOT_SIGUSR1 : GOT_SIGUSR2;
            buf[0] == 'c' ? send(fd, "Reloading Configuration.\n", 26, MSG_DONTWAIT)
                          : send(fd, "Rebuilding Interfaces.\n", 24, MSG_DONTWAIT);
            IF_FOR_IF(mrt_tbl < 0 && chld.nr, int i = 0; i < chld.nr; i++, chld.c[i].pid > 0)
                kill(chld.c[i].pid, buf[0] == 'c' ? SIGUSR1 : SIGUSR2);
        } else if ((pid = fork()) != 0)
            pid < 0 ? LOG(LOG_WARNING, eNOFORK, "Cannot fork().") : LOG(LOG_DEBUG, 0, "acceptCli: Forked PID: %d", pid);
        if (pid != 0 || buf[0] == 'c' || buf[0] == 'b') {
            close(fd);
            return;
        }
    }
    if (buf[0] == 'r') {
        logRouteTable("", buf[1] == 'h' ? 0 : 1, fd, addr, mask);
    } else if ((buf[0] == 'i' || buf[0] == 'f')  && len > 2 && ! (IfDp = getIf(0, &buf[buf[1] == 'h' ? 3 : 2], 2))) {
        sprintf(msg, "Interface %s Not Found\n", &buf[buf[1] == 'h' ? 3 : 2]);
        send(fd, msg, strlen(msg), MSG_DONTWAIT);
    } else if (buf[0] == 'i') {
        getIfStats(IfDp, buf[1] == 'h' ?  0 : 1, fd);
    } else if (buf[0] == 'f') {
        getIfFilters(IfDp, len > 1 && buf[1] == 'h' ? 0 : 1, fd);
    } else if (buf[0] == 't') {
        debugQueue("", len > 1 && buf[1] == 'h' ? 0 : 1, fd);
    } else if (buf[0] == 'm') {
        getMemStats(buf[1] == 'h' ?  0 : 1, fd);
    } else if (buf[0] == 'p' && mrt_tbl < 0) {
        sprintf(msg, "Monitor PID: %d\n", getppid());
        send(fd, msg, strlen(msg), MSG_DONTWAIT);
        for (int i = 0; i < chld.nr; i++) {
            if (chld.c[i].pid > 0)
                sprintf(msg, "Table: %d - PID: %d\n", chld.c[i].tbl, chld.c[i].pid);
            else
                sprintf(msg, "Table: %d - %s\n", chld.c[i].tbl, exitmsg[chld.c[i].st]);
            send(fd, msg, strlen(msg), MSG_DONTWAIT);
        }
    } else if (buf[0] == 'p' && mrt_tbl >= 0) {
        sprintf(msg, "Table: %d - PID: %d\n", mrt_tbl, getppid());
        send(fd, msg, strlen(msg), MSG_DONTWAIT);
    } else
        send(fd, "GO AWAY\n", 9, MSG_DONTWAIT);

    // Close connection.
    close(fd);
    LOG(LOG_DEBUG, 0, "acceptCli: Finished command %s.", buf);
    exit(0);
}

// Below are functions and definitions for client connections.
static int                srv_fd = -1;

/**
*   Sends command to daemon and writes response to stdout. Error exit if socket cannot be connected.
*/
void cliCmd(char *cmd, int tbl) {
    struct sigaction   sa;
    struct stat        st;
    struct sockaddr_un srv_sa;
    char               buf[CLI_CMD_BUF+1] = "", *path, tpath[128];

    sa.sa_handler = cliSignalHandler;
    sa.sa_flags = 0;    /* Interrupt system calls */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGURG, &sa, NULL);

    memset(&srv_sa, 0, sizeof(struct sockaddr_un));
    srv_sa.sun_family = AF_UNIX;
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
    srv_sa.sun_len = SUN_LEN(&srv_sa);
#endif

    // Check for daemon socket location.
    path = strtok(RUN_PATHS, " ");
    while (path) {
        sprintf(tpath, "%s/%s/root", path, fileName);
        if (lstat(tpath, &st) == 0 && (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode))) {
            if (tbl != 0)
                sprintf(srv_sa.sun_path, "/%s/%s/root/cli-%d.sock", path, fileName, tbl);
            else
                sprintf(srv_sa.sun_path, "/%s/%s/root/cli.sock", path, fileName);
            break;
        }
        if (tbl != 0)
            sprintf(tpath, "%s/%s/cli-%d.sock", path, fileName, tbl);
        else
            sprintf(tpath, "%s/%s/cli.sock", path, fileName);
        if (stat(tpath, &st) != -1) {
            strcpy(srv_sa.sun_path, tpath);
            break;
        }
        path = strtok(NULL, " ");
    }

    // Open and bind socket for receiving answers from daemon.
    if (strcmp(srv_sa.sun_path, "") == 0 || (srv_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0
           || connect(srv_fd, (struct sockaddr*)&srv_sa, sizeof(struct sockaddr_un)) != 0) {
        fprintf(stderr, "Cannot open daemon socket (%s). %s\n", srv_sa.sun_path, strerror(errno));
        exit(-1);
    }
    if (send(srv_fd, cmd, strlen(cmd), 0) < 0) {
        fprintf(stderr, "Cannot send command. %s\n", strerror(errno));
        exit(-1);
    }
    // Receive the daemon's answer. It will be closed by one single byte.
    for (int len = 0; (len = recv(srv_fd, &buf, CLI_CMD_BUF, 0)) > 0; buf[len] = '\0', fprintf(stdout, "%s", buf));
    close(srv_fd);
}

static void cliSignalHandler(int sig) {
    switch (sig) {
    case SIGINT:
    case SIGTERM:
    case SIGURG:
    case SIGPIPE:
        if (srv_fd != -1)
            close(srv_fd);
        fprintf(stdout, "Terminated.\n");
        exit(1);
    }
}
