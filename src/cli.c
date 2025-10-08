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
static int                cli_fd = -1;
static struct sockaddr_un cli_sa;
extern volatile uint64_t  sighandled;  // From igmpv3proxy.c signal handler.

/**
 *  Returns cli fd.
**/
int getCliFd(void) {
    return cli_fd;
}

/**
*   Opens, closes and binds a socket for cli connections.
*   mode - 0: close, 1: open, 2: reopen.
*/
int initCli(int mode) {
    struct stat st;

    // Do not reopen socket if it is not open.
    if (mode == 2 && cli_fd < 0)
        return cli_fd;
    if (mode != 1 && cli_fd >= 0) {
        if (mode == 0 && !SPROXY)
            shutdown(cli_fd, SHUT_RDWR);
        if (close(cli_fd) < 0)
            LOG(LOG_ERR, 1, "CLI socket close %s failed", cli_sa.sun_path);
        else {
            LOG(LOG_NOTICE, 0, "Closed CLI socket %s.", cli_sa.sun_path);
            cli_fd = -1;
        }
        if (mode == 0 && !SPROXY)
            unlink(cli_sa.sun_path);
    }
    // Open the socket, set permissions and mode.
    if (mode > 0 && cli_fd == -1) {
        memset(&cli_sa, 0, sizeof(struct sockaddr_un));
        cli_sa.sun_family = AF_UNIX;
        if (   !strncpy(cli_sa.sun_path, CONF->runPath, sizeof(cli_sa.sun_path))
            || !snprintf(cli_sa.sun_path + strlen(cli_sa.sun_path), sizeof(cli_sa.sun_path) - strlen(cli_sa.sun_path),
                          mrt_tbl >= 0 && chld.onr > 0 ? "cli-%d.sock" : "cli.sock", mrt_tbl)
            ||   (stat(cli_sa.sun_path, &st) == 0 && unlink(cli_sa.sun_path) < 0)
            || !(cli_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0))
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
            || !(cli_sa.sun_len = SUN_LEN(&cli_sa))
            ||  bind(cli_fd, (struct sockaddr *)&cli_sa, cli_sa.sun_len) < 0
#else
            ||  bind(cli_fd, (struct sockaddr *)&cli_sa, sizeof(struct sockaddr_un)) < 0
#endif
            ||  listen(cli_fd, CONF->reqQsz) < 0
            ||  (   chown(cli_sa.sun_path, CONF->user ? CONF->user->pw_uid : -1, CONF->group->gr_gid))
                 || chmod(cli_sa.sun_path, 0660)) {
            LOG(LOG_ERR, 1, "Cannot open CLI Socket %s. CLI connections will not be available.", cli_sa.sun_path);
            cli_fd = -1;
        } else
            LOG(LOG_NOTICE, 0, "Opened CLI socket %s.", cli_sa.sun_path);
    }
    return cli_fd;
}

/**
*   Processes an incoming cli connection. Requires the fd of the cli socket.
*/
bool acceptCli(void)
{
    int                 pid, len = 0, fd = -1, s = sizeof(struct sockaddr), h;
    uint32_t            addr = (uint32_t)-1, mask = (uint32_t)-1;
    struct sockaddr     cli_sa;
    struct IfDesc      *IfDp = NULL;
    static int          i = 0;

    // Receive and answer the cli request.
    if ((fd = accept(cli_fd, &cli_sa, (socklen_t *)&s)) < 0 && ++i <= 10) {
        LOG(errno == EAGAIN ? LOG_NOTICE : LOG_WARNING, 1, "failure %d in cli accept().", i);
        return true;
    } else if (i > 10) {
        LOG(LOG_ERR, errno, "Too many failures in cli accept(). Reopening socket.");
        i = 0;
        return false;
    } else if ((pid = igmpProxyFork(NULL)) != 0) {
        if (pid < 0)
            send(fd, "Cannot fork()\n", 14, MSG_DONTWAIT);
        close(fd);
        i = 0;
        return true;
    }
    // Child answers cli request.
    char *buf = strFmt(1, "", "");
    while (!(errno = 0) && (len = recv(fd, buf, STRBUF, MSG_DONTWAIT)) <= 0 && errno == EAGAIN && ++i <= 10)
        nanosleep(&(struct timespec){0, 10000000}, NULL);
    if (i > 10)
        exit(1);
    LOG(LOG_INFO, 0, "RECV CLI Request: '%s'.", buf);
    h = len > 1 && buf[1] == 'h' ? 0 : 1;
    if (len <= 0 || len > STRBUF) {
        LOG(LOG_WARNING, 1, "Error receiving CLI (%d) command. %s", chld.onr, &buf);
        buf = strFmt(1, "Error connecting to daemon. %s", "", strerror(errno));
    } else if (buf[0] == 'r' || buf[0] == 'i' || buf[0] == 'f') {
        i = h ? 2 : 3;
        if (len > i && (! (IfDp = getIf(0, &buf[i], FINDNAME | (mrt_tbl < 0 ? 0 : SRCHVIFL)))
                    && (buf[0] != 'r' || !parseSubnetAddress(&buf[i], &addr, &mask) || !IN_MULTICAST(ntohl(addr))))) {
            LOG(LOG_WARNING, 0, strFmt(buf[0] == 'r', "CLI (%d) %s invalid interface or subnet/mask.",
                                       "CLI (%d) interface %s not found.", chld.onr, &buf[i]));
            buf = strFmt(buf[0] == 'r', "'%s' is not a valid interface, subnet/mask or multicast address.\n",
                         "Interface '%s' Not Found.\n", &buf[i]);
        } else {
            if (buf[0] == 'r')
                logRouteTable("", h, fd, addr, mask, IfDp);
            else if (buf[0] == 'i')
                getIfStats(IfDp, h, fd);
            else if (buf[0] == 'f')
                getIfFilters(IfDp, h, fd);
            buf[0] = 0;
        }
    } else if (buf[0] == 'c' || buf[0] == 'b') {
        sighandled |= buf[0] == 'c' ? GOT_SIGUSR1 : GOT_SIGUSR2;
        buf = strFmt(buf[0] == 'c', "Reloading Configuration.\n", "Rebuilding Interfaces.\n");
        kill(getppid(), buf[0] == 'c' ? SIGUSR1 : SIGUSR2);
    } else if (buf[0] == 't') {
        DEBUGQUEUE("", h, fd);
        buf[0] = 0;
    } else if (buf[0] == 'm') {
        getMemStats(h, fd);
    } else if (buf[0] == 'p' && mrt_tbl < 0) {
        sprintf(buf, "Monitor PID: %d\n", getppid());
        FOR_IF((i = 0; i < chld.nr; i++), chld.c[i].tbl >= 0) {
            if (chld.c[i].pid > 0)
                sprintf(&buf[strlen(buf)], "Table: %d - PID: %d\n", chld.c[i].tbl, chld.c[i].pid);
            else
                sprintf(&buf[strlen(buf)], "Table: %d - %s\n", chld.c[i].tbl, exitmsg[chld.c[i].st]);
            send(fd, buf, strlen(buf), MSG_DONTWAIT);
            buf[0] = 0;
        }
    } else if (buf[0] == 'p' && mrt_tbl >= 0) {
        sprintf(buf, "Table: %d - PID: %d\n", mrt_tbl, getppid());
    } else
        sprintf(buf, "GO AWAY\n");

    // Close connection.
    if (strlen(buf))
        send(fd, buf, strlen(buf), MSG_DONTWAIT);
    close(fd);
    LOG(errno ? LOG_NOTICE : LOG_DEBUG, errno, "%s CLI command.", errno ? "Failed" : "Finished");
    exit(errno > 0);
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
    char               buf[STRBUF+1] = "", *path, tpath[128];

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
            if (tbl >= 0)
                sprintf(srv_sa.sun_path, "/%s/%s/root/cli-%d.sock", path, fileName, tbl);
            else
                sprintf(srv_sa.sun_path, "/%s/%s/root/cli.sock", path, fileName);
            break;
        }
        if (tbl >= 0)
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
        fprintf(stderr, "Cannot open daemon socket. %s\n", strerror(errno));
        exit(-1);
    }
    if (send(srv_fd, cmd, strlen(cmd) + 1, 0) < 0) {
        fprintf(stderr, "Cannot send command. %s\n", strerror(errno));
        exit(-1);
    }
    // Receive the daemon's answer. It will be closed by one single byte.
    for (int len = 0; (len = recv(srv_fd, &buf, STRBUF, 0)) > 0; buf[len] = '\0', fprintf(stdout, "%s", buf));
    close(srv_fd);
}

static void cliSignalHandler(int sig) {
    if (sig == SIGPIPE)
        fprintf(stderr, "Connection reset by daemon.\n");
    else
        fprintf(stderr, "Terminated.\n");
    if (srv_fd >= 0)
        close(srv_fd);
    exit(sig);
}
