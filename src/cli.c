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
*   Contains function for cli control and status of daemon.
*/

#include "igmpv3proxy.h"

// Local Prototypes.
static void signalHandler(int sig);

// Daemon CLI socket address.
static struct sockaddr_un cli_sa;

/**
*   Opens and binds a socket for cli connections.
*/
int openCliFd(void) {
    struct stat st;
    int         cli_fd;

    memset(&cli_sa, 0, sizeof(struct sockaddr_un));
    cli_sa.sun_family = AF_UNIX;

    // Open the socket, set permissions and mode.
    if (   ! strcat(strcpy(cli_sa.sun_path, CONFIG->runPath), "cli.sock")
        ||   (stat(cli_sa.sun_path, &st) == 0 && unlink(cli_sa.sun_path) < 0)
        || ! (cli_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0))
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
        || ! (cli_sa.sun_len = SUN_LEN(&cli_sa))
        ||    bind(cli_fd, (struct sockaddr *)&cli_sa, cli_sa.sun_len) < 0
#else
        ||    bind(cli_fd, (struct sockaddr *)&cli_sa, sizeof(struct sockaddr_un)) < 0
#endif
        ||    listen(cli_fd, CONFIG->reqQsz) < 0
        ||  (     chown(cli_sa.sun_path, CONFIG->user ? CONFIG->user->pw_uid : -1, CONFIG->group->gr_gid))
               || chmod(cli_sa.sun_path, 0660)) {
        LOG(LOG_WARNING, errno, "Cannot open CLI Socket %s. CLI connections will not be available.", cli_sa.sun_path);
        cli_fd = -1;
    }

    return cli_fd;
}

/**
*   Close and unlink CLI socket.
*/
void closeCliFd(int fd) {
    shutdown(fd, SHUT_RDWR);
    close(fd);
    unlink(cli_sa.sun_path);
}

/**
*   Processes an incoming cli connection. Requires the fd of the cli socket.
*/
void acceptCli(int fd) {
    int                 cli_fd = -1, len = 0, s = sizeof(struct sockaddr);
    uint32_t            addr = (uint32_t)-1, mask = (uint32_t)-1;
    char                buf[CLI_CMD_BUF] = {0}, msg[CLI_CMD_BUF];
    struct sockaddr     cli_sa;
    struct IfDesc      *IfDp = NULL;

    // Receive and answer the cli request.
    cli_fd = accept(fd, &cli_sa, (socklen_t *)&s);
    len = recv(cli_fd, &buf, CLI_CMD_BUF, MSG_DONTWAIT);

    if ( len <= 0 || len > CLI_CMD_BUF ||
        (buf[0] == 'r' && len > 2 &&
         (!parseSubnetAddress(&buf[buf[1] == 'h' ? 3 : 2], &addr, &mask) || !IN_MULTICAST(ntohl(addr))))) {
        LOG(LOG_DEBUG, 0, "acceptCli: Invalid command received.");
    } else if (buf[0] == 'r') {
        logRouteTable("", buf[1] == 'h' ? 0 : 1, cli_fd, addr, mask);
    } else if (buf[0] == 'i' && len > 2 && ! (IfDp = getIf(0, &buf[buf[1] == 'h' ? 3 : 2], 2))) {
        sprintf(msg, "Interface %s Not Found\n", &buf[buf[1] == 'h' ? 3 : 2]);
        send(cli_fd, msg, strlen(msg), MSG_DONTWAIT);
    } else if (buf[0] == 'i') {
        getIfStats(IfDp, buf[1] == 'h' ?  0 : 1, cli_fd);
    } else if (buf[0] == 'f') {
        getIfFilters(len > 1 && buf[1] == 'h' ? 0 : 1, cli_fd);
    } else if (buf[0] == 't') {
        debugQueue("", len > 1 && buf[1] == 'h' ? 0 : 1, cli_fd);
    } else if (buf[0] == 'c') {
        sighandled |= GOT_SIGUSR1;
        send(cli_fd, "Reloading Configuration.\n", 26, MSG_DONTWAIT);
    } else if (buf[0] == 'b') {
        sighandled |= GOT_SIGUSR2;
        send(cli_fd, "Rebuilding Interfaces.\n", 24, MSG_DONTWAIT);
    } else
        send(cli_fd, "GO AWAY\n", 9, MSG_DONTWAIT);

    // Close connection.
    close(cli_fd);
    LOG(LOG_DEBUG, 0, "acceptCli: Finished command %s.", buf);
}

// Below are functions and definitions for client connections.
static int                srv_fd = -1;

/**
*   Sends command to daemon and writes response to stdout. Error exit if socket cannot be connected.
*/
void cliCmd(char *cmd) {
    struct sigaction   sa;
    struct stat        st;
    struct sockaddr_un srv_sa;
    char               buf[CLI_CMD_BUF+1] = "", paths[sizeof(RUN_PATHS)] = RUN_PATHS, *path, tpath[128];

    sa.sa_handler = signalHandler;
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
    path = strtok(paths, " ");
    while (path) {
        sprintf(tpath, "%s/%s/root", path, fileName);
        if (lstat(tpath, &st) == 0 && (S_ISLNK(st.st_mode) || S_ISDIR(st.st_mode))) {
            strcpy(srv_sa.sun_path, strcat(tpath, "/cli.sock"));
            break;
        }
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

    if (send(srv_fd, cmd, strlen(cmd), 0) < 0) {
        fprintf(stderr, "Cannot send command. %s\n", strerror(errno));
        exit(-1);
    }

    // Receive the daemon's answer. It will be closed by one single byte.
    for (int len = 0; (len = recv(srv_fd, &buf, CLI_CMD_BUF, 0)) > 0; buf[len] = '\0', fprintf(stdout, "%s", buf));

    close(srv_fd);
}

static void signalHandler(int sig) {
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
