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
*   Contains function for cli control of daemon. It's a simple question -> answer implementation.
*/

#include "igmpv3proxy.h"

// Local Prototypes.
static void signalHandler(int sig);

// Daemon Cli socket address.
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
        || ! (cliSockAddr.sun_len = SUN_LEN(&cliSockAddr))
        ||    bind(cli_fd, (struct sockaddr *)&cliSockAddr, cliSockAddr.sun_len) < 0
#else
        ||    bind(cli_fd, (struct sockaddr *)&cli_sa, sizeof(struct sockaddr_un)) < 0
#endif
        ||    listen(cli_fd, CONFIG->reqQsz) < 0
        ||  (     chown(cli_sa.sun_path, CONFIG->user ? CONFIG->user->pw_uid : -1, CONFIG->socketGroup->gr_gid))
               || chmod(cli_sa.sun_path, 0660)) {
        LOG(LOG_WARNING, errno, "Cannot open CLI Socket %s. CLI connections will not be available.", cli_sa.sun_path);
        cli_fd = -1;
    }

    return cli_fd;
} 

/**
*   Sets access for specified path and group to configured cligroup.
*/
void cliSetGroup(struct group *gid) {
    if (chown(cli_sa.sun_path, CONFIG->user ? CONFIG->user->pw_uid : 0, gid->gr_gid))
        LOG(LOG_ERR, errno, "cliSetGroup: cannot chown %s to %s.", cli_sa.sun_path, CONFIG->user ? CONFIG->user->pw_name : "root");
    if (chown(CONFIG->runPath, CONFIG->user ? CONFIG->user->pw_uid : 0, gid->gr_gid))
        LOG(LOG_ERR, errno, "cliSetGroup: cannot chown %s to %s.", CONFIG->runPath, CONFIG->user ? CONFIG->user->pw_name : "root");
}

/**
*   Processes an incoming cli connection. Requires the fd of the cli socket.
*/
void acceptCli(int fd) {
    int                 cli_fd = -1, len = 0, s = sizeof(struct sockaddr_un);
    uint32_t            addr, mask;
    char                buf[CLI_CMD_BUF] = {0};
    struct sockaddr_un  cli_sa;

    memset(&cli_sa, 0, sizeof(struct sockaddr_un));
    cli_sa.sun_family = AF_UNIX;
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
    cli_sa.sun_len = SUN_LEN(&cli_sa);
#endif

    // Receive and answer the cli request.
    cli_fd = accept(fd, &cli_sa, (socklen_t *)&s);
    len = recv(cli_fd, &buf, CLI_CMD_BUF, MSG_DONTWAIT);

    if (len <= 0 || len > CLI_CMD_BUF) {
        close(cli_fd);
        return;
    } else if (buf[0] == 'r') {
        if (len > 2 && parseSubnetAddress(buf[1] == 'h'? &buf[2] : &buf[1], &addr, &mask))
            send(cli_fd, "GO AWAY\n\0", 9, MSG_DONTWAIT);
        else
            logRouteTable("", buf[1] == 'h' ? 0 : 1, cli_fd);
    } else if (buf[0] == 'i') {
        getIfStats(buf[1] == 'h' ?  0 : 1, cli_fd);
    } else if (buf[0] == 'f') {
        getIfFilters(buf[1] == 'h' ? 0 : 1, cli_fd);
    } else if (buf[0] == 't') {
        debugQueue("", buf[1] == 'h' ? 0 : 1, cli_fd);
    } else if (buf[0] == 'c') {
        sighandled |= GOT_SIGUSR1;
        send(cli_fd, "Reloading Configuration.\n\0", 26, MSG_DONTWAIT);
    } else if (buf[0] == 'b') {
        sighandled |= GOT_SIGUSR2;
        send(cli_fd, "Rebuilding Interfaces.\n\0", 24, MSG_DONTWAIT);
    } else
        send(cli_fd, "GO AWAY\n\0", 9, MSG_DONTWAIT);

    // Close connection.
    close(cli_fd);
    LOG(LOG_DEBUG, 0, "Cli: Finished command %s.", buf);
}

// Below are functions and definitions for client connections.
static int                srv_fd = -1, cli_fd = -1;

/**
*   Sends command to daemon and writes response to stdout. Error exit if socket cannot be connected.
*/
void cliCmd(char *cmd) {
    struct sigaction   sa;
    struct stat        st;
    struct sockaddr_un srv_sa;
    bool               cli = strcmp(cmd, "cli") == 0 ? true : false;
    char               buf[CLI_CMD_BUF] = "", paths[sizeof(CLI_SOCK_PATHS)] = CLI_SOCK_PATHS, *path, tpath[50];

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

    // Check for daemon socket.
    path = strtok(paths, " ");
    while (path) {
        sprintf(tpath, "%s/%s/cli.sock", path, fileName);
        if (stat(tpath, &st) != -1) {
            strcpy(srv_sa.sun_path, tpath);
            break;
        }
        path = strtok(NULL, " ");
    }

    // Open and bind socket for receiving answers from daemon.
    if (strcmp(srv_sa.sun_path, "") == 0 || (srv_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1
           || (cli_fd = connect(srv_fd, (struct sockaddr*)&srv_sa, sizeof(struct sockaddr_un))) < 0) {
        fprintf(stdout, "Cannot open socket %s. %s\n", srv_sa.sun_path, strerror(errno));
        exit(-1);
    }

    for (cmd = cli ? fgets(buf, CLI_CMD_BUF, stdin) : strcpy(buf, cmd); cmd && strcmp("done\n", buf) != 0
                   && strcmp(".\n", buf) != 0 && strlen(buf) < CLI_CMD_BUF; cmd = fgets(buf, CLI_CMD_BUF, stdin)) {
        if (send(srv_fd, buf, cli ? strlen(buf) - 1 : strlen(buf), 0) < 0) {
            fprintf(stdout, "Cannot send command. %s\n", strerror(errno));
            exit(-1);
        }

        // Receive the daemon's answer. It will be closed by one single byte.
        for (int len = recv(srv_fd, &buf, sizeof(buf), 0); len > 0; len = recv(srv_fd, &buf, sizeof(buf), 0)) {
            fprintf(stdout, "%s", buf);
            memset(buf, 0, len);
        }
        if (! cli)
            break;
    }

    close(cli_fd);
}

static void signalHandler(int sig) {
    switch (sig) {
    case SIGINT:
    case SIGTERM:
    case SIGURG:
    case SIGPIPE:
        if (cli_fd != -1)
            close(cli_fd);
        fprintf(stdout, "Terminated.\n");
        exit(1);
    }
}
