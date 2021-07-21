/*
**  igmpv3proxy - IGMP proxy based multicast router
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
*/

/**
*   Contains function for cli control of daemon. It's a simple question -> answer implementation.
*/

#include "igmpv3proxy.h"

// Local Prototypes.
static void signalHandler(int sig);

// Daemon Cli socket address.
static struct sockaddr_un cliSockAddr;

/**
*   Opens and binds a socket for cli connections.
*/
int openCliSock(void) {
    struct stat    st;
    int            cliSock;

    memset(&cliSockAddr, 0, sizeof(struct sockaddr_un));
    cliSockAddr.sun_family = AF_UNIX;

    // Check for valid location to place socket and PID file.
    char paths[sizeof(CLI_SOCK_PATHS)] = CLI_SOCK_PATHS, *path;
    for (path = strtok(paths, " "); path; path = strtok(NULL, " ")) {
        if (stat(path, &st) != -1) {
            if (! (CONFIG->runPath = malloc(strlen(path) + 12)))
                LOG(LOG_ERR, 0, "openCliSock: Out of memory.");   // Freed by igmpProxyCleanup()
            strcpy(CONFIG->runPath, strcat(path, "/igmpv3proxy/"));
            break;
        }
    }

    // Open the socket after directory exists / created etc.
    if ((stat(strcpy(cliSockAddr.sun_path, CONFIG->runPath), &st) == -1 && (mkdir(cliSockAddr.sun_path, 0770)
        || chmod(cliSockAddr.sun_path, S_ISVTX | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH)))
        || chown(cliSockAddr.sun_path, 0, CONFIG->socketGroup.gr_gid)
        || ! strcat(cliSockAddr.sun_path, "cli.sock") || (stat(cliSockAddr.sun_path, &st) == 0 && unlink(cliSockAddr.sun_path) != 0)
        || ! (cliSock = socket(AF_UNIX, SOCK_DGRAM, 0)) || fcntl(cliSock, F_SETFD, O_NONBLOCK) < 0
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
        || ! (cliSockAddr.sun_len = SUN_LEN(&cliSockAddr)) || bind(cliSock, (struct sockaddr *)&cliSockAddr, cliSockAddr.sun_len) != 0
#else
        || bind(cliSock, (struct sockaddr *)&cliSockAddr, sizeof(struct sockaddr_un)) != 0
#endif
        || (chown(cliSockAddr.sun_path, 0, CONFIG->socketGroup.gr_gid)) || chmod(cliSockAddr.sun_path, 0660)) {
        LOG(LOG_WARNING, errno, "Cannot open CLI Socket %s. CLI connections will not be available.", cliSockAddr.sun_path);
        cliSock = -1;
    }

    // Write PID.
    char  pidFile[strlen(CONFIG->runPath) + 14];
    FILE *pidFilePtr = fopen(strcat(strcpy(pidFile, CONFIG->runPath), "igmpv3proxy.pid"), "w");
    fprintf(pidFilePtr, "%d\n", getpid());
    fclose(pidFilePtr);

    return cliSock;
} 

/**
*   Sets access for specified path and group to configured cligroup.
*/
int cliSetGroup(int gid) {
    char path[128];
    strcpy(path, cliSockAddr.sun_path);
    int x = chown(path, 0, gid);
    memset(path + strlen(path) - 9, 0, 9);
    x = chown(path, 0, gid);
    return x;
}

/**
*   Processes an incoming cli connection. Requires the fd of the cli socket.
*/
void processCliCon(int fd) {
    char buf[CLI_CMD_BUF] = {0};
    struct sockaddr_un cliSockAddr;
    memset(&cliSockAddr, 0, sizeof(struct sockaddr_un));
    cliSockAddr.sun_family = AF_UNIX;
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
    cliSockAddr.sun_len = SUN_LEN(&cliSockAddr);
#endif

    // Receive and answer the cli request.
    unsigned int s = sizeof(cliSockAddr);
    int len = recvfrom(fd, &buf, CLI_CMD_BUF, MSG_DONTWAIT, (struct sockaddr *)&cliSockAddr, &s);
    uint32_t addr, mask;
    if (len <= 0 || len > CLI_CMD_BUF)
        return;
    if (buf[0] == 'r') {
        if (len > 2 && parseSubnetAddress(buf[1] == 'h'? &buf[2] : &buf[1], &addr, &mask))
            sendto(fd, "GO AWAY\n\0", 9, MSG_DONTWAIT, (struct sockaddr *)&cliSockAddr, sizeof(struct sockaddr_un));
        else
            logRouteTable("", buf[1] == 'h' ? 0 : 1, &cliSockAddr, fd);
    } else if (buf[0] == 'i')
        getIfStats(buf[1] == 'h' ?  0 : 1, &cliSockAddr, fd);
    else if (buf[0] == 'f')
        getIfFilters(buf[1] == 'h' ? 0 : 1, &cliSockAddr, fd);
    else if (buf[0] == 't')
        debugQueue("", buf[1] == 'h' ? 0 : 1, &cliSockAddr, fd);
    else if (buf[0] == 'c') {
        sighandled |= GOT_SIGUSR1;
        sendto(fd, "Reloading Configuration.\n\0", 26, MSG_DONTWAIT, (struct sockaddr *)&cliSockAddr, sizeof(struct sockaddr_un));
    } else if (buf[0] == 'b') {
        sighandled |= GOT_SIGUSR2;
        sendto(fd, "Rebuilding Interfaces.\n\0", 24, MSG_DONTWAIT, (struct sockaddr *)&cliSockAddr, sizeof(struct sockaddr_un));
    } else
        sendto(fd, "GO AWAY\n\0", 9, MSG_DONTWAIT, (struct sockaddr *)&cliSockAddr, sizeof(struct sockaddr_un));

    // Close connection by sending 1 byte.
    sendto(fd, ".", 1, MSG_DONTWAIT, (struct sockaddr *)&cliSockAddr, sizeof(struct sockaddr_un));
    LOG(LOG_DEBUG, 0, "Cli: Finished command %s.", buf);
}

// Below are functions and definitions for client connections.
static int                srvSock = -1;
static struct sockaddr_un ownSockAddr;

/**
*   Sends command to daemon and writes response to stdout. Error exit if socket cannot be connected.
*/
void cliCmd(char *cmd) {
    struct stat        st;
    struct sockaddr_un srvSockAddr;
    struct sigaction   sa;
    bool               cli = strcmp(cmd, "cli") == 0 ? true : false;
    char               buf[CLI_CMD_BUF] = "";

    sa.sa_handler = signalHandler;
    sa.sa_flags = 0;    /* Interrupt system calls */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    memset(&srvSockAddr, 0, sizeof(struct sockaddr_un));
    memset(&ownSockAddr, 0, sizeof(struct sockaddr_un));
    srvSockAddr.sun_family = ownSockAddr.sun_family = AF_UNIX;
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
    srvSockAddr.sun_len = ownSockAddr.sun_len = SUN_LEN(&srvSockAddr);
#endif

    // Check for daemon socket.
    char paths[sizeof(CLI_SOCK_PATHS)] = CLI_SOCK_PATHS, *path, tpath[50];
    path = strtok(paths, " ");
    while (path) {
        strcat(strcpy(tpath, path), "/igmpv3proxy/cli.sock");
        if (stat(tpath, &st) != -1) {
            strcpy(srvSockAddr.sun_path, tpath);
            sprintf(ownSockAddr.sun_path, "%s.%d", tpath, getpid());
            break;
        }
        path = strtok(NULL, " ");
    }

    // Open and bind socket for receiving answers from daemon.
    if (strcmp(srvSockAddr.sun_path, "") == 0 || (srvSock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1
               || bind(srvSock, (struct sockaddr*)&ownSockAddr, sizeof(struct sockaddr_un))) {
        fprintf(stdout, "Cannot open socket %s. %s\n", srvSockAddr.sun_path, strerror(errno));
        exit(-1);
    }

    for (cmd = cli ? fgets(buf, CLI_CMD_BUF, stdin) : strcpy(buf, cmd); cmd && strcmp("done\n", buf) != 0
                   && strcmp(".\n", buf) != 0 && strlen(buf) < CLI_CMD_BUF; cmd = fgets(buf, CLI_CMD_BUF, stdin)) {
        if (sendto(srvSock, buf, cli ? strlen(buf) - 1 : strlen(buf), 0, (struct sockaddr *)&srvSockAddr,
                                                                          sizeof(srvSockAddr)) == -1) {
            fprintf(stdout, "Cannot send command. %s\n", strerror(errno));
            exit(-1);
        }

        // Receive the daemon's answer. It will be closed by one single byte.
        unsigned int s = sizeof(srvSockAddr);
        for (int len = recvfrom(srvSock, &buf, sizeof(buf), 0, (struct sockaddr *)&srvSockAddr, &s);
                 len > 1; len = recvfrom(srvSock, &buf, sizeof(buf), 0, (struct sockaddr *)&srvSockAddr, &s)) {
            fprintf(stdout, "%s", buf);
            memset(buf, 0, len);
        }
        if (! cli)
            break;
    }

    unlink(ownSockAddr.sun_path);
    close(srvSock);
}

static void signalHandler(int sig) {
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        if (srvSock != -1) {
            unlink(ownSockAddr.sun_path);
            close(srvSock);
        }
        fprintf(stdout, "Terminated.\n");
        exit(1);
    }
}
