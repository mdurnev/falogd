/**
 * falogd - Log system wide file access events.
 *
 * Copyright (C) 2015 Mentor Graphics
 * Mikhail Durnev <mikhail_durnev@mentor.com>
 *
 * This file is based on pmon.c (http://bewareofgeek.livejournal.com/2945.html)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <time.h>

#include "log.h"
#include "pid_tree.h"

/* assume that new process with the same pid will not be created within this time */
#define PID_NO_REUSE_TIME 10

struct procid
{
    pid_t          pid;
    time_t         time;        /* time when the process was started (notification received) */
    char*          name;
    struct procid* parent;      /* the parent process */
    struct procid* same_pid;    /* previous process with the same pid */
    int            reuse_count; /* pid reuse count */
};

static int pid_max = 0; /* size of proctable */
static struct procid** proctable = NULL;
static pthread_mutex_t proctable_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t event_listener_thread;

struct __attribute__ ((aligned(NLMSG_ALIGNTO))) netlink_msg {
    struct nlmsghdr nl_hdr;
    struct __attribute__ ((__packed__)) {
        struct cn_msg cn_msg;
        union {
            enum proc_cn_mcast_op cn_mcast;
            struct proc_event proc_ev;
        };
    };
};

int netlink_socket = 0;


/**************************************************************************************************
* Init pid tree (proctable)
**************************************************************************************************/
int init_proctable(int log_fd)
{
    pthread_mutex_lock(&proctable_mutex);

    proctable = NULL;

    /* Allocate memory for the proc table*/
    int pid_max_fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
    if (pid_max_fd < 0) {
         log_error("Can't open for reading: ", "/proc/sys/kernel/pid_max", errno, log_fd);
         pthread_mutex_unlock(&proctable_mutex);
         return 0;
    }

    static char pid_max_buf[100];
    int pid_max_len = read(pid_max_fd, pid_max_buf, sizeof(pid_max_buf - 1));
    if (pid_max_len > 0) {
        close(pid_max_fd);
        pid_max_buf[pid_max_len] = '\0';
    }
    else {
         log_error("Can't read: ", "/proc/sys/kernel/pid_max", errno, log_fd);
         close(pid_max_fd);
         pthread_mutex_unlock(&proctable_mutex);
         return 0;
    }

    pid_max = atoi(pid_max_buf);
    if (pid_max < 0 || pid_max > 65536) {
         log_error("Can't get valid max pid from value ", pid_max_buf, 0, log_fd);
         pthread_mutex_unlock(&proctable_mutex);
         return 0;
    }

    proctable = (struct procid**)malloc(pid_max * sizeof(struct procid*));
    if (!proctable) {
        log_error("Can't allocate memory for proctable", "", 0, log_fd);
        pthread_mutex_unlock(&proctable_mutex);
        return 0;
    }
    memset(proctable, 0, pid_max * sizeof(struct procid*)); /* init with NULL pointers */

    /* scan /proc for process entries */
    DIR* dp;
    struct dirent* ent;
    if (!(dp = opendir("/proc"))) {
        log_error("Can't open for reading: ", "/proc", errno, log_fd);
        pthread_mutex_unlock(&proctable_mutex);
        return 0;
    }

    while ((ent = readdir(dp)) != NULL) {
        pid_t pid;

        /* skip non-process entries */
        if (ent->d_type != DT_DIR
            || (pid = atol(ent->d_name)) <= 0
            || pid >= pid_max)
            continue;

        struct procid* p = proctable[pid];
        if (!p) {
            /* create new node only if it does not exist */
            p = (struct procid*)malloc(sizeof(struct procid));
            if (!p) {
                log_error("Can't allocate memory ", "", 0, log_fd);
                closedir(dp);
                pthread_mutex_unlock(&proctable_mutex);
                return 0;
            }
            proctable[pid] = p;
        }

        p->pid = pid;
        time(&p->time);
        p->name = NULL;
        p->parent = NULL;
        p->same_pid = NULL;
        p->reuse_count = 0;

        /* get ppid */
        int fd;
        ssize_t len;
        static char buf[100];
        static char data[1024];
        struct stat st;

        snprintf(buf, sizeof(buf), "/proc/%i/status", pid);
        len = 0;
        fd = open(buf, O_RDONLY);
        if (fd >= 0) {
            len = read(fd, data, sizeof(data));
            while (len > 0 && data[len-1] == '\n') {
                len--;
            }
        }
        if (len >= 0) {
            data[len] = '\0';
        }
        else {
            data[0] = 0;
        }
        if (fd >= 0)
            close(fd);

        pid_t ppid;
        char* d = data;
        while (d) {
            if (!strncmp(d, "PPid:", 5)) {
                d += 5;
                while (*d == ' ' || *d == '\t')
                    d++;
                ppid = atol(d);
                if (ppid < 0 || ppid >= pid_max) {
                    /* this should never happen */
                    ppid = 0;
                }

                break;
            }
            d = strchr(d, '\n');
            if (d)
                d++;
        }

        if (!proctable[ppid]) {
            /* create an new node for parent pid */
            proctable[ppid] = (struct procid*)malloc(sizeof(struct procid));
            if (!proctable[ppid]) {
                log_error("Can't allocate memory ", "", 0, log_fd);
                closedir(dp);
                pthread_mutex_unlock(&proctable_mutex);
                return 0;
            }
            proctable[ppid]->pid = ppid;
            time(&proctable[ppid]->time);
            proctable[ppid]->name = NULL;
            proctable[ppid]->parent = NULL;
            proctable[ppid]->same_pid = NULL;
            proctable[ppid]->reuse_count = 0;
        }
        p->parent = proctable[ppid];

        /* get name */
        static char procname[100];
        snprintf(buf, sizeof(buf), "/proc/%i/comm", pid);
        len = 0;
        fd = open(buf, O_RDONLY);
        if (fd >= 0) {
            len = read(fd, procname, sizeof(procname));

            while (len > 0 && procname[len-1] == '\n') {
                len--;
            }

            if (len > 0) {
                procname[len] = '\0';
                p->name = (char*)malloc(strlen(procname) + 1);
                if (p->name)
                    strcpy(p->name, procname);
            }

            close(fd);
        }
    }
    closedir(dp);

    pthread_mutex_unlock(&proctable_mutex);
    return 1;
}


/**************************************************************************************************
* Remove pid tree (proctable)
**************************************************************************************************/
void free_proctable()
{
    pthread_mutex_lock(&proctable_mutex);

    int i;
    for (i = 0; i < pid_max; i++) {
        struct procid* p = proctable[i];
        while (p) {
            struct procid* pp = p;
            p = p->same_pid;
            if (pp->name)
                free(pp->name);
            free(pp);
        }
    }

    free(proctable);
    proctable = NULL;

    pthread_mutex_unlock(&proctable_mutex);
}

/**************************************************************************************************
* Add pid to the pid tree (proctable)
**************************************************************************************************/
int add_procid(pid_t pid, pid_t ppid, int log_fd)
{
    time_t t;
    time(&t);

    if (pid < 0 || pid >= pid_max
        || ppid < 0 || ppid >= pid_max) {
        static char buf [100];
        snprintf(buf, sizeof(buf), "pid=%d, ppid=%d", (int)pid, (int)ppid);
        log_error("Incorrect pid or ppid: ", buf, 0, log_fd);
        return 0;
    }

    pthread_mutex_lock(&proctable_mutex);

    struct procid* p = (struct procid*)malloc(sizeof(struct procid));
    if (!p) {
        log_error("Can't allocate memory ", "", 0, log_fd);
        pthread_mutex_unlock(&proctable_mutex);
        return 0;
    }

    p->pid = pid;
    p->time = t;
    p->name = NULL;
    p->parent = proctable[ppid];
    p->same_pid = proctable[pid];
    p->reuse_count = proctable[pid] ? proctable[pid]->reuse_count + 1 : 0;

    proctable[pid] = p;

    /* get name */
    int fd;
    ssize_t len;
    static char buf[100];
    static char procname[100];

    snprintf(buf, sizeof(buf), "/proc/%i/comm", pid);
    len = 0;
    fd = open(buf, O_RDONLY);
    if (fd >= 0) {
        len = read(fd, procname, sizeof(procname));

        while (len > 0 && procname[len-1] == '\n') {
            len--;
        }

        if (len > 0) {
            procname[len] = '\0';
            p->name = (char*)malloc(strlen(procname) + 1);
            if (p->name)
                strcpy(p->name, procname);
        }

        close(fd);
    }

    pthread_mutex_unlock(&proctable_mutex);

    return 1;
}

/**************************************************************************************************
* Check if two file access events can be done by the same process
**************************************************************************************************/
int is_same_pid(pid_t pid, time_t t1, time_t t2)
{
    pthread_mutex_lock(&proctable_mutex);

    if (!proctable[pid]) {
        /* pid not found */
        pthread_mutex_unlock(&proctable_mutex);
        return 0;
    }

    struct procid* p1 = proctable[pid];
    while (p1->same_pid) {
        /* events about new process and file access are received asynchronously */
        /* let's assume that processes with the same pid are not created within PID_NO_REUSE_TIME seconds */
        if (t1 + PID_NO_REUSE_TIME < p1->time)
            p1 = p1->same_pid;
        else
            break;
    }

    struct procid* p2 = proctable[pid];
    while (p2->same_pid) {
        if (t2 + PID_NO_REUSE_TIME < p2->time)
            p2 = p2->same_pid;
        else 
            break;
    }

    pthread_mutex_unlock(&proctable_mutex);

    return (p1 == p2);
}

/**************************************************************************************************
* Print pid<ppid<pppid<...
**************************************************************************************************/
int print_pid_subtree(pid_t pid, time_t t, char* printbuf, int printbuf_size, int log_fd)
{
    int l;
    static char errbuf[128];

    pthread_mutex_lock(&proctable_mutex);

    struct procid* p = proctable[pid];

    if (!p) {
        snprintf(errbuf, 128, "Failed to find pid for %i", (int)pid);
        log_error(errbuf, "", 0, log_fd);
        pthread_mutex_unlock(&proctable_mutex);
        snprintf(printbuf, printbuf_size, "unknown(%i): ", pid);
        return 0;
    }

    /* which of the processes with the same pid? */
    while (p->same_pid) {
        /* events about new process and file access are received asynchronously */
        /* let's assume that processes with the same pid are not created within PID_NO_REUSE_TIME seconds */
        if (t + PID_NO_REUSE_TIME < p->time)
            p = p->same_pid;
        else {
            if (t < p->time) {
                snprintf(errbuf, 128, "WARNING: File access before pid received for %i", (int)pid);
                log_error(errbuf, "", 0, log_fd);
            }
            break;
        }
    }

    snprintf(printbuf, printbuf_size, "%s(%i", p->name, pid + (p->reuse_count << 16));

    while (p->parent && p->parent->pid)
    {
        l = strlen(printbuf);
        printbuf = printbuf + l;
        printbuf_size -= l;
        snprintf(printbuf, printbuf_size, "<%i", p->parent->pid + (p->parent->reuse_count << 16));
        p = p->parent;
    }

    l = strlen(printbuf);
    printbuf = printbuf + l;
    printbuf_size -= l;
    snprintf(printbuf, printbuf_size, "): ");

    if (p->pid != 1) {
        snprintf(errbuf, 128, "Failed to find pid of the parent process for %i", (int)p->pid);
        log_error(errbuf, "", 0, log_fd);
        pthread_mutex_unlock(&proctable_mutex);
        return 0;
    }

    pthread_mutex_unlock(&proctable_mutex);

    return 1;
}

/**************************************************************************************************
* Event listener
**************************************************************************************************/
static void* proc_event_listener(void* data)
{
    int log_fd = (int)(long)data;
    struct netlink_msg msg;

    while (1) {
        int rc = recv(netlink_socket, &msg, sizeof(msg), 0);
        if (!rc) {
            break;
        }
        if (rc == -1) {
            if (errno == EINTR) {
                continue;
            }
            else {
                log_error("Failed to read from socket ", "", errno, log_fd);
                pthread_exit(NULL);
            }
        }

        switch (msg.proc_ev.what) {
            case PROC_EVENT_FORK:
                add_procid(msg.proc_ev.event_data.fork.child_pid, 
                           msg.proc_ev.event_data.fork.parent_pid,
                           log_fd);
                break;
            case PROC_EVENT_NONE:
            case PROC_EVENT_EXEC:
            case PROC_EVENT_UID:
            case PROC_EVENT_GID:
            case PROC_EVENT_EXIT:
            default:
                ;
        }

        pthread_testcancel();
    }

    pthread_exit(NULL);
}

/**************************************************************************************************
* Start proc event listener thread
**************************************************************************************************/
int start_proc_event_listener(int log_fd)
{
    /* Connect to netlink */
    int rc;
    int netlink_socket;
    struct sockaddr_nl sa;

    netlink_socket = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (netlink_socket == -1) {
        log_error("Failed to create socket object ", "", errno, log_fd);
        return 0;
    }

    sa.nl_family = AF_NETLINK;
    sa.nl_groups = CN_IDX_PROC;
    sa.nl_pid = getpid();

    rc = bind(netlink_socket, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == -1) {
        log_error("Failed to bind to socket ", "", errno, log_fd);
        close(netlink_socket);
        return 0;
    }

    /* Subscribe on events */
    struct netlink_msg msg;
    memset(&msg, 0, sizeof(msg));

    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    msg.cn_msg.id.idx = CN_IDX_PROC;
    msg.cn_msg.id.val = CN_VAL_PROC;
    msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    msg.cn_mcast = PROC_CN_MCAST_LISTEN;

    rc = send(netlink_socket, &msg, sizeof(msg), 0);
    if (rc == -1) {
        log_error("Failed to send to netlink ", "", errno, log_fd);
        close(netlink_socket);
        return 0;
    }

    /* start event listener thread */
    rc = pthread_create(&event_listener_thread, NULL, proc_event_listener, (void*)(long)log_fd);
    if (rc) {
        log_error("Failed to start proc event listener", "", 0, log_fd);
        return 0;
    }

    return 1;
}

/**************************************************************************************************
* Stop proc event listener thread
**************************************************************************************************/
int stop_proc_event_listener(int log_fd)
{
    void* status;

    int rc = pthread_cancel(event_listener_thread);
    if (rc) {
        log_error("Failed to send cancel event to proc event listener", "", 0, log_fd);
        return 0;
    }

    rc = pthread_join(event_listener_thread, &status);
    if (rc) {
        log_error("Failed to stop proc event listener", "", 0, log_fd);
        return 0;
    }

    /* Unlock proctable_mutex in case it was left locked after the thread was cancelled */
    pthread_mutex_unlock(&proctable_mutex);

    /* Unsubscribe */
    struct netlink_msg msg;
    memset(&msg, 0, sizeof(msg));

    msg.nl_hdr.nlmsg_len = sizeof(msg);
    msg.nl_hdr.nlmsg_pid = getpid();
    msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    msg.cn_msg.id.idx = CN_IDX_PROC;
    msg.cn_msg.id.val = CN_VAL_PROC;
    msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    msg.cn_mcast = PROC_CN_MCAST_IGNORE;

    rc = send(netlink_socket, &msg, sizeof(msg), 0);
    if (rc == -1) {
        log_error("Failed to send to netlink ", "", errno, log_fd);
    }

    close(netlink_socket);
    return 1;
}
