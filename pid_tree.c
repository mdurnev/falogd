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
    pid_t          ppid;        /* ppid is used in init_proclist() only */
    char*          name;
    struct procid* parent;      /* the parent process */
    struct procid* next;        /* next process in the list (previous in the time line) */
    struct procid* same_pid;    /* previous process with the same pid */
    int            reuse_count; /* pid reuse count */
};

static struct procid* proclist = NULL;
static pthread_mutex_t proclist_mutex = PTHREAD_MUTEX_INITIALIZER;

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
* Init pid tree (proclist)
**************************************************************************************************/
int init_proclist(int log_fd)
{
    pthread_mutex_lock(&proclist_mutex);

    /* scan /proc for process entries */
    DIR* dp;
    struct dirent* ent;
    if (!(dp = opendir("/proc"))) {
        log_error("Can't open for reading: ", "/proc", errno, log_fd);
        pthread_mutex_unlock(&proclist_mutex);
        return 0;
    }

    while ((ent = readdir(dp)) != NULL) {
        pid_t pid;

        /* skip non-process entries */
        if (ent->d_type != DT_DIR
            || (pid = atol(ent->d_name)) <= 0)
            continue;

        struct procid* p = (struct procid*)malloc(sizeof(struct procid));
        if (!p) {
            log_error("Can't allocate memory ", "", 0, log_fd);
            closedir(dp);
            pthread_mutex_unlock(&proclist_mutex);
            return 0;
        }

        p->pid = pid;
        time(&p->time);
        p->name = NULL;
        p->next = proclist;
        proclist = p;
        p->ppid = 0;
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

        char* d = data;
        while (d) {
            if (!strncmp(d, "PPid:", 5)) {
                d += 5;
                while (*d == ' ' || *d == '\t')
                    d++;
                p->ppid = atol(d);

                break;
            }
            d = strchr(d, '\n');
            if (d)
                d++;
        }

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
                strcpy(p->name, procname);
            }

            close(fd);
        }
    }
    closedir(dp);

    /* set links */
    struct procid* p = proclist;
    while (p) {
        struct procid* pp = proclist;
        while (pp) {
            if (p->ppid == pp->pid) {
                p->parent = pp;
                break;
            }
            pp = pp->next;
        }
        p = p->next;
    }

    pthread_mutex_unlock(&proclist_mutex);
    return 1;
}


/**************************************************************************************************
* Remove pid tree (proclist)
**************************************************************************************************/
void free_proclist()
{
    pthread_mutex_lock(&proclist_mutex);

    struct procid* p = proclist;
    while (p) {
        struct procid* pp = p;
        p = p->next;
        if (pp->name)
            free(pp->name);
        free(pp);
    }

    proclist = NULL;

    pthread_mutex_unlock(&proclist_mutex);
}

/**************************************************************************************************
* Add pid to the pid tree (proclist)
**************************************************************************************************/
int add_procid(pid_t pid, pid_t ppid, int log_fd)
{
    time_t t;
    time(&t);

    pthread_mutex_lock(&proclist_mutex);

    /* search for parent process */
    struct procid* p = proclist;
    struct procid* parent = NULL;
    while (p) {
        if (p->pid == ppid) {
            parent = p;
            break;
        }
        p = p->next;
    }

    /* search for previous process with the same pid */
    p = proclist;
    struct procid* prev = NULL;
    int reuse_count = 0;
    while (p) {
        if (p->pid == pid) {
            prev = p;
            reuse_count = p->reuse_count + 1;
            break;
        }
        p = p->next;
    }

    p = (struct procid*)malloc(sizeof(struct procid));
    if (!p) {
        log_error("Can't allocate memory ", "", 0, log_fd);
        pthread_mutex_unlock(&proclist_mutex);
        return 0;
    }

    p->pid = pid;
    p->time = t;
    p->name = NULL;
    p->ppid = ppid;
    p->parent = parent;
    p->same_pid = prev;
    p->reuse_count = reuse_count;
    p->next = proclist;
    proclist = p;

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
            strcpy(p->name, procname);
        }

        close(fd);
    }

    pthread_mutex_unlock(&proclist_mutex);

    return 1;
}

/**************************************************************************************************
* Check if two file access events can be done by the same process
**************************************************************************************************/
int is_same_pid(pid_t pid, time_t t1, time_t t2)
{
    static struct procid* p = NULL;

    pthread_mutex_lock(&proclist_mutex);

    /* search for pid */
    if (!p || p->pid != pid) {
        p = proclist;
        while (p) {
            if (p->pid == pid) {
                break;
            }
            p = p->next;
        }
        if (p->pid != pid) {
            /* pid not found */
            pthread_mutex_unlock(&proclist_mutex);
            return 0;
        }
    }

    struct procid* p1 = p;
    while (p1->same_pid) {
        /* events about new process and file access are received asynchronously */
        /* let's assume that processes with the same pid are not created within PID_NO_REUSE_TIME seconds */
        if (t1 + PID_NO_REUSE_TIME < p1->time)
            p1 = p1->same_pid;
        else
            break;
    }

    struct procid* p2 = p;
    while (p2->same_pid) {
        if (t2 + PID_NO_REUSE_TIME < p2->time)
            p2 = p2->same_pid;
        else 
            break;
    }

    pthread_mutex_unlock(&proclist_mutex);

    return (p1 == p2);
}

/**************************************************************************************************
* Print pid<ppid<pppid<...
**************************************************************************************************/
int print_pid_subtree(pid_t pid, time_t t, char* printbuf, int printbuf_size, int log_fd)
{
    int l;
    static char errbuf[128];

    pthread_mutex_lock(&proclist_mutex);

    /* search for pid */
    struct procid* p = proclist;
    while (p) {
        if (p->pid == pid) {
            break;
        }
        p = p->next;
    }

    if (p->pid != pid) {
        snprintf(errbuf, 128, "Failed to find pid for %i", (int)pid);
        log_error(errbuf, "", 0, log_fd);
        pthread_mutex_unlock(&proclist_mutex);
        snprintf(printbuf, printbuf_size, "unknown(%i)", pid);
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
    pthread_mutex_unlock(&proclist_mutex);

    l = strlen(printbuf);
    printbuf = printbuf + l;
    printbuf_size -= l;
    snprintf(printbuf, printbuf_size, "): ", p->name, pid);

    if (p->pid != 1) {
        snprintf(errbuf, 128, "Failed to find pid of the parent process for %i", (int)p->pid);
        log_error(errbuf, "", 0, log_fd);
        return 0;
    }

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
                //{
                //    char sss[1024];
                //    snprintf(sss, 1024, "ppid=%d, pid=%d ", (int)msg.proc_ev.event_data.fork.parent_pid, (int)msg.proc_ev.event_data.fork.child_pid);
                //    log_error(sss, "", 0, log_fd);
                //}
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

    /* Unlock proclist_mutex in case it was left locked after the thread was cancelled */
    pthread_mutex_unlock(&proclist_mutex);

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
