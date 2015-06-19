/**
 * falogd - Log system wide file access events.
 *
 * Copyright (C) 2015 Mentor Graphics
 * Mikhail Durnev <mikhail_durnev@mentor.com>
 *
 * This file is based on fatrace.c by Martin Pitt <martin.pitt@ubuntu.com>
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

#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <mntent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/fanotify.h>
#include <sys/time.h>
#include <pthread.h>

#include "log.h"
#include "pid_tree.h"

#define BUFSIZE 256*1024

/* work around kernels which do not have this fix yet:
 * http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1e2ee49f7
 * O_LARGEFILE is usually 0, so hardcode it here
 */
#define KERNEL_O_LARGEFILE 00100000

struct access_node
{
    pid_t               pid;      /* process id */
    int                 access;   /* access code */
    struct access_node* next;
};

struct fs_node
{
    char*               name;         /* file or directory name */
    struct access_node* access_list;  /* access list */
    int                 size;         /* allocated memory for the children table */
    int                 children;     /* actual number of children (sub-directories or files) */
    struct fs_node**    child;        /* children table */
};

static struct fs_node* fs_tree = NULL;
static pthread_mutex_t fs_tree_mutex = PTHREAD_MUTEX_INITIALIZER;

static int fan_fd = -1;

static pthread_t fanotify_event_listener_thread;

static char* path_filter[64];
static unsigned int path_filter_len = 0;
static pthread_mutex_t path_filter_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int fa_events = FAN_ACCESS | FAN_MODIFY | FAN_OPEN | FAN_CLOSE | FAN_ONDIR;
static pthread_mutex_t fa_events_mutex = PTHREAD_MUTEX_INITIALIZER;


/**************************************************************************************************
* Clean up file system tree
**************************************************************************************************/
static void free_fs_tree(struct fs_node* tree)
{
    if (tree) {
        if (tree->size && tree->child) {
            int i;
            for (i = 0; i < tree->children; i++) {
                free_fs_tree(tree->child[i]);
            }

            while (tree->access_list) {
                struct access_node* p = tree->access_list;
                tree->access_list = tree->access_list->next;
                free(p);
            }

            free(tree->child);
        }
        free(tree);
    }
}

void fs_tree_free()
{
    pthread_mutex_lock(&fs_tree_mutex);
    free_fs_tree(fs_tree);
    fs_tree = NULL;
    pthread_mutex_unlock(&fs_tree_mutex);
}

/**************************************************************************************************
* Add file to file system tree
**************************************************************************************************/
int fs_tree_add_file(char* path, pid_t pid, int access)
{
    /* check filter */
    pthread_mutex_lock(&path_filter_mutex);

    if (path_filter_len > 0) {
        int match = 0;

        int i;
        for (i = 0; i < path_filter_len; i++) {
            if (!path_filter[i])
                continue;

            if (path_filter[i][0] == '!' && strstr(path, &path_filter[i][1])) {
                match = -1;
                break;
            }
            if (strstr(path, path_filter[i])) {
                match = 1;
            }
        }

        if (match <= 0) {
            /* filtered out */
            pthread_mutex_unlock(&path_filter_mutex);
            return 1;
        }
    }

    pthread_mutex_unlock(&path_filter_mutex);

    pthread_mutex_lock(&fs_tree_mutex);

    if (!fs_tree) {
        /* add root node */
        fs_tree = (struct fs_node*)malloc(sizeof(struct fs_node));
        fs_tree->name = 0;
        fs_tree->access_list = NULL;
        fs_tree->size = 0;
        fs_tree->children = 0;
        fs_tree->child = NULL;
    }

    struct fs_node* tree = fs_tree;

    while (path) {
        /* split the path */
        char* p = strchr(path, '/');

        if (p == path) {
            ++path;
            continue;
        }

        if (p)
            *p = '\0';

        /* check if we have sub-tree entries */
        if (!tree->size || !tree->child) {
            tree->child = (struct fs_node**)malloc(64 * sizeof(struct fs_node*));
            if (!tree->child) {
                pthread_mutex_unlock(&fs_tree_mutex);
                tree->size = 0;
                return 0;
            }
            tree->size = 64;
        }

        /* make sure we have available entries */
        if (tree->children == tree->size) {
            struct fs_node** n = (struct fs_node**)malloc((tree->size + 64) * sizeof(struct fs_node*));
            if (!n) {
                pthread_mutex_unlock(&fs_tree_mutex);
                return 0;
            }
            memcpy(n, tree->child, tree->size * sizeof(struct fs_node*));
            free(tree->child);
            tree->child = n;
            tree->size += 64;
        }

        /* check if corresponding entry exists */
        int i1 = 0;
        int i2 = tree->children;
        int i = (i1 + i2) >> 1;
        int found = 0;
        while (i1 != i2) {
            int cmp;
            if (tree->child[i] && tree->child[i]->name && !(cmp = strcmp(path, tree->child[i]->name))) {
                /* found */
                found = 1;
                break;
            }

            if (cmp < 0)
                i2 = i;
            else
                i1 = i + 1;
            i = (i1 + i2) >> 1;
        }

        if (!found) {
            /* add new entry */
            memmove(&(tree->child[i+1]), &(tree->child[i]), (tree->children - i) * sizeof(struct fs_node*));
            tree->children++;
            tree->child[i] = (struct fs_node*)malloc(sizeof(struct fs_node));
            tree->child[i]->size = 0;
            tree->child[i]->children = 0;
            tree->child[i]->child = NULL;
            tree->child[i]->name = (char*)malloc(strlen(path) + 1);
            if (!tree->child[i]->name) {
                pthread_mutex_unlock(&fs_tree_mutex);
                return 0;
            }
            strcpy(tree->child[i]->name, path);
            tree->child[i]->access_list = NULL;
        }

        if (p) {
            path = p + 1;
            tree = tree->child[i];
        }
        else {
            path = NULL;

            /* search pid in the access list */
            found = 0;
            struct access_node* p = tree->child[i]->access_list;

            while (p) {
                if (p->pid == pid) {
                    p->access |= access;
                    found = 1;
                    break;
                }

                p = p->next;
            }

            /* add new access node */
            if (!found) {
                struct access_node* p = (struct access_node*)malloc(sizeof(struct access_node));
                if (!p) {
                    pthread_mutex_unlock(&fs_tree_mutex);
                    return 0;
                }

                p->pid = pid;
                p->access = access;
                p->next = tree->child[i]->access_list;
                tree->child[i]->access_list = p;
            }
        }
    }

    pthread_mutex_unlock(&fs_tree_mutex);
    return 1;
}

/**************************************************************************************************
* Print log
**************************************************************************************************/
static void print_fs_tree(struct fs_node* tree, char* path, int out_fd, int log_fd)
{
    if (tree) {
        struct access_node* p = tree->access_list;
        while (p) {
            if (p->access) {
                static char buf[1024];

                /* print "procname(pid<ppid<pppid<...<1): "*/
                print_pid_subtree(p->pid, buf, 1010, log_fd);

                /* convert access code to string */
                int n = strlen(buf);

                if (p->access & FAN_ACCESS)
                    buf[n++] = 'R';
                if (p->access & FAN_CLOSE_WRITE || p->access & FAN_CLOSE_NOWRITE)
                    buf[n++] = 'C';
                if (p->access & FAN_MODIFY || p->access & FAN_CLOSE_WRITE)
                    buf[n++] = 'W';
                if (p->access & FAN_OPEN)
                    buf[n++] = 'O';
                buf[n] = '\0';

                /* output */
                static char str[PATH_MAX + 1024];
                snprintf(str, PATH_MAX + 1024, "%s %s%s\n", buf, path, tree->name);
                int len = strlen(str);
                if (len != write(out_fd, str, strlen(str))) {
                    log_error("Failed to write ", "", errno, log_fd);
                }
            }

            p = p->next;
        }

        if (tree->size && tree->child) {
            char* new_path = (char*)malloc(strlen(path) + (tree->name ? strlen(tree->name) : 0) + 2);
            if (!new_path) {
                log_error("Failed to allocate memory ", "", 0, log_fd);
                return;
            }

            if (tree->name)
                sprintf(new_path, "%s%s/", path, tree->name);
            else
                strcpy(new_path, path);

            int i;
            for (i = 0; i < tree->children; i++) {
                print_fs_tree(tree->child[i], new_path, out_fd, log_fd);
            }

            free(new_path);
        }
    }
}

int fs_tree_print_log(int out_fd, int log_fd)
{
    pthread_mutex_lock(&fs_tree_mutex);
    print_fs_tree(fs_tree, "/", out_fd, log_fd);
    pthread_mutex_unlock(&fs_tree_mutex);
}

/**************************************************************************************************
* Init fanotify
**************************************************************************************************/
int init_fanotify(int log_fd)
{
    FILE* mounts;
    struct mntent* mount;

    fan_fd = fanotify_init(0, KERNEL_O_LARGEFILE);
    if (fan_fd < 0) {
        if (errno == EPERM) {
            log_error("Cannot initialize fanotify. You need to run this program as root.", "", 0, log_fd);
        }
        else {
            log_error("Cannot initialize fanotify ", "", errno, log_fd);
        }
        return 0;
    }

    /* iterate over all mounts */
    mounts = setmntent("/proc/self/mounts", "r");
    if (mounts == NULL) {
        log_error("Failed to list mounts ", "", errno, log_fd);
        return 0;
    }

    pthread_mutex_lock(&fa_events_mutex);

    while ((mount = getmntent(mounts)) != NULL) {
        /* Only consider mounts which have an actual device or bind mount
         * point. The others are stuff like proc, sysfs, binfmt_misc etc. which
         * are virtual and do not actually cause disk access. */
        if (mount->mnt_fsname == NULL || access(mount->mnt_fsname, F_OK) != 0 
            || strchr(mount->mnt_fsname, '/') == NULL) {
            continue;
        }

        int rc = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                            fa_events | FAN_EVENT_ON_CHILD,
                            AT_FDCWD, mount->mnt_dir);
        if (rc < 0) {
            log_error("Failed to add watch for mount ", mount->mnt_dir, errno, log_fd);
        }
    }

    pthread_mutex_unlock(&fa_events_mutex);

    endmntent(mounts);
    return 1;
}

/**************************************************************************************************
* Adjust fanotify
**************************************************************************************************/
int adjust_fanotify(unsigned int new_fa_events, int log_fd)
{
    FILE* mounts;
    struct mntent* mount;

    /* iterate over all mounts */
    mounts = setmntent("/proc/self/mounts", "r");
    if (mounts == NULL) {
        log_error("Failed to list mounts ", "", errno, log_fd);
        return 0;
    }

    pthread_mutex_lock(&fa_events_mutex);

    unsigned int add_events = (fa_events ^ new_fa_events) & new_fa_events;
    unsigned int rm_events  = (fa_events ^ new_fa_events) & fa_events;

    fa_events = new_fa_events;

    while ((mount = getmntent(mounts)) != NULL) {
        if (mount->mnt_fsname == NULL || access(mount->mnt_fsname, F_OK) != 0
            || strchr(mount->mnt_fsname, '/') == NULL) {
            continue;
        }

        if (add_events) {
            int rc = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                                   add_events,
                                   AT_FDCWD, mount->mnt_dir);
            if (rc < 0) {
                log_error("Failed to add watch for mount ", mount->mnt_dir, errno, log_fd);
            }
        }

        if (rm_events) {
            int rc = fanotify_mark(fan_fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                                   rm_events,
                                   AT_FDCWD, mount->mnt_dir);
            if (rc < 0) {
                log_error("Failed to remove watch for mount ", mount->mnt_dir, errno, log_fd);
            }
        }
    }

    pthread_mutex_unlock(&fa_events_mutex);
}

/**************************************************************************************************
* Add file path filtering string
**************************************************************************************************/
void fanotify_filter_add(const char* str, int log_fd)
{
    pthread_mutex_lock(&path_filter_mutex);

    if (path_filter_len >= sizeof(path_filter) / sizeof(char*)) {
        log_error("Failed to add filter (too many filters) ", str, 0, log_fd);
        return;
    }

    path_filter[path_filter_len] = (char*)malloc(strlen(str) + 1);
    if (!path_filter[path_filter_len]) {
        log_error("Failed to add filter (no memory) ", str, 0, log_fd);
        return;
    }

    strcpy(path_filter[path_filter_len], str);

    ++path_filter_len;

    pthread_mutex_unlock(&path_filter_mutex);
}

/**************************************************************************************************
* Remove all path filtering strings
**************************************************************************************************/
void fanotify_filter_clean()
{
    pthread_mutex_lock(&path_filter_mutex);

    int i;
    for (i = 0; i < path_filter_len; i++) {
        if (path_filter[i]) {
            free(path_filter[i]);
            path_filter[i] = NULL;
        }
    }

    path_filter_len = 0;

    pthread_mutex_unlock(&path_filter_mutex);
}

/**************************************************************************************************
* fanotify event listener thread
**************************************************************************************************/
static void* fanotify_event_listener(void* data)
{
    int log_fd = (int)(long)data;

    /* allocate memory for fanotify */
    void* buffer = NULL;
    if (posix_memalign(&buffer, 4096, BUFSIZE) != 0 || buffer == NULL) {
        log_error("Failed to allocate buffer ", "", 0, log_fd);
        pthread_exit(NULL);
    }

    /* read all events in a loop */
    while (1) {
        int rc = read(fan_fd, buffer, BUFSIZE);
        if (!rc) {
            log_error("No more fanotify events (EOF)", "", 0, log_fd);
            free(buffer);
            pthread_exit(NULL);
        }
        else if (rc < 0) {
            if (errno == EINTR)
                continue;
            log_error("Read error ", "", errno, log_fd);
            free(buffer);
            pthread_exit(NULL);
        }

        struct fanotify_event_metadata* mdata = (struct fanotify_event_metadata*)buffer;

        while (FAN_EVENT_OK(mdata, rc)) {
            static char buf[1024];
            static char pathname[PATH_MAX];

            /* ignore events from ourselves */
            if (mdata->pid != getpid()) {
                /* get path name */
                snprintf(buf, sizeof(buf), "/proc/self/fd/%i", mdata->fd);
                ssize_t len = readlink(buf, pathname, sizeof(pathname)-1);
                if (len > 0) {
                    pathname[len] = '\0';

                    if (len > 9 && !strcmp(pathname + (len - 10), " (deleted)")) {
                        pathname[len - 10] = '\0';
                    }
                
                    if(!fs_tree_add_file(pathname, mdata->pid, mdata->mask)) {
                        log_error("Failed to allocate memory for path name ", pathname, 0, log_fd);
                    }
                }
            }

            close(mdata->fd);
            mdata = FAN_EVENT_NEXT(mdata, rc);
        }
    }
}

/**************************************************************************************************
* Start fanotify event listener thread
**************************************************************************************************/
int start_fanotify_event_listener(int log_fd)
{
    /* start event listener thread */
    int rc = pthread_create(&fanotify_event_listener_thread, NULL, fanotify_event_listener, 
                            (void*)(long)log_fd);
    if (rc) {
        log_error("Failed to start fanotify event listener", "", 0, log_fd);
        return 0;
    }

    return 1;
}

/**************************************************************************************************
* Stop fanotify event listener thread
**************************************************************************************************/
int stop_fanotify_event_listener(int log_fd)
{
    void* status;

    int rc = pthread_cancel(fanotify_event_listener_thread);
    if (rc) {
        log_error("Failed to send cancel event to fanotify event listener", "", 0, log_fd);
        return 0;
    }

    rc = pthread_join(fanotify_event_listener_thread, &status);
    if (rc) {
        log_error("Failed to stop fanotify event listener", "", 0, log_fd);
        return 0;
    }

    return 1;
}
