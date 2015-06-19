/**
 * falogd - Log system wide file access events.
 *
 * Copyright (C) 2015 Mentor Graphics
 * Mikhail Durnev <mikhail_durnev@mentor.com>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <libudev.h>
#if HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "log.h"
#include "pid_tree.h"
#include "fa.h"

#define CONTROL_PIPE    "/tmp/falog-ctrl"
#define DATA_PIPE       "/tmp/falog-out"


/**************************************************************************************************
* Create named pipe
**************************************************************************************************/
int create_pipe(const char* pipename, mode_t access, int log_fd)
{
    int st = mknod(pipename, S_IFIFO | access, 0);

    if (st != 0 && errno != EEXIST) {
        log_error("Can't create named pipe ", pipename, errno, log_fd);
        return 0;
    }

    if (st != 0 && errno == EEXIST) {
        /* A file with this name already exists. We have to make sure it's a pipe */
        struct stat sb;
        if (stat(CONTROL_PIPE, &sb) == -1) {
            log_error("Can't stat ", pipename, errno, log_fd);
            return 0;
        }

        if (!S_ISFIFO(sb.st_mode)) {
            log_error(pipename, " is not a pipe", 0, log_fd);
            return 0;
        }
    }
    return 1;
}


/**************************************************************************************************
* Program entry point
**************************************************************************************************/
int main(void)
{
    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0) {
#if HAVE_SYSTEMD
        sd_notifyf(0, "MAINPID=%ld", (long)pid);
#endif
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open logs */        
    int kmsg_fd = open("/dev/kmsg", O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
    if (kmsg_fd < 0) {
        printf("Can't open system log\n");
        exit(EXIT_FAILURE);
    }

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        log_error("Can't create a new SID for the child process", "", 0, kmsg_fd);
        exit(EXIT_FAILURE);
    }

        /* Change the current working directory */
    if ((chdir("/")) < 0) {
        log_error("Can't change the current working directory", "", 0, kmsg_fd);
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Daemon-specific initialization */

    /* Create named pipes */
    if (!create_pipe(CONTROL_PIPE, 0622, kmsg_fd) || !create_pipe(DATA_PIPE, 0644, kmsg_fd)) {
        exit(EXIT_FAILURE);
    }

    /* Initialize storage to process ids */
    if (!init_proclist(kmsg_fd) || !start_proc_event_listener(kmsg_fd)) {
        exit(EXIT_FAILURE);
    }

    /* Initialize fanotify */
    if (!init_fanotify(kmsg_fd) || !start_fanotify_event_listener(kmsg_fd)) {
        free_proclist();
        exit(EXIT_FAILURE);
    }

#if HAVE_SYSTEMD
    /* Notify systemd */
    sd_notify(0, "READY=1");
#endif

    /* Main loop */
    while (1) {
        /* open the control pipe */
        int pipe_fd = open(CONTROL_PIPE, O_RDONLY);
        if (pipe_fd == -1) {
            log_error("Can't open named pipe ", CONTROL_PIPE, errno, kmsg_fd);
            exit(EXIT_FAILURE);
        }

        /* read the data */
        static char buf[PIPE_BUF];
        ssize_t cnt;
        #define MAX_DATA_SIZE (PIPE_BUF * 8 + 1)
        static char data[MAX_DATA_SIZE];
        ssize_t data_size = 0;
        while ((cnt = read(pipe_fd, buf, PIPE_BUF)) > 0) {
            if (data_size + cnt < MAX_DATA_SIZE) {
                memcpy(data + data_size, buf, cnt);
                data_size += cnt;
            }
            else {
                log_error("Too much data in pipe ", CONTROL_PIPE, 0, kmsg_fd);
            }
        }

        if (cnt < 0) {
            log_error("Can't read pipe ", CONTROL_PIPE, errno, kmsg_fd);
            exit(EXIT_FAILURE);
        }

        /* EOF reached, close the pipe */
        close(pipe_fd);

        /* handle the data */
        data[data_size] = 0;

        /* split lines - each line is a separate command */
        char *eol;
        char *str = data;
        while ((eol = strchr(str, '\n')) != NULL) {
            *eol = 0;

            /* check for the quit command */
            if (!strcmp(str, "quit")) {
                /* free up memory */
                stop_fanotify_event_listener(kmsg_fd);
                fs_tree_free();

                stop_proc_event_listener(kmsg_fd);
                free_proclist();

                /* remove pipes and exit */
                remove(CONTROL_PIPE);
                remove(DATA_PIPE);

                close(kmsg_fd);
                exit(EXIT_SUCCESS);
            }

            /* check for the reset command */
            if (!strcmp(str, "reset")) {
                adjust_fanotify(FAN_ACCESS | FAN_MODIFY | FAN_OPEN | FAN_CLOSE | FAN_ONDIR, kmsg_fd);
                fanotify_filter_clean();

                suspend_proc_event_listener();
                free_proclist();
                init_proclist(kmsg_fd);
                release_proc_event_listener();

                fs_tree_free();
            }

            /* check for the print command */
            else if (!strcmp(str, "print")) {
                int data_fd = open(DATA_PIPE, O_WRONLY);
                if (data_fd == -1) {
                    log_error("Can't open named pipe ", DATA_PIPE, errno, kmsg_fd);
                }
                else {
                    fs_tree_print_log(data_fd, kmsg_fd);

                    close(data_fd);
                }
            }

            /* check for the filter command */
            else if (!strncmp(str, "filter ", 7)) {
                fanotify_filter_add(str + 7, kmsg_fd);
            }

            /* check for the events command */
            else if (!strncmp(str, "events ", 7)) {
                unsigned int fa_events = 0;
                if (strchr(str + 7, 'R'))
                    fa_events |= FAN_ACCESS;
                if (strchr(str + 7, 'W'))
                    fa_events |= FAN_MODIFY;
                if (strchr(str + 7, 'O'))
                    fa_events |= FAN_OPEN;
                if (strchr(str + 7, 'C'))
                    fa_events |= FAN_CLOSE;
                if (strchr(str + 7, 'D'))
                    fa_events |= FAN_ONDIR;

                adjust_fanotify(fa_events, kmsg_fd);
            }

            else {
                log_error("Incorrect data received", "", 0, kmsg_fd);
            }
            str = eol + 1;
        }
    }
}
