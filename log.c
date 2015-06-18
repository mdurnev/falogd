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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_LINE_MAX_SIZE 1024

/**************************************************************************************************
* log error to file
**************************************************************************************************/
void log_error(const char* msg, const char* name, int err, int fd)
{
    static char str[LOG_LINE_MAX_SIZE];
    if (err) {
        snprintf(str, LOG_LINE_MAX_SIZE, "falogd: %s%s: %s\n", msg, name?name:"", strerror(err));
    }
    else {
        snprintf(str, LOG_LINE_MAX_SIZE, "falogd: %s%s\n", msg, name?name:"");
    }
    write(fd, str, strlen(str));
}
