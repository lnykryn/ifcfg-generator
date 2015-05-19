/*
 * ifcfg-generator
 *
 * Copyright 2015 Lukas Nykryn <lnykryn@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "shared.h"
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>


void log_internal(char *level, char *format, ...) {
        va_list args;
        va_start (args, format);

        if(!strcmp(LOG_ERR, level) || !strcmp(LOG_WARNING, level))
                fprintf(stderr, ANSI_COLOR_RED);
        else if(!strcmp(LOG_INFO, level))
                fprintf(stderr, ANSI_COLOR_YELLOW);

        fprintf(stderr, "%s: ", level);
        vfprintf(stderr, format, args);
        va_end(args);
        fprintf(stderr, ANSI_COLOR_RESET "\n");
}

int log_oom() {
        log(LOG_ERR, "Can't allocate memory");
        return -ENOMEM;
}

void hastable_free(gpointer data) {
        free(data);
}

void hastable_close_file(gpointer data) {
        svCloseFile(data);
}