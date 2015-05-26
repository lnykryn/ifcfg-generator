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

#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <glib.h>

/* FIXME - proper logging*/
#define log log_internal

void hastable_free(gpointer data);
void hastable_close_file(gpointer data);
void log_internal(char *level, char *format, ...);

static inline void freep(void *p) {
        free(*(void**) p);
}

int log_oom();

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        func(*p);                               \
        }                                                       \
        struct __useless_struct_to_allow_trailing_semicolon__

#define _cleanup_(x) __attribute__((cleanup(x)))

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, fclose);
DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, pclose);
DEFINE_TRIVIAL_CLEANUP_FUNC(DIR*, closedir);

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_pclose_ _cleanup_(pclosep)
#define _cleanup_closedir_ _cleanup_(closedirp)

#define LOG_ERR     "err"
#define LOG_WARNING "warn"
#define LOG_INFO    "info"
#define LOG_DEBUG   "debug"

#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_RESET   "\x1b[0m"

