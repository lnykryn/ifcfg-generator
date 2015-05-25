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


#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include <errno.h>
#include <assert.h>


#include <stddef.h>
#include <libgen.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "shvar.h"
#include "ifcfg-generator.h"

#include "ifcfg-parser.h"
#include "shared.h"



int safe_atoi(const char *s, int *ret_i) {
        char *x = NULL;
        long l;

        errno = 0;
        l = strtol(s, &x, 0);

        if (!x || x == s || *x || errno)
                return errno > 0 ? -errno : -EINVAL;

        if ((long) (int) l != l)
                return -ERANGE;

        *ret_i = (int) l;
        return 0;
}

int parser_char(shvarFile *sv, char *key, char *value, void *store) {
        char **ptr = (char **) store;
        *ptr = strdup(value);

        return *ptr != NULL ? 0 : log_oom();
}

int parser_netmask(shvarFile *sv, char *key, char *value, void *store) {
        in_addr_t l;
        int i;
        struct in_addr in;
        int *prefix = (int *) store;

        /* netmask has a lowest priority*/
        if (*prefix != -1)
                return 0;

        inet_aton(value, &in);

        l = htonl(in.s_addr);

        for (i = 0; i < 32 && l & (1 << (31 - i)); i++);

        *prefix = i;

        return 0;
}

int parser_ip_prefix(shvarFile *sv, char *key, char *value, void *store) {
        _cleanup_free_ char *index = NULL;
        _cleanup_free_ char *prefix = NULL;
        char *c = NULL;
        char *addr = NULL;
        GList **l = (GList **) store;
        GList *tmp;

        //IPADDR -> "" IPADDR3 -> "3"
        index = strdup(key + strlen("IPADDR"));
        if (!index)
                return log_oom();

        asprintf(&c, "PREFIX%s", index);
        if (!c)
                return log_oom();

        prefix = svGetValue(sv, c);
        free(c);

        if (!prefix) {
                _cleanup_free_ char *netmask;
                struct in_addr in;
                in_addr_t l;
                int i;

                asprintf(&c, "NETMASK%s", index);
                if (!c)
                        return log_oom();

                netmask = svGetValue(sv, c);
                free(c);

                if (!netmask) {
                        log(LOG_ERR, "Missing PREFIX or NETMASK in %s", sv->fileName);
                        return -EINVAL;
                }

                inet_aton(netmask, &in);

                l = htonl(in.s_addr);

                for (i = 0; i < 32 && l & (1 << (31 - i)); i++);

                asprintf(&prefix, "%d", i);
                if (!prefix)
                        return log_oom();
        }

        asprintf(&addr, "%s/%s", value, prefix);
        if (!addr)
                return log_oom();

        tmp = g_list_append(*l, addr);
        if (!tmp)
                return log_oom();
        *l = tmp;

        return 0;
}

int parser_bool(shvarFile *sv, char *key, char *value, void *store) {
        bool *ptr = (bool *) store;
        if (!strcasecmp(value, "yes") || !strcasecmp(value, "1") || !strcasecmp(value, "true"))
                *ptr = true;
        else
                *ptr = false;
        return 0;
}

int parser_dhcp(shvarFile *sv, char *key, char *value, void *store) {
        bool *ptr = (bool *) store;
        if (!strcasecmp(value, "dhcp"))
                *ptr = true;
        else
                *ptr = false;
        return 0;
}

int parser_ip(shvarFile *sv, char *key, char *value, void *store) {
        struct in_addr *in = (struct in_addr *) store;
        int r;

        r = inet_aton(value, in);
        if (!r)
                return -EINVAL;

        in->s_addr = htonl(in->s_addr);

        return 0;
}

int parser_int(shvarFile *sv, char *key, char *value, void *store) {
        int *i = (int *) store;

        return safe_atoi(value, i);
}

int parse(void *target, shvarFile *sv, struct parser_table *table, enum ifcfg_type *type,  bool warn) {
        GList *l;
        int i;

        log(LOG_DEBUG, "parsing: %s", sv->fileName);

        for (l = sv->lineList; l != NULL; l = l->next) {
                _cleanup_free_ char *key = NULL;
                _cleanup_free_ char *value = NULL;
                char *c;
                int found = 0;
                size_t n;

                c = strchr(l->data, '=');
                if (!c)
                        continue;

                key = strndup(l->data, c - (char *) l->data);
                if (!key)
                        return log_oom();

                value = svGetValue(sv, key);
                if (!value)
                        continue;

                /* remove digital suffix (IPADDR2) */
                n = strcspn(key, "0123456789");

                for (i = 0; table[i].key != NULL && found == 0; i++) {
                        if (!strncmp(table[i].key, key, n)) {
                                if (type) {
                                        /* FIXME and find a better solution*/
                                        if (*type == table[i].type || *type == IFCFG_ALL || *type==IFCFG_ETHERNET)
                                                *type = table[i].type;
                                        else {
                                                log(LOG_WARNING, "%s: unsupported key %s in this context", sv->fileName, key);
                                                continue;
                                        }
                                }
                                found = 1;
                                if (table[i].parser)
                                        table[i].parser(sv, key, value, target + table[i].offset);
                        }
                }

                if (warn && !found)
                        log(LOG_WARNING, "%s: unsupported key %s=%s", sv->fileName, key, value);
        }

        return 0;
}


