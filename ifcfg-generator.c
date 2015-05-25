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

#define IFCFG_PATH      "/etc/sysconfig/network-scripts/"
#define NETWORKD_PATH   "/run/systemd/network/"

void network_destroy(gpointer data);

struct parser_table ptable_ethernet[] = {
        { "HWADDR",          IFCFG_ETHERNET,   &parser_char,   offsetof(struct network, match_macaddr)},
        { "MACADDR",         IFCFG_ETHERNET,   &parser_char,   offsetof(struct network, link_macaddr)},
        { "DEVICE",          IFCFG_ETHERNET,   &parser_char,   offsetof(struct network, match_name)},
        { "BOOTPROTO",       IFCFG_ETHERNET,   &parser_dhcp,   offsetof(struct network, dhcp)},
        { "GATEWAY",         IFCFG_ETHERNET,   &parser_char,   offsetof(struct network, gateway)},
        { "NAME",            IFCFG_ETHERNET,   &parser_char,   offsetof(struct network, name)},
        { "MTU",             IFCFG_ETHERNET,   &parser_int,    offsetof(struct network, mtu)},
        /* FIXME no Broadcast in [Network] */
        /* { "BROADCAST",          &parser_ip,     offsetof(struct network, broadcast)}, */
        { "IPADDR",          IFCFG_ETHERNET,   &parser_ip_prefix, offsetof(struct network, addr)},
        /* prefix or netmask is handled in parser_ip_prefix */
        { "PREFIX",          IFCFG_ETHERNET,   NULL,           0},
        { "NETMASK",         IFCFG_ETHERNET,   NULL,           0},
        /* ignored values */
        { "NM_CONTROLLED",   IFCFG_ETHERNET,   NULL,           0},
        { "UUID",            IFCFG_ETHERNET,   NULL,           0},
        { "NETBOOT",         IFCFG_ETHERNET,   NULL,           0}, /* FIXME should be probably critical connection */
        { NULL,              0,                NULL,           0}
};

struct parser_table ptable_ethernet_range[] = {
        { "IPADDR_START",    IFCFG_RANGE,   &parser_ip,     offsetof(struct range, start)},
        { "IPADDR_END",      IFCFG_RANGE,   &parser_ip,     offsetof(struct range, end)},
        { "CLONENUM_START",  IFCFG_RANGE,   &parser_int,    offsetof(struct range, clonum)},
        { "PREFIX",          IFCFG_RANGE,   &parser_int,    offsetof(struct range, prefix)},
        { "NETMASK",         IFCFG_RANGE,   &parser_netmask,offsetof(struct range, prefix)},
        { "BROADCAST",       IFCFG_RANGE,   &parser_ip,     offsetof(struct range, broadcast)},
        { NULL,              0,   NULL,           0}

};

int is_cfg(const struct dirent *dent) {
	int len = strlen(dent->d_name);

	if (strncmp(dent->d_name,"ifcfg-",6) ||
	    strstr(dent->d_name,"rpmnew") ||
	    strstr(dent->d_name,"rpmsave") ||
	    strstr(dent->d_name,"rpmorig") ||
	    dent->d_name[len-1] == '~' ||
	    !strncmp(dent->d_name+len-4,".bak",4) ||
            !strcmp(dent->d_name, "ifcfg-lo"))
                return 0;

	return 1;
}

int load_ifcfgs(GHashTable *ifcfg_list) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *ent = NULL;

        dir = opendir(IFCFG_PATH);
        if (!dir) {
                log(LOG_ERR, "Can't open network-scripts directory");
                return -ENOENT;
        }

        while ((ent = readdir(dir)) != NULL) {
                shvarFile *svfile = NULL;
                char *path = NULL;

                if (!is_cfg(ent))
                        continue;

                asprintf(&path, "%s%s", IFCFG_PATH, ent->d_name);
                if (!path)
                        return log_oom();

                svfile = svNewFile(path);
                free(path);
                if (!svfile) {
                        log(LOG_ERR, "Can't read file %s",
                                ent->d_name);
                        continue;
                }

                path = strdup(ent->d_name);
                if (!path) {
                        svCloseFile(svfile);
                        return log_oom();
                }

                g_hash_table_insert(ifcfg_list, path, svfile);

                log(LOG_DEBUG, "Read: %s", path);
        }
        return 0;
}

int print_link(struct network *net) {
        char *name = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_fclose_ FILE *f = NULL;

        if (!net->mtu && !net->link_macaddr && (!net->match_name || !net->match_macaddr))
                return 0;

        name = net->name ? net->name :
                net->match_name ? net->match_name :
                net->ifcfg;

        if (!net->match_name && !net->match_macaddr) {
                log(LOG_WARNING, "To write link file for %s we need DEVICE or HWADDR", name);
                return -EINVAL;
        }

        asprintf(&path, "%s%s.link", NETWORKD_PATH, name);

        if (!path)
                return log_oom();

        f = fopen(path, "w");
        if (!f) {
                log(LOG_ERR, "can't access %s", path);
                return -EACCES;
        }

        fprintf(f, "[Match]\n");
        if (net->match_macaddr)
                fprintf(f, "MACAddress=%s\n", net->match_macaddr);
        else if (net->match_name)
                fprintf(f, "OriginalName=%s\n", net->match_name);

        fprintf(f, "[Link]\n");

        if (net->mtu)
                fprintf(f, "MTUBytes=%d\n", net->mtu);

        if (net->link_macaddr)
                fprintf(f, "MACAddress=%s\n", net->link_macaddr);

        if (net->match_macaddr && net->match_name) {
                fprintf(f, "NamePolicy=\n");
                fprintf(f, "Name=%s\n", net->match_name);
        }
}

int print_network(struct network *net) {
        char *name = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        GList *l;

        name = net->name ? net->name :
                net->match_name ? net->match_name :
                net->ifcfg;

        asprintf(&path, "%s%s.network", NETWORKD_PATH, name);

        if (!path)
                return log_oom();

        f = fopen(path, "w");
        if (!f) {
                log(LOG_ERR, "can't access %s", path);
                return -EACCES;
        }

        fprintf(f, "[Match]\n");
        if (net->match_macaddr)
                fprintf(f, "MACAddress=%s\n", net->match_macaddr);
        if (net->match_name)
                fprintf(f, "Name=%s\n", net->match_name);

        fprintf(f, "[Network]\n");
        fprintf(f, "DHCP=%s\n", net->dhcp ? "true" : "false");

        for (l = net->addr; l != NULL; l = l->next)
                fprintf(f, "Address=%s\n", l->data);

        if (net->gateway)
                fprintf(f, "Gateway=%s\n", net->gateway);

        if (net->dns1)
                fprintf(f, "DNS=%s\n", net->dns1);

        if (net->dns2)
                fprintf(f, "DNS=%s\n", net->dns2);

        if (net->aliases) {
                GList *l, *k;
                fprintf(f, "[Address]\n");
                for (l = net->aliases; l != NULL; l = l->next) {
                        struct network *n = l->data;
                        fprintf(f, "Label=%d\n", n->label);
                        for (k = n->addr; k != NULL; k = k->next)
                                fprintf(f, "Address=%s\n", k->data);
                }
        }

        if (net->ranges) {
                GList *l;
                for (l = net->ranges; l != NULL; l = l->next) {
                        struct range *r = l->data;
                        struct in_addr in;
                        int label;

                        for (in.s_addr = r->start.s_addr, label = r->clonum; in.s_addr < r->end.s_addr; in.s_addr++, label++) {
                                struct in_addr i;

                                fprintf(f, "[Address]\n");
                                fprintf(f, "Label=%d\n", label);
                                i.s_addr = ntohl(in.s_addr);
                                fprintf(f, "Address=%s/%d\n", inet_ntoa(i), r->prefix);
                                if (r->broadcast.s_addr)
                                        fprintf(f, "Broadcast=%s\n", inet_ntoa(r->broadcast));
                                fprintf(f, "\n");
                        }
                }
        }

        log(LOG_DEBUG, "Wrote %s", name);

        return 0;
}

void network_destroy(gpointer data) {
        struct network *n = (struct network *) data;

        free(n->dns1);
        free(n->dns2);
        free(n->gateway);
        free(n->ifcfg);
        free(n->link_macaddr);
        free(n->match_macaddr);
        free(n->match_name);
        free(n->name);
        g_list_free_full(n->addr, hastable_free);
        g_list_free_full(n->aliases, network_destroy);
        g_list_free_full(n->ranges, hastable_free);
        free(n);
}

struct network * network_find_or_alloc(GHashTable *networks, char *device) {
        struct network *n = NULL;
        char *c;

        log(LOG_DEBUG, "Looking for %s", device);

        n = (struct network *) g_hash_table_lookup(networks, device);
        if (n != NULL)
                return n;

        n = (struct network *) malloc(sizeof (struct network));
        if (!n)
                return NULL;

        bzero(n, sizeof (struct network));

        c = strdup(device);
        if (!c) {
                free(n);
                return NULL;
        }

        g_hash_table_insert(networks, c, n);

        return n;
}

int process_ethernet_aliases(struct network *net, GHashTable *ifcfg_list) {
        GHashTableIter iter;
        shvarFile *sv;
        char *name;
        int len_alias;
        int len_range;
        _cleanup_free_ char *match_alias = NULL;
        _cleanup_free_ char *match_range = NULL;

        asprintf(&match_alias, "%s:", net->match_name);
        asprintf(&match_range, "ifcfg-%s-range", net->match_name);

        if (!match_alias || !match_range)
                return log_oom();

        len_alias = strlen(match_alias);
        len_range = strlen(match_range);

        g_hash_table_iter_init(&iter, ifcfg_list);

        while (g_hash_table_iter_next(&iter, (gpointer *) & name, (gpointer *) & sv)) {
                _cleanup_free_ char *device = NULL;
                int r;

                if (!strncmp(name, match_range, len_range)) {
                        struct range *ran;
                        GList *tmp;

                        ran = (struct range *) malloc(sizeof (struct range));
                        if (!ran)
                                return log_oom();

                        bzero(ran, sizeof (struct range));

                        ran->prefix=-1;

                        /* we can inherit some things from parent config */
                        parse(ran, net->sv, ptable_ethernet_range, NULL, false);
                        parse(ran, sv, ptable_ethernet_range, NULL, true);

                        if (ran->start.s_addr == 0 || ran->end.s_addr == 0) {
                                log(LOG_ERR, "%s: range file is not valid, skipping", name);
                                free(ran);
                                continue;
                        }
                        if (ran->start.s_addr > ran->end.s_addr) {
                                log(LOG_ERR, "%s: range file is not valid, skipping", name);
                                free(ran);
                                continue;
                        }


                        tmp = g_list_append(net->ranges, ran);
                        if (!tmp) {
                                free(ran);
                                return log_oom();
                        }
                        net->ranges = tmp;


                }
                device = svGetValue(sv, "DEVICE");

                if (device != NULL && !strncmp(device, match_alias, len_alias)) {
                        GList *tmp;
                        struct network *n;

                        n = (struct network *) malloc(sizeof (struct network));
                        if (!n)
                                return log_oom();

                        bzero(n, sizeof (struct network));

                        r = parse(n, sv, ptable_ethernet, &n->type, true);
                        if (r) {
                                free(n);
                                log(LOG_ERR, "%s: ifcfg file is not valid, skipping", name);
                                continue;
                        }

                        n->label = atoi(strchr(device, ':') + 1);

                        tmp = g_list_append(net->aliases, n);
                        if (!tmp) {
                                free(n);
                                return log_oom();
                        }
                        net->aliases = tmp;
                }


        }
        return 0;
}

int process_ethernet(char *name, shvarFile *sv, GHashTable *ifcfg_list, GHashTable *networks) {
        int r = 0;

        _cleanup_free_ char *device = NULL;
        struct network *n = NULL;

        log(LOG_DEBUG, "Processing ethernet: %s", name);

        device = svGetValue(sv, "DEVICE");

        if (!device)
                return 0;

        n = network_find_or_alloc(networks, device);
        if (!n)
                return log_oom();

        n->ifcfg = strdup(basename(sv->fileName));

        n->sv = sv;

        if (!n->ifcfg)
                return log_oom();

        r = parse(n, sv, ptable_ethernet, &n->type, true);
        if(r)
                return r;

        r = process_ethernet_aliases(n, ifcfg_list);

        return r;
}

int process_ifcfg(char *name, shvarFile *sv, GHashTable *ifcfg_list, GHashTable *networks) {
        int r = 0;
        _cleanup_free_ char *type = NULL;
        log(LOG_DEBUG, "Processing: %s", name);

        type = svGetValue(sv, "TYPE");

        /* We have to skip aliases, because first we need to find parent config */
        if (strchr(name, ':') || strstr(name, "-range"))
                return 0;
        else if (!type || !strcasecmp(type, "Ethernet")) {
                if(!type)
                        log(LOG_INFO, "%s does not have any type, assuming ethernet", name);
                r = process_ethernet(name, sv, ifcfg_list, networks);
        } else  {
                log(LOG_ERR, "%s has unsupported type %s", name, type);
                r = -EINVAL;
        }

        return r;
}

int main(void) {
        GHashTable *ifcfg_list = NULL; /* shvarFile */
        GHashTable *networks = NULL; /* struct network */
        GHashTableIter iter;

        gpointer key, value;
        int r = 0;
        int p;

        ifcfg_list = g_hash_table_new_full(g_str_hash, g_str_equal,
                hastable_free, hastable_close_file);
        if (!ifcfg_list) {
                r = log_oom();
                goto finish;
        }

        networks = g_hash_table_new_full(g_str_hash, g_str_equal,
                hastable_free, network_destroy);
        if (!networks) {
                r = log_oom();
                goto finish;
        }

        /* FIXME - this directory should be created elsewshere */
        mkdir(NETWORKD_PATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

        /* use shvar and read ifcfg files to hashmap */
        r = load_ifcfgs(ifcfg_list);

        g_hash_table_iter_init(&iter, ifcfg_list);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                p = process_ifcfg((char *) key, (shvarFile *) value, ifcfg_list, networks);
                r = r?:p;
        }

        g_hash_table_iter_init(&iter, networks);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                p = print_link(value);
                r = r?:p;
                p = print_network(value);
                r = r?:p;
        }

finish:
        g_hash_table_destroy(ifcfg_list);
        g_hash_table_destroy(networks);
        return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
