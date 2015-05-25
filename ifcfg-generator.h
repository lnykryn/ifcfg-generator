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
#include <stdbool.h>

enum ifcfg_type {
        IFCFG_INVALID = -1,
        IFCFG_ALL = 0,
        IFCFG_ETHERNET,
        IFCFG_RANGE,
};


struct range {
        struct in_addr start;
        struct in_addr end;
        int prefix;
        int clonum;
        struct in_addr broadcast;
};

union netdev {
};

struct network {
        char *name;
        char *ifcfg;
        enum ifcfg_type type;

        shvarFile *sv;

        char *match_macaddr;
        char *match_name;

        char *link_macaddr;

        bool dhcp;

        GList *addr;
        int prefix;
        char *gateway;
        struct in_addr broadcast;

        char *dns1;
        char *dns2;

        int mtu;

        int label;
        
        GList *ranges;  /* struct range */
        GList *aliases; /* struct network */

        union netdev netdev;
};
