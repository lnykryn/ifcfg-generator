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

#include "ifcfg-parser.h"

struct parser_table {
        const char *key;
        enum ifcfg_type type;
        int (* parser)(shvarFile *, char *, char *, void *);
        const size_t offset;
};
    
int parser_char(shvarFile *sv, char *key, char *value, void *store);
int parser_bool(shvarFile *sv, char *key, char *value, void *store);
int parser_dhcp(shvarFile *sv, char *key, char *value, void *store);
int parser_ignore(shvarFile *sv, char *key, char *value, void *store);
int parser_ip_prefix(shvarFile *sv, char *key, char *value, void *store);
int parser_ip(shvarFile *sv, char *key, char *value, void *store);
int parser_int(shvarFile *sv, char *key, char *value, void *store);
int parser_netmask(shvarFile *sv, char *key, char *value, void *store);

int parse(void *target, shvarFile *sv, struct parser_table *table, enum ifcfg_type *type, bool warn);
