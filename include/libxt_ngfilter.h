/**
 * Copyright (C) 2010-2012 G. Elian Gidoni
 *               2012 Ed Wildgoose
 *               2014 Humberto Jucá <betolj@gmail.com>
 *               2018 Ibrohim Kholilul Islam <ibrohimislam@gmail.com>
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */


#ifndef _LINUX_NETFILTER_LIBXT_NGFILTER_H
#define _LINUX_NETFILTER_LIBXT_NGFILTER_H

static void ngfilter_match_check(unsigned int);
static void ngfilter_match_init(struct xt_entry_match *);
static void ngfilter_match_save(const void *, const struct xt_entry_match *);
static void ngfilter_match_print(const void *, const struct xt_entry_match *, int);
static int ngfilter_match_parse(int, char **, int, unsigned int *, const void *, struct xt_entry_match **);
static void ngfilter_match_help(void);

#endif /* _LINUX_NETFILTER_LIBXT_NGFILTER_H */
