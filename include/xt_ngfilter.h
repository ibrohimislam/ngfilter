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

#ifndef _LINUX_NETFILTER_XT_NGFILTER_H
#define _LINUX_NETFILTER_XT_NGFILTER_H

/*
 * Binary operations are used to be more accurate that a numerical
 * representation.
 */
enum {
  XT_NGFILTER_PATTERN = 1 << 0,
  XT_NGFILTER_SMB_COMMAND = 1 << 1,
  XT_NGFILTER_SMB_TREE_CONNECT_ANDX_PATH = 1 << 2,
};


#define is_have_flag(info, flag) !!(info->flags & flag)


/*
 * This is the information to which we want to match against.
 */
#define MAX_PATTERN_LENGTH 256
struct xt_ngfilter_mtinfo {
  __u8 flags;
  unsigned char pattern[MAX_PATTERN_LENGTH];
  unsigned char smb_command;
};

#endif /* _LINUX_NETFILTER_XT_NGFILTER_H */
