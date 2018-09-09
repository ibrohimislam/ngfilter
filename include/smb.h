#ifndef HEADER_CURL_SMB_H
#define HEADER_CURL_SMB_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014, Bill Nagel <wnagel@tycoint.com>, Exacq Technologies
 * Copyright (C) 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

enum smb_conn_state {
  SMB_NOT_CONNECTED = 0,
  SMB_CONNECTING,
  SMB_NEGOTIATE,
  SMB_SETUP,
  SMB_CONNECTED
};

struct smb_conn {
  enum smb_conn_state state;
  __u8 *user;
  __u8 *domain;
  __u8 *share;
  __u8 challenge[8];
  __u32 session_key;
  __u16 uid;
  __u8 *recv_buf;
  size_t upload_size;
  size_t send_size;
  size_t sent;
  size_t got;
};


#define SMB_COM_CLOSE                 0x04
#define SMB_COM_READ_ANDX             0x2e
#define SMB_COM_WRITE_ANDX            0x2f
#define SMB_COM_TREE_DISCONNECT       0x71
#define SMB_COM_NEGOTIATE             0x72
#define SMB_COM_SETUP_ANDX            0x73
#define SMB_COM_TREE_CONNECT_ANDX     0x75
#define SMB_COM_NT_CREATE_ANDX        0xa2
#define SMB_COM_NO_ANDX_COMMAND       0xff

#define SMB_WC_CLOSE                  0x03
#define SMB_WC_READ_ANDX              0x0c
#define SMB_WC_WRITE_ANDX             0x0e
#define SMB_WC_SETUP_ANDX             0x0d
#define SMB_WC_TREE_CONNECT_ANDX      0x04
#define SMB_WC_NT_CREATE_ANDX         0x18

#define SMB_FLAGS_CANONICAL_PATHNAMES 0x10
#define SMB_FLAGS_CASELESS_PATHNAMES  0x08
#define SMB_FLAGS2_UNICODE_STRINGS    0x8000
#define SMB_FLAGS2_IS_LONG_NAME       0x0040
#define SMB_FLAGS2_KNOWS_LONG_NAME    0x0001

#define SMB_CAP_LARGE_FILES           0x08
#define SMB_GENERIC_WRITE             0x40000000
#define SMB_GENERIC_READ              0x80000000
#define SMB_FILE_SHARE_ALL            0x07
#define SMB_FILE_OPEN                 0x01
#define SMB_FILE_OVERWRITE_IF         0x05

#define SMB_ERR_NOACCESS              0x00050001

struct smb_header {
  __u8 nbt_type;
  __u8 nbt_flags;
  __u16 nbt_length;
  __u8 magic[4];
  __u8 command;
  __u32 status;
  __u8 flags;
  __u16 flags2;
  __u16 pid_high;
  __u8 signature[8];
  __u16 pad;
  __u16 tid;
  __u16 pid;
  __u16 uid;
  __u16 mid;
};

struct smb_negotiate_response {
  struct smb_header h;
  __u8 word_count;
  __u16 dialect_index;
  __u8 security_mode;
  __u16 max_mpx_count;
  __u16 max_number_vcs;
  __u32 max_buffer_size;
  __u32 max_raw_size;
  __u32 session_key;
  __u32 capabilities;
  __u32 system_time_low;
  __u32 system_time_high;
  __u16 server_time_zone;
  __u8 encryption_key_length;
  __u16 byte_count;
  __u8 bytes[1];
};

struct andx {
  __u8 command;
  __u8 pad;
  __u16 offset;
};

struct smb_setup {
  __u8 word_count;
  struct andx andx;
  __u16 max_buffer_size;
  __u16 max_mpx_count;
  __u16 vc_number;
  __u32 session_key;
  __u16 lengths[2];
  __u32 pad;
  __u32 capabilities;
  __u16 byte_count;
  __u8 bytes[1024];
};

struct smb_tree_connect {
  __u8 word_count;
  struct andx andx;
  __u16 flags;
  __u16 pw_len;
  __u16 byte_count;
  __u8 bytes[1024];
};

// struct smb_nt_create {
//   __u8 word_count;
//   struct andx andx;
//   __u8 pad;
//   __u16 name_length;
//   __u32 flags;
//   __u32 root_fid;
//   __u32 access;
//   curl_off_t allocation_size;
//   __u32 ext_file_attributes;
//   __u32 share_access;
//   __u32 create_disposition;
//   __u32 create_options;
//   __u32 impersonation_level;
//   __u8 security_flags;
//   __u16 byte_count;
//   __u8 bytes[1024];
// };

// struct smb_nt_create_response {
//   struct smb_header h;
//   __u8 word_count;
//   struct andx andx;
//   __u8 op_lock_level;
//   __u16 fid;
//   __u32 create_disposition;

//   curl_off_t create_time;
//   curl_off_t last_access_time;
//   curl_off_t last_write_time;
//   curl_off_t last_change_time;
//   __u32 ext_file_attributes;
//   curl_off_t allocation_size;
//   curl_off_t end_of_file;

// };

struct smb_read {
  __u8 word_count;
  struct andx andx;
  __u16 fid;
  __u32 offset;
  __u16 max_bytes;
  __u16 min_bytes;
  __u32 timeout;
  __u16 remaining;
  __u32 offset_high;
  __u16 byte_count;
};

struct smb_write {
  struct smb_header h;
  __u8 word_count;
  struct andx andx;
  __u16 fid;
  __u32 offset;
  __u32 timeout;
  __u16 write_mode;
  __u16 remaining;
  __u16 pad;
  __u16 data_length;
  __u16 data_offset;
  __u32 offset_high;
  __u16 byte_count;
  __u8 pad2;
};

struct smb_close {
  __u8 word_count;
  __u16 fid;
  __u32 last_mtime;
  __u16 byte_count;
};

struct smb_tree_disconnect {
  __u8 word_count;
  __u16 byte_count;
};

#endif /* HEADER_CURL_SMB_H */
