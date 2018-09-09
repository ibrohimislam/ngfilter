#ifndef HEADER_NETBIOS_H
#define HEADER_NETBIOS_H

struct nbss_hdr {
  __u8 type;
  __u8 flag;
  __u16 length;
};

#endif