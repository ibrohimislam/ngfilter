/**
 * @author Ibrohim Kholilul Islam
 */

#ifndef _LINUX_NETFILTER_XT_NGFILTER_H
#define _LINUX_NETFILTER_XT_NGFILTER_H

/*
 * Binary operations are used to be more accurate that a numerical
 * representation.
 */
enum {
	XT_NGFILTER_DPI = 1 << 0,
	XT_NGFILTER_PATTERN = 1 << 1,
};


#define is_have_flag(info, flag) !!(info->flags & flag)


/*
 * This is the information to which we want to match against.
 */
#define MAX_PATTERN_LENGTH 256
struct xt_ngfilter_mtinfo {
	__u8 dpi;
	char pattern[MAX_PATTERN_LENGTH];
	__u8 flags;
};

#endif /* _LINUX_NETFILTER_XT_NGFILTER_H */
