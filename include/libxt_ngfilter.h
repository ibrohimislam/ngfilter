/**
 * @author Ibrohim Kholilul Islam
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
