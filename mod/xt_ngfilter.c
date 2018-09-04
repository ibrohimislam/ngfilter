#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/module.h>

#include "xt_ngfilter.h"

MODULE_AUTHOR("Ibrohim Kholilul Islam <ibrohimislam@gmail.com>");
MODULE_DESCRIPTION("Xtables: packet filter with DPI");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_ALIAS("ipt_ngfilter");

static bool is_dpi_match(const struct sk_buff *skb, __u8 protocol) {
	// TODO: implement
	return false;
}

static bool is_pattern_match(const struct sk_buff *skb, __u8 *pattern) {
	// TODO: implement
	return false;
}

static bool is_protocol_exists(const __u8 protocol) {
	// TODO: implement
	return true;
}

/*
 * The match function
 */
static bool ngfilter_match(const struct sk_buff *skb, struct xt_action_param *param) {
	const struct xt_ngfilter_mtinfo *info = param->matchinfo;
	const struct iphdr *ip_header = ip_hdr(skb);

	pr_info("SRC=%pI4 DST=%pI4\n", &ip_header->saddr, &ip_header->daddr);

	if (is_have_flag(info,XT_NGFILTER_DPI) && !is_dpi_match(skb, info->dpi)) {
		pr_notice("protocol - no match\n");
		return false;
	}

	if (is_have_flag(info,XT_NGFILTER_PATTERN) && !is_pattern_match(skb, info->pattern)) {
		pr_notice("pattern - no match\n");
		return false;
	}

	return true;
}

/*
 * This function checks if the added rule is valid.
 */
static int ngfilter_match_check(const struct xt_mtchk_param *par) {
	const struct xt_ngfilter_mtinfo *info = par->matchinfo;
	
	pr_info("Added a rule with -m ngfilter in the %s table; this rule is "
			"reachable through hooks 0x%x\n",
			par->table, par->hook_mask);

	if (info->flags == 0) {
		pr_info("not testing for anything\n");
		return -EINVAL;
	}
	
	if (is_have_flag(info, XT_NGFILTER_DPI) && !is_protocol_exists(info->dpi)) {
		pr_info("Protocol not found on nDPI implementation.\n");
		return -EINVAL;
	}
	
	return 0;
}

static void ngfilter_match_destroy(const struct xt_mtdtor_param *par) {
	const struct xt_ngfilter_mtinfo *info = par->matchinfo;
	pr_info("Test for protocol %08lX removed\n", info->dpi);
}


static struct xt_match ngfilter_match4_reg __read_mostly = {
	.name = "ngfilter",
	.revision = 0,
	.family = NFPROTO_IPV4,
	.match = ngfilter_match,
	.checkentry = ngfilter_match_check,
	.destroy = ngfilter_match_destroy,
	.matchsize = sizeof(struct xt_ngfilter_mtinfo),
	.me = THIS_MODULE,
};

static int __init ngfilter_match_reg(void) {
	int ret;
	ret = xt_register_match(&ngfilter_match4_reg);
	pr_info("The NGFilter module has been successfully loaded...\n");
	return ret;
}

static void __exit ngfilter_match_exit(void) {
	xt_unregister_match(&ngfilter_match4_reg);
	pr_info("The NGFilter module has been successfully unloaded...\n");
}

module_init(ngfilter_match_reg);
module_exit(ngfilter_match_exit);