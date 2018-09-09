#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>

#include "xt_ngfilter.h"
#include "string_match.h"
#include "smb.h"
#include "netbios.h"

MODULE_AUTHOR("Ibrohim Kholilul Islam <ibrohimislam@gmail.com>");
MODULE_DESCRIPTION("Xtables: packet filter with DPI");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_ALIAS("ipt_ngfilter");

struct payload_t {
	unsigned char *data;
	__u32 len;
};

static const struct payload_t * get_payload(const struct sk_buff *skb) {
	struct iphdr *ip_header;
	unsigned char *transport_header;

	__u32 transport_header_len;

	struct payload_t *result = kmalloc(sizeof(struct payload_t), GFP_NOWAIT);

    if (!skb) return result;

    ip_header = ip_hdr(skb);
    transport_header = skb_transport_header(skb);

	switch (ip_header->protocol) {
	case IPPROTO_ICMP:
		transport_header_len = 16;
		break;
	case IPPROTO_TCP:
		transport_header_len = tcp_hdr(skb)->doff * 4;
		break;
	default:
		return result;
	}

    result->data = ((unsigned char *)transport_header + transport_header_len);
	result->len = (__u32)(ntohs(ip_header->tot_len) - ip_header->ihl*4 - transport_header_len);

	return result;
}

static bool smb_command_match(const struct payload_t *payload, const unsigned char command){
	struct smb_header *smb_header;
	smb_header = (struct smb_header *) payload->data + 4;

	return smb_header->command == command;
}

/*
 * The match function
 */
static bool ngfilter_match(const struct sk_buff *skb, struct xt_action_param *param) {
	const struct xt_ngfilter_mtinfo *info = param->matchinfo;
	const struct iphdr *ip_header = ip_hdr(skb);
	const struct payload_t *payload = get_payload(skb);
    
	pr_info("SRC=%pI4 DST=%pI4\n", &ip_header->saddr, &ip_header->daddr);

	if (is_have_flag(info, XT_NGFILTER_PATTERN) &&
		!string_match((const char *) info->pattern, payload->data, strlen(info->pattern), payload->len)) {
		return false;
	}

	if (is_have_flag(info,XT_NGFILTER_SMB_COMMAND) &&
		!smb_command_match(payload, info->smb_command)) {
		return false;
	}

	kfree(payload);

	pr_notice("pattern %s - match\n", info->pattern);
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
	
	return 0;
}

static void ngfilter_match_destroy(const struct xt_mtdtor_param *par) {
	const struct xt_ngfilter_mtinfo *info = par->matchinfo;
	pr_info("Test for pattern %s\n", info->pattern);
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