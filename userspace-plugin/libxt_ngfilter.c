#include <xtables.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "xt_ngfilter.h"
#include "libxt_ngfilter.h"
#include "strcpy.h"

static const struct option ngfilter_match_opts[] = {
	{.name = "pattern", .has_arg = true, .val = '1'},
	{.name = "smb-command", .has_arg = true, .val = '2'},
	{.name = "smb-tree-connect-path", .has_arg = true, .val = '3'},
	{NULL},
};

static struct xtables_match ngfilter_mt_reg = {
	.version = XTABLES_VERSION,
	.name = "ngfilter",
	.revision = 0,
	.family = NFPROTO_IPV4,
	.size = XT_ALIGN(sizeof(struct xt_ngfilter_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_ngfilter_mtinfo)),
	.help = ngfilter_match_help,
	.init = ngfilter_match_init,
	.parse = ngfilter_match_parse,
	.final_check = ngfilter_match_check,
	.print = ngfilter_match_print,
	.save = ngfilter_match_save,
	.extra_opts = ngfilter_match_opts,
};


static void ngfilter_match_init(struct xt_entry_match *match) {
	// struct xt_ngfilter_mtinfo *info = (void	 *)match->data;
}

/*
 * Prints the rule.
 */
static void ngfilter_match_save(const void *entry, const struct xt_entry_match *match) {
	const struct xt_ngfilter_mtinfo *info = (const void *)match->data;

	if (is_have_flag(info, XT_NGFILTER_PATTERN)) {
		printf(" --pattern %s", info->pattern);
	}

	if (is_have_flag(info, XT_NGFILTER_SMB_COMMAND)) {
		printf(" --smb-command %02x", info->smb_command);
	}
}

static void ngfilter_match_print(const void *entry, const struct xt_entry_match *match, int numeric) {

	const struct xt_ngfilter_mtinfo *info = (const void *)match->data;

	if (is_have_flag(info, XT_NGFILTER_PATTERN)) {
		printf(" with pattern");
	}

	if (is_have_flag(info, XT_NGFILTER_SMB_COMMAND)) {
		printf(" with smb command %02x", info->smb_command);
	}
}

static bool is_hex_digit(char c) {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int ngfilter_match_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_match **match) {

	struct xt_ngfilter_mtinfo *info = (void *)(*match)->data;

	switch (c) {
		case '1': /* --pattern */
			if (*flags & XT_NGFILTER_PATTERN){
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: "
						"Only use \"--pattern\" once!");
			}
			if (invert) {
				xtables_error(PARAMETER_PROBLEM, "xt_ngfilter: "
						"\"--pattern\" invert not implemented.");
			}

			*flags |= XT_NGFILTER_PATTERN;
			info->flags |= XT_NGFILTER_PATTERN;

			strcpy_safe((char*)info->pattern, optarg, MAX_PATTERN_LENGTH);

			return true;
		
		case '2': /* --smb-command */
			if (*flags & XT_NGFILTER_PATTERN){
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: "
						"Only use \"--smb-command\" once!");
			}
			if (invert) {
				xtables_error(PARAMETER_PROBLEM, "xt_ngfilter: "
						"\"--smb-command\" invert not implemented.");
			}
			if (strlen(optarg) != 2 && is_hex_digit(optarg[0]) && is_hex_digit(optarg[1])){
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: "
						"smb-command must be 2 digit hexadecimal.");
			}

			*flags |= XT_NGFILTER_SMB_COMMAND;
			info->flags |= XT_NGFILTER_SMB_COMMAND;

			info->smb_command = (__u8) strtoul(optarg, NULL, 16);

			return true;

	    default:
            return false;
    }
}


static void ngfilter_match_check(unsigned int flags) {
	if (flags == 0) {
		xtables_error(PARAMETER_PROBLEM, "xt_ngfilter: You need to "
				"specify \"--pattern\".");
	}
}


static void ngfilter_match_help(void) {
	printf(
			"ngfilter match options:\n"
			"[!] --pattern addr Match pattern inside packet\n"
		  );
}


void _init(void) {
	xtables_register_match(&ngfilter_mt_reg);
}

