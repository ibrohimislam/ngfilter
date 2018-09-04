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
	{.name = "dpi", .has_arg = true, .val = '1'},
	{.name = "pattern", .has_arg = true, .val = '2'},
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

	if (is_have_flag(info, XT_NGFILTER_DPI)) {
		printf(" --dpi %u", info->dpi);
	}
	if (is_have_flag(info, XT_NGFILTER_PATTERN)) {
		printf(" --pattern %s", info->pattern);
	}
}


static void ngfilter_match_print(const void *entry, const struct xt_entry_match *match, int numeric) {

	const struct xt_ngfilter_mtinfo *info = (const void *)match->data;

	if (is_have_flag(info, XT_NGFILTER_DPI)) {
		printf(" dpi(%u)", info->dpi);
	}
	if (is_have_flag(info, XT_NGFILTER_PATTERN)) {
		if (is_have_flag(info, XT_NGFILTER_DPI)) {
			printf(" ");
		}
		printf(" with pattern");
	}
}


static int ngfilter_match_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_match **match) {

	struct xt_ngfilter_mtinfo *info = (void *)(*match)->data;

	switch (c) {
		case '1': /* --dpi */
			if (*flags & XT_NGFILTER_DPI) {
				xtables_error(PARAMETER_PROBLEM, "xt_ngfilter: "
						"Only use \"--dpi\" once!");
			}
			if (invert) {
				xtables_error(PARAMETER_PROBLEM, "xt_ngfilter: "
						"\"--dpi\" invert not implemented.");
			}

			*flags |= XT_NGFILTER_DPI;
			info->flags |= XT_NGFILTER_DPI;
			info->dpi = (__u8) atoi(optarg);

			return true;

		case '2': /* --pattern */
			if (*flags & XT_NGFILTER_PATTERN){
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: "
						"Only use \"--pattern\" once!");
			}
			if (invert) {
				xtables_error(PARAMETER_PROBLEM, "xt_ngfilter: "
						"\"--dpi\" invert not implemented.");
			}

			*flags |= XT_NGFILTER_PATTERN;
			info->flags |= XT_NGFILTER_PATTERN;
			strcpy_safe((char*)&info->pattern, optarg, MAX_PATTERN_LENGTH-1);

			return true;

	    default:
            return false;
    }
}


static void ngfilter_match_check(unsigned int flags) {
	if (flags == 0) {
		xtables_error(PARAMETER_PROBLEM, "xt_ngfilter: You need to "
				"specify at least \"--dpi\" or \"--pattern\".");
	}
}


static void ngfilter_match_help(void) {
	printf(
			"ngfilter match options:\n"
			"[!] --dpi addr Match protocol of packet\n"
			"[!] --pattern addr Match pattern inside packet\n"
		  );
}


void _init(void) {
	xtables_register_match(&ngfilter_mt_reg);
}

