/*
 * netlink atrributes to message, for libreswan
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
 * A part of this came from iproute2 lib/libnetlink.c
 * Authors:     Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdio.h>
#include <string.h>

#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>

#include "netlink_attrib.h"

#define RTA_TAIL(rta) ((struct rtattr *) (((void *) (rta)) + \
			RTA_ALIGN((rta)->rta_len)))

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

int nl_addattr_l(struct nlmsghdr *n, const unsigned short maxlen,
		const unsigned short type, const void *data, int alen)
{
	unsigned short len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr, "ERROR: addattr_l: message exceeded bound %hu / %hu",
				n->nlmsg_len, maxlen);
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

struct rtattr *nl_addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	nl_addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

int nl_addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

int nl_addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str)
{
	return nl_addattr_l(n, maxlen, type, str, strlen(str)+1);
}

int nl_addattr32(struct nlmsghdr *n, int maxlen, int type, const uint32_t data)
{
	return nl_addattr_l(n, maxlen, type, &data, sizeof(uint32_t));
}
