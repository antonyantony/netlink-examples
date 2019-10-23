/* 
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net> from libreswan source code.
 * Copyright (C) 2019 Antony Antony <antony@phenome.org>
 *
 * parts of the code comes from  iproute2 ip/iplink.c ip/ipaddress.c
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/*
 * When reading data from netlink the final message in each recvfrom()
 * will be truncated if it doesn't fit to buffer. Netlink seem to return up
 * to 32KiB of data. Keep 32K minimum buffer.
 */
#define NL_BUFMARGIN 32768
#define IFINFO_REPLY_BUFFER_SIZE (NL_BUFMARGIN * 2)

#define LINE_LEN 512

struct nl_ifinfomsg_req {
        struct nlmsghdr n;
        struct ifinfomsg i;
};

/*
static char *parse_link_kind(struct rtattr *tb)
{
	if (tb[IFLA_LINKINFO] == NULL)
		return NULL;

	struct rtattr *attr_link_kind = tb[IFLA_LINKINFO];
	int attr = IFLA_INFO_KIND;

	struct rtattr *linkinfo[IFLA_INFO_MAX+1];
	parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb);

	if (linkinfo[attr])
                return RTA_DATA(linkinfo[attr]);

	return NULL;
}

parse_nested_arguments()
{

	  for (struct rtattr * nested_attrib = (struct rtattr *) RTA_DATA(attribute); RTA_OK(nested_attrib, attribute->rta_len); nested_attrib = RTA_NEXT(nested_attrib, attribute->rta_len)) { 
		  if (nested_attrib->rta_type == IFLA_INFO_KIND) {
			struct rtattr *kind_attr = nested_attrib;
			char *kind_str = RTA_DATA(kind_attr);
			if (!strcmp("xfrm", kind_str)) {
				snprintf(kind, LINE_LEN, "type %s IFLA_LINKINFO %u IFLA_INFO_KIND %u strlen %u ", kind_str, attribute->rta_len, kind_attr->rta_len,  strlen(kind_str));
		  } else if (nested_attrib->rta_type == IFLA_XFRM_IF_ID) {
			u_int32_t *if_id = (u_int32_t*) RTA_DATA(nested_attrib);
  			snprintf(if_id_str, LINE_LEN,  "if_id 0x%x", *if_id);
		  }
	  }

	  }
}

parse_rtattr()
{

}
*/

static void parse_nlmsg_print(struct nlmsghdr *h)
{
	struct ifinfomsg *iface;
	struct rtattr *attribute;
	int len;

	iface = NLMSG_DATA(h);
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

	char ifn[LINE_LEN] = "";
	char kind[LINE_LEN] = "";

	for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len); attribute = RTA_NEXT(attribute, len))
	{
		switch(attribute->rta_type)
		{
			case IFLA_IFNAME:
				snprintf(ifn, LINE_LEN, "Interface %d : %s ", iface->ifi_index, (char *) RTA_DATA(attribute));
				break;
			case IFLA_LINKINFO:
				//kind = parse_link_kind(attribute);
				for (struct rtattr * nested_attrib = (struct rtattr *) RTA_DATA(attribute); RTA_OK(nested_attrib, attribute->rta_len); nested_attrib = RTA_NEXT(nested_attrib, attribute->rta_len)) { 
					if (nested_attrib->rta_type == IFLA_INFO_KIND) {
						struct rtattr *kind_attr = nested_attrib;

						char *kind_str = RTA_DATA(kind_attr);
						if (!strcmp("xfrm", kind_str))
							snprintf(kind, LINE_LEN, "type %s IFLA_LINKINFO %u IFLA_INFO_KIND %u strlen %ld ", kind_str, attribute->rta_len, kind_attr->rta_len,  strlen(kind_str));
					}
				}
				break;
			default:
				break;
		}
	}

	if(strlen(ifn) > 0)
		printf("%s %s \n", ifn, kind);
}

static ssize_t process_nlmsgs(char *msgbuf, ssize_t len)
{
	int i = 0;
	int ignored = 0;
	int red_msg_size = 0;
	struct nlmsghdr *nlmsg = (struct nlmsghdr *)msgbuf;
	for (; NLMSG_OK(nlmsg, (size_t)len); nlmsg = NLMSG_NEXT(nlmsg, len)) {
		switch(nlmsg->nlmsg_type)
		{
			case NLMSG_DONE:
				printf("got NLMSG_DONE: RTM_NEWLINK messages %d ignored %d. Bytes %d\n",
						i, ignored, red_msg_size);
				return 0;
			case NLMSG_ERROR:
				printf("ERROR: netlink error\n");
				free(msgbuf);
				return -1;
			case RTM_NEWLINK:
				i++;
				red_msg_size += nlmsg->nlmsg_len;
				parse_nlmsg_print(nlmsg);
				break;
			case 0:
				printf("INFO: NOOP? message type %d length %d\n", nlmsg->nlmsg_type,
						nlmsg->nlmsg_len);	
				ignored++;
				break;

			default:
				printf("INFO: ignored message type %d length %d\n", nlmsg->nlmsg_type,
						nlmsg->nlmsg_len);
				ignored++;
				break;
		}
	}

	return 0;
}

static ssize_t netlink_read_reply(int sock, char **pbuf, size_t bufsize,
                                  unsigned int seqnum, __u32 pid)
{
	size_t msglen = 0;
	int i = 0;
        int ignored = 0;
        int parsed_msg_size = 0;

	for (;;) {
		struct sockaddr_nl sa;
		ssize_t readlen;

		/* Read netlink message, verifying kernel origin. */
		do {
			socklen_t salen = sizeof(sa);

			readlen = recvfrom(sock, (*pbuf + msglen),
					bufsize - msglen, 0,
					(struct sockaddr *)&sa, &salen);
			if (readlen <= 0 || salen != sizeof(sa))
				return -1;
		} while (sa.nl_pid != 0);

		/* Verify it's valid */
		struct nlmsghdr *nlhdr = (struct nlmsghdr *)(*pbuf + msglen);

		if (!NLMSG_OK(nlhdr, (size_t)readlen) ||
				nlhdr->nlmsg_type == NLMSG_ERROR)
			return -1;

		struct nlmsghdr *nlmsg = (struct nlmsghdr *) (*pbuf + msglen);
		/* Move read pointer */
		msglen += readlen;
		for (; NLMSG_OK(nlmsg, (size_t)readlen);
				nlmsg = NLMSG_NEXT(nlmsg, readlen)) {
			switch(nlmsg->nlmsg_type)
			{
				case NLMSG_DONE:
					printf("NLMSG_DONE red %ld/%ld\n", msglen, bufsize);
					return msglen;

				case NLMSG_ERROR:
					printf("NLMSG_ERROR red %ld/%ld\n", msglen, bufsize);
					printf("ERROR: netlink error\n");
					return msglen;

				case RTM_NEWLINK:
					i++;
					parsed_msg_size += nlmsg->nlmsg_len;
					//printf("%d/%d nlmsg %p read/total %d/%d FOUND RTM_NEWLINK\n", i, n, nlmsg, nlmsg->nlmsg_len, size);
					break;
				case 0:
					printf("INFO: NOOP? message type %d length %d\n", nlmsg->nlmsg_type, nlmsg->nlmsg_len);
					ignored++;
					break;
				default:
					printf("INFO: ignored message type %d length %d\n", nlmsg->nlmsg_type, nlmsg->nlmsg_len);
					ignored++;
					break;
			}

			/* all done if it's not a multi part */
			if ((nlhdr->nlmsg_flags & NLM_F_MULTI) == 0)
			{
				printf("NOT NLM_F_MULTI end red %ld/%ld\n", msglen, bufsize);
				return msglen;
			}

			/* all done if this is the one we were searching for */
			if (nlhdr->nlmsg_seq == seqnum && nlhdr->nlmsg_pid == pid)
			{
				printf("PID match red %ld/%ld\n", msglen, bufsize);
				return msglen;
			}
		}
		/* Allocate more memory for buffer if needed. */
		if (msglen >= bufsize - NL_BUFMARGIN) {
			bufsize = bufsize * 2;
			char *newbuf = (char *)malloc(bufsize);
			if (newbuf == NULL) {
				printf("ERROR malloc failed for %ld bytes\n", bufsize);
				return -1;
			}
  			memset(newbuf, '\0', bufsize);
			memcpy(newbuf, *pbuf, msglen);
			free(*pbuf);
			*pbuf = newbuf;
		}
	}
        return msglen;
}

int main(void)
{
  struct nl_ifinfomsg_req nl_req = { /* netlink request message */
  	.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
  	.n.nlmsg_type = RTM_GETLINK,
  	.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
	.n.nlmsg_seq = 0,
	.n.nlmsg_pid = getpid(),
	.i.ifi_family = AF_PACKET,
	.i.ifi_type = 0,
	.i.ifi_index = 0,
  };

  /* 
   * open a netlink socket for kernel for userland communication 
   * for "ip link show" info set protocol to NETLINK_ROUTE,
   * domain to AF_NETLINK (not PF_NETLINK).
   */

  int nl_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (nl_fd < 0) {
	  int e = errno;
	  printf("create netlink socket failure: (%d: %s)\n", e, strerror(e));
	  return -1;
  }
 
  /* send request to RTNL socket */
  if (send(nl_fd, &nl_req.n, nl_req.n.nlmsg_len, 0) < 0) {
	  int e = errno;
	  printf("write netlink socket failure: (%d: %s)\n", e, strerror(e));
	  close(nl_fd);
	  return -1;
  }

  char *resp_msgbuf = (char *) malloc(IFINFO_REPLY_BUFFER_SIZE);
  memset(resp_msgbuf, '\0', IFINFO_REPLY_BUFFER_SIZE);
  errno = 0;

  ssize_t len = netlink_read_reply(nl_fd, &resp_msgbuf, IFINFO_REPLY_BUFFER_SIZE, 1, getpid());
  if (len < 0) {
	  printf("read netlink socket failure: (%d: %s)\n", errno, strerror(errno));
  } else {
	  printf("red %ld bytes netlink response\n", len);
  }

  process_nlmsgs(resp_msgbuf, len);

  close(nl_fd);

  return 0;
}
