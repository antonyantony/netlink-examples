/*
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net> from libreswan source code.
 * Copyright (C) 2019-2020 Antony Antony <antony@phenome.org>
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
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "netlink_attrib.h"

/*
 * When reading data from netlink the final message in each recvfrom()
 * will be truncated if it doesn't fit to buffer. Netlink seem to return up
 * to 32KiB of data. Keep 32K minimum buffer.
 */
#define NL_BUFMARGIN 32768 * 2
#define IFINFO_REPLY_BUFFER_SIZE NL_BUFMARGIN

#define LINE_LEN 512

struct nl_ifaaddrmsg_req {
        struct nlmsghdr n;
        struct ifaddrmsg ifa;
	char buf[512];
};

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
				return -1;
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

		if (!NLMSG_OK(nlhdr, (size_t)readlen))
			return -1;

		struct nlmsghdr *nlmsg = (struct nlmsghdr *) (*pbuf + msglen);
		if (nlhdr->nlmsg_type == NLMSG_ERROR) {
			if (nlhdr->nlmsg_len >= (sizeof(struct nlmsgerr) + NLMSG_HDRLEN)) {
				struct nlmsgerr *err = NLMSG_DATA(nlhdr);
				printf("error = %d \"%s\"\n", err->error, strerror((-err->error)));
			} else {
				printf("error message is too short %d/%zu\n", nlhdr->nlmsg_len, (sizeof(struct nlmsgerr) + NLMSG_HDRLEN));
			}
			return 0;
		}
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
  struct nl_ifaaddrmsg_req nl_req = { /* netlink request message */
	.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),

	.n.nlmsg_type = RTM_NEWADDR,
	.n.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST | NLM_F_ACK,

	// .n.nlmsg_type = RTM_DELADDR;
	// .n.nlmsg_flags = NLM_F_REQUEST;

	.n.nlmsg_seq = 0,
	.n.nlmsg_pid = getpid(),
	.ifa.ifa_family = AF_INET,
	.ifa.ifa_prefixlen = 32,
	.ifa.ifa_index = 1 , // loopback
	.ifa.ifa_scope = 0 ,
  };

  const char cip[] = "192.192.192.192";
   struct in_addr ip;
  inet_aton(cip, &ip);

  nl_addattr_l(&nl_req.n, sizeof(nl_req), IFA_LOCAL, &ip.s_addr, sizeof(uint32_t));

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
  printf("send %u bytes \n", nl_req.n.nlmsg_len);
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
	if (len > 0) {
		printf("red %ld bytes netlink response\n", len);
		process_nlmsgs(resp_msgbuf, len);
	}
  }

  free(resp_msgbuf);
  close(nl_fd);

  return 0;
}
