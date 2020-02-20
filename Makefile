WERROR_CFLAGS?=-Werror
WARNING_CFLAGS?=-Wall -Wextra -Wformat -Wformat-nonliteral -Wformat-security -Wundef -Wmissing-declarations -Wredundant-decls -Wnested-externs

USERLAND_CFLAGS+= $(WERROR_CFLAGS)
USERLAND_CFLAGS+= $(WARNING_CFLAGS)
USERLAND_CFLAGS+= -g
all:
	gcc $(USERLAND_CFLAGS) -o ip_link_show ip_link_show.c
	gcc $(USERLAND_CFLAGS) -o ip_addr ip_addr.c netlink_attrib.c
