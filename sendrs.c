/*
Sending Router Solicitation test implemention.

THIS CODE IS PROVIDED BY AS-IS.

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>

#define MSG_SIZE 4096
#define MAX_IFR 10
#define IFNM "eth0"
#define PATH_PROC_NET_IF_INET6 "/proc/net/if_inet6"
#define IPV6_ADDR_LINKLOCAL   0x0020U

int main(void) {
    char all_routers_addr[] = "ff02::2";
    struct addrinfo hints, *res;
    static struct sockaddr_storage ss;
    struct nd_router_solicit *rs;
    struct nd_opt_hdr *rs_opt_hdr;
    unsigned char buf[4096];
    struct msghdr mhdr;
    struct cmsghdr *cmsg;
    struct iovec iov;
    struct in6_pktinfo *pinfo;
    struct ifreq ifr;

    int sock, err, fd, nifs, i;
    size_t len;
    char cmsgb[CMSG_SPACE(sizeof(struct in6_pktinfo))];

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_protocol = IPPROTO_ICMPV6;

    err = getaddrinfo(all_routers_addr, NULL, &hints, &res);

    if (err) {
	fprintf(stderr, "%s/%s: %s\n", all_routers_addr, IPPROTO_ICMPV6, gai_strerror(err));
	exit(1);
    }

    if (res->ai_addrlen > sizeof(ss)) {
	fprintf(stderr, "sockaddr too large\n");
	exit(1);
    }

    memcpy(&ss, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sock < 0) {
	perror("socket error");
	return -1;
    }

    memset(&buf, 0, sizeof(buf));
    rs = (struct nd_router_solicit *) buf; /* bufの先をRSメッセージの先へのポインタに */

    rs->nd_rs_type  = ND_ROUTER_SOLICIT;
    rs->nd_rs_code  = 0;
    rs->nd_rs_cksum = 0;
    rs->nd_rs_reserved = 0;

    len = sizeof(struct nd_router_solicit); /* RS メッセージの大きさ (64ビット) */

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, IFNM, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
	perror("ioctl error");
	exit(1);
    }

    rs_opt_hdr = (struct nd_opt_hdr *)(buf + len);
    rs_opt_hdr->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    rs_opt_hdr->nd_opt_len  = (sizeof(struct nd_opt_hdr) + sizeof(char) * 6) / 8;

    len += sizeof(struct nd_opt_hdr);

    if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
	memcpy(buf + len, ifr.ifr_hwaddr.sa_data, sizeof(char) * 6);
    }

    close(fd);

    len += sizeof(char) * 6;

    /*
    iov には Router Solicitation (ICMPv6) に関する情報が入る
    */

    iov.iov_len = len;
    iov.iov_base = (caddr_t) buf;

    /*
    これ以下は IPv6 のヘッダをつくってる。
    mhdr では送信先アドレスが入る
    cmdg には宛先サドレスが入る
    */

    memset(cmsgb, 0, sizeof(cmsgb));

    cmsg = (struct cmsghdr *) cmsgb;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;

    pinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    err = get_linklocal_addr(IFNM, pinfo);

    if (err < 0) {
	perror("can't get link local address");
	exit(1);
    }

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (void *)&ss;
    mhdr.msg_namelen = sizeof(struct sockaddr_in6);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = (void *) cmsg;
    mhdr.msg_controllen = sizeof(cmsgb);

    err = sendmsg(sock, &mhdr, 0);

    if (err < 0) {
	perror("sendmsg error");
	exit(1);
    }

    return 0;
}

/* this function is delivered by radvd-1.2/device-linux.c */
/* and bit modified */

int get_linklocal_addr(char *ifname, struct in6_pktinfo *pinfo)
{
	FILE *fp;
	char str_addr[40];
	unsigned int plen, scope, dad_status, if_idx;
	char devname[IFNAMSIZ];

	if ((fp = fopen(PATH_PROC_NET_IF_INET6, "r")) == NULL)
	{
		perror("can't open");
		return (-1);	
	}
	
	while (fscanf(fp, "%32s %x %02x %02x %02x %15s\n",
		      str_addr, &if_idx, &plen, &scope, &dad_status,
		      devname) != EOF)
	{
		if (scope == IPV6_ADDR_LINKLOCAL &&
		    strcmp(devname, ifname) == 0)
		{
			struct in6_addr addr;
			unsigned int ap;
			int i;
			
			for (i=0; i<16; i++)
			{
				sscanf(str_addr + i * 2, "%02x", &ap);
				addr.s6_addr[i] = (unsigned char)ap;
			}
			memcpy(&pinfo->ipi6_addr, &addr, sizeof(addr));
			pinfo->ipi6_ifindex = if_idx;
			fclose(fp);
			return 0;
		}
	}

	fclose(fp);
	return (-1);
}
