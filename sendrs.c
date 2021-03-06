/*
Test implementation of sending Router Solicitation.

THIS CODE IS PROVIDED BY AS-IS.

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netdb.h>

#define MSG_SIZE 4096
#define MAX_IFR 10
#define HOPLIMIT 255
#define PATH_PROC_NET_IF_INET6 "/proc/net/if_inet6"
#define IPV6_ADDR_LINKLOCAL   0x0020U

void usage(char *cmd) {
    fprintf(stderr, "usage: %s <interface>\n", cmd);
}

int main(int argc, char *argv[]) {
    char all_routers_addr[] = "ff02::2";
    struct addrinfo hints, *res;
    static struct sockaddr_storage ss;
    struct nd_router_solicit *rs;
    uint8_t *rs_opt;
    unsigned char buf[4096];
    struct msghdr mhdr;
    struct cmsghdr *cmsg_pinfo, *cmsg_hoplimit;
    struct iovec iov;
    struct in6_pktinfo *pinfo;
    struct ifreq ifr;
    char *ifname;

    if (argc < 2) {
	fprintf(stderr, "please specify interface\n");
	usage(argv[0]);
	exit(1);
    } else if (argc > 2) {
	fprintf(stderr, "too many args\n");
	usage(argv[0]);
	exit(1);
    }

    ifname = argv[1];

    int sock, err, fd, nifs, i;
    int *hoplimit;
    size_t len;
    char cmsg_buf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
    char cmsg_pinfo_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    char cmsg_hoplimit_buf[CMSG_SPACE(sizeof(int))];

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_protocol = IPPROTO_ICMPV6;

    err = getaddrinfo(all_routers_addr, NULL, &hints, &res);

    if (err) {
	fprintf(stderr, "%s/%d: %s\n", all_routers_addr, IPPROTO_ICMPV6, gai_strerror(err));
	exit(1);
    }

    if (res->ai_addrlen > sizeof(ss)) {
	fprintf(stderr, "sockaddr too large\n");
	exit(1);
    }

    memcpy(&ss, res->ai_addr, res->ai_addrlen);

    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    freeaddrinfo(res);

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
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
	perror("ioctl error");
	exit(1);
    }


    if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
	rs_opt = (uint8_t *) (buf + len);
	*rs_opt++ = ND_OPT_SOURCE_LINKADDR;
	*rs_opt++ = (uint8_t) 1; /* Ethernet 決め打ち… */

	len += 2 * sizeof(uint8_t);

	memcpy(buf + len, ifr.ifr_hwaddr.sa_data, sizeof(char) * 6);
	len += sizeof(char) * 6;
    }

    close(fd);

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

    memset(cmsg_pinfo_buf, 0, sizeof(cmsg_pinfo_buf));
    memset(cmsg_hoplimit_buf, 0, sizeof(cmsg_hoplimit_buf));

    cmsg_pinfo = (struct cmsghdr *) cmsg_pinfo_buf;
    cmsg_pinfo->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    cmsg_pinfo->cmsg_level = IPPROTO_IPV6;
    cmsg_pinfo->cmsg_type = IPV6_PKTINFO;

    pinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg_pinfo);
    err = get_linklocal_addr(ifname, pinfo);

    fprintf(stderr, "pinfo: %i\n", sizeof(cmsg_pinfo_buf));

    if (err < 0) {
	perror("can't get link local address");
	exit(1);
    }

    fprintf(stderr, "dev: %i\n", ((struct in6_pktinfo *)CMSG_DATA(cmsg_pinfo))->ipi6_ifindex);

    cmsg_hoplimit = (struct cmsghdr *) cmsg_hoplimit_buf;
    cmsg_hoplimit->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg_hoplimit->cmsg_level = IPPROTO_IPV6;
    cmsg_hoplimit->cmsg_type = IPV6_HOPLIMIT;

    fprintf(stderr, "hoplimit: %i\n", sizeof(cmsg_hoplimit_buf));

    hoplimit = (int *)CMSG_DATA(cmsg_hoplimit);
    *hoplimit = HOPLIMIT;

    memcpy(cmsg_buf, cmsg_pinfo_buf, sizeof(cmsg_pinfo_buf));
    memcpy(cmsg_buf + sizeof(cmsg_pinfo_buf), cmsg_hoplimit, sizeof(cmsg_hoplimit_buf));

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t *)&ss;
    mhdr.msg_namelen = sizeof(struct sockaddr_in6);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = (void *) cmsg_buf;
    mhdr.msg_controllen = sizeof(cmsg_buf);

    fprintf(stderr, "controllen: %i\n", mhdr.msg_controllen);

    if (CMSG_NXTHDR(&mhdr, cmsg_pinfo) != NULL) {
	fprintf(stderr, "has next\n");
    } else {
	fprintf(stderr, "has no next!\n");
	exit(1);
    }

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
