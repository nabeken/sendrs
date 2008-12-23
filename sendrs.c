/*
Sending Router Solicitation test implemention.

THIS CODE IS PROVIDED BY AS-IS.

this code is based on radvd 1.2 and modified to send RS instead of RA.
*/

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/ipv6.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>

#define MSG_SIZE 4096
#define PATH_PROC_NET_IF_INET6 "/proc/net/if_inet6"
#define IPV6_ADDR_LINKLOCAL   0x0020U

int main(void) {
    uint8_t all_hosts_addr[] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};

    struct in6_addr *dest;
    struct in6_pktinfo *pkt_info;
    struct sockaddr_in6 addr;
    struct in6_pktinfo *pkg_info;
    struct nd_router_solicit *rs;

    struct msghdr mhdr;
    struct cmsghdr *cmsg;
    struct iovec iov;

    int sock;
    int err;

    size_t len = 0;
    unsigned char buf[MSG_SIZE];
    char chdr[CMSG_SPACE(sizeof(struct in6_pktinfo))];

    FILE *fp;
    char str_addr[40];
    char devname[IFNAMSIZ];
    unsigned int plen, scope, dad_status, if_idx;

    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if (sock < 0) {
	perror("socket error");
	return -1;
    }

    dest = (struct in6_addr *)all_hosts_addr;

    memset((void *)&addr, 0, sizeof(addr));

    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(IPPROTO_ICMPV6);
    memcpy(&addr.sin6_addr, dest, sizeof(struct in6_addr));

    memset(&buf, 0, sizeof(buf));
    rs = (struct nd_router_solicit *) buf;

    rs->nd_rs_type  = ND_ROUTER_SOLICIT;
    rs->nd_rs_code  = 0;
    rs->nd_rs_cksum = 0;
    rs->nd_rs_reserved = 0;

    len = sizeof(struct nd_router_solicit);

    /*
    これ以下は IPv6 のヘッダをつくってる‥はず。よくわからない。
    */

    iov.iov_len = len;
    iov.iov_base = (caddr_t) buf;

    memset(chdr, 0, sizeof(chdr));
    cmsg = (struct cmsghdr *) chdr;

    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;

    pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);

    /*
    ファイルを開いて、RSのソースアドレスとなるリンクローカルを捜している
    */
    if ((fp = fopen(PATH_PROC_NET_IF_INET6, "r")) == NULL) {
	    perror("can't open");
	    return -1;
    }
    
    while (fscanf(fp, "%32s %x %02x %02x %02x %15s\n",
		  str_addr, &if_idx, &plen, &scope, &dad_status,
		  devname) != EOF)
    {
	if (scope == IPV6_ADDR_LINKLOCAL) {
		struct in6_addr link_addr;
		unsigned int ap;
		int i;
		
		for (i=0; i<16; i++) {
			sscanf(str_addr + i * 2, "%02x", &ap);
			link_addr.s6_addr[i] = (unsigned char)ap;
		}

		memcpy(&pkt_info->ipi6_addr, &link_addr, sizeof(struct in6_addr));
		pkt_info->ipi6_ifindex = if_idx;

		fclose(fp);
	}
    }

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)&addr;
    mhdr.msg_namelen = sizeof(struct sockaddr_in6);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = (void *) cmsg;
    mhdr.msg_controllen = sizeof(chdr);

    err = sendmsg(sock, &mhdr, 0);

    if (err < 0) {
	perror("sendmsg error");
	return -1;
    }

    return 0;
}
