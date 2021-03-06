/*
 * Copyright (C) 2009-2013 Michael Richardson <mcr@sandelman.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

/*
 * this file is just for setup and maintenance of interface,
 * it does not really do any heavy lifting.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include <errno.h>
#include <pathnames.h>		/* for PATH_PROC_NET_IF_INET6 */
#include <poll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if_arp.h>         /* for ARPHRD_ETHER */
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/if.h>           /* for IFNAMSIZ */
#include <time.h>

#include <netlink/rt_names.h>
#include <netlink/utils.h>
#include <netlink/ll_map.h>

}

#include "iface.h"

struct rtnl_handle* network_interface::netlink_handle = NULL;

class iface_factory basic_factory;
class iface_factory *iface_maker = &basic_factory;

network_interface *iface_factory::newnetwork_interface(const char *name, netprog_debug *deb)
{
    return new network_interface(name, deb);
}

int network_interface::gather_linkinfo(const struct sockaddr_nl *who,
                           struct nlmsghdr *n, void *arg)
{

    switch(n->nlmsg_type) {
    case RTM_NEWLINK:
    case RTM_DELLINK:
        adddel_linkinfo(who, n, arg);
        break;
    case RTM_NEWADDR:
        adddel_ipinfo(who, n, arg);
        break;
    }
}

int network_interface::adddel_ipinfo(const struct sockaddr_nl *who,
                                       struct nlmsghdr *n, void *arg)
{
    struct network_interface_init *nii = (struct network_interface_init *)arg;
    netprog_debug *deb = nii->debug;
    struct ifaddrmsg *iai = (struct ifaddrmsg *)NLMSG_DATA(n);
    struct rtattr * tb[IFA_MAX+1], *addrattr;
    int len = n->nlmsg_len;
    unsigned m_flag = 0;
    SPRINT_BUF(b1);

    len -= NLMSG_LENGTH(sizeof(*iai));
    if (len < 0)
        return -1;

    parse_rtattr(tb, IFA_MAX, IFA_RTA(iai), len);
    addrattr = tb[IFA_LOCAL];
    if(addrattr == NULL) {
        addrattr = tb[IFA_ADDRESS];
    }

    if (addrattr == NULL) {
        /* not a useful update */
        return 0;
    }

    network_interface *ni = find_by_ifindex(iai->ifa_index);
    if(ni == NULL) {
        /*
         * might work if we have a name to go with it, but we will
         * not create it for now.
         */
        deb->warn("Not creating new interface index=%d\n", iai->ifa_index);
        return 0;
    }

    const unsigned char *addr = NULL;
    unsigned int addrlen = 0;

    switch(iai->ifa_family) {
    case AF_INET6:
        addr = (unsigned char *)RTA_DATA(addrattr);
        if(addr) {
            addrlen = RTA_PAYLOAD(addrattr);
            if(addrlen > sizeof(ni->if_addr)) addrlen=sizeof(ni->if_addr);

            memcpy(&ni->if_addr, addr, addrlen);
        }

        inet_ntop(AF_INET6, addr, b1, sizeof(b1));

        //ni->node = new rpl_node(ni->if_addr);
        //ni->node->debug = deb;

        /* log it for human */
        deb->log("found[%d]: %s address=%s\n",
                 ni->if_index, ni->if_name, b1);
        break;

    default:
        break;
    }

    return 0;
}

int network_interface::adddel_linkinfo(const struct sockaddr_nl *who,
                                       struct nlmsghdr *n, void *arg)
{
    struct network_interface_init *nii = (struct network_interface_init *)arg;
    netprog_debug *deb = nii->debug;
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(n);
    FILE *fp = stdout;
    struct rtattr * tb[IFLA_MAX+1];
    int len = n->nlmsg_len;
    unsigned m_flag = 0;
    SPRINT_BUF(b1);

    len -= NLMSG_LENGTH(sizeof(*ifi));
    if (len < 0)
        return -1;

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
    if (tb[IFLA_IFNAME] == NULL) {
        fprintf(stderr, "BUG: nil ifname\n");
        return -1;
    }

    network_interface *ni = find_by_ifindex(ifi->ifi_index);
    if(ni == NULL) {
        ni = iface_maker->newnetwork_interface((const char*)RTA_DATA(tb[IFLA_IFNAME]), deb);
        ni->if_index = ifi->ifi_index;
        ni->set_debug(deb);
    }

    /* log it for human */
    deb->log("found[%d]: %s type=%s (%s %s)%s\n",
             ni->if_index, ni->get_if_name(),
             ll_type_n2a(ifi->ifi_type, b1, sizeof(b1)),
             ni->alive   ? "active" : "inactive",
             ni->on_list ? "existing" :"new",
             ni->faked() ? " faked" : "");

    ni->add_to_list();

    /* dummy0 interface is always changing */
    if(strcasecmp(ni->if_name, "dummy0")==0) {
        return 0;
    }

    const unsigned char *addr = NULL;
    unsigned int addrlen = 0;

    switch(ifi->ifi_type) {
    case ARPHRD_ETHER:
        addr = (unsigned char *)RTA_DATA(tb[IFLA_ADDRESS]);
        if(addr) {
            addrlen = RTA_PAYLOAD(tb[IFLA_ADDRESS]);
            if(memcpy(ni->eui48, addr, addrlen)==0) {
                /* no change, go on to next interface */
                return 0;
            }
            break;
        }

    case ARPHRD_LOOPBACK:
        loopback_interface = ni;
        ni->loopback = true;
        return 0;

    default:
        deb->log("   ignoring address type: %d\n", ifi->ifi_type);
        return 0;
    }

    if (tb[IFLA_MTU]) {
        ni->if_maxmtu =  *(int*)RTA_DATA(tb[IFLA_MTU]);
    }

    /* must be a new mac address */
    memcpy(ni->eui48, addr, addrlen);

    /* now build eui64 from eui48 */
    ni->generate_eui64();

    SPRINT_BUF(b2);
    deb->log("   adding as new interface %s/%s\n",
             ni->eui48_str(b1,sizeof(b1)),
             ni->eui64_str(b2,sizeof(b2)));

    return 0;
}


bool network_interface::open_netlink()
{
    if(netlink_handle == NULL) {
        netlink_handle = (struct rtnl_handle*)malloc(sizeof(struct rtnl_handle));
        if(netlink_handle == NULL) {
            return false;
        }

        if(rtnl_open(netlink_handle, 0) < 0) {
            fprintf(stderr, "Cannot open rtnetlink!!\n");
            free(netlink_handle);
            netlink_handle = NULL;
            return false;
        }
    }
    return true;
}


void network_interface::scan_devices(netprog_debug *deb, bool setup)
{
	struct nlmsg_list *linfo = NULL;
	struct nlmsg_list *ainfo = NULL;
	struct nlmsg_list *l, *n;
	char *filter_dev = NULL;
	int no_link = 0;
        struct network_interface_init nii;

        if(!open_netlink()) return;

        remove_marks();

        nii.debug = deb;
        nii.setup = setup;

        /* get list of interfaces */
	if (rtnl_wilddump_request(netlink_handle, AF_PACKET, RTM_GETLINK) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(netlink_handle, gather_linkinfo,
                             (void *)&nii, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

        /* get list of addresses on the interfaces */
	if (rtnl_wilddump_request(netlink_handle, AF_INET6, RTM_GETADDR) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(netlink_handle, gather_linkinfo,
                             (void *)&nii, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

        /* now look for interfaces with no mark, as they may be removed */

}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: whitesmith
 * End:
 */
