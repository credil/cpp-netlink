#ifndef _UNSTRUNG_IFACE_H_
#define _UNSTRUNG_IFACE_H_

#include <map>

extern "C" {
#include <errno.h>
#include <signal.h>
#include <pathnames.h>		/* for PATH_PROC_NET_IF_INET6 */
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <sys/time.h>
#include <netinet/icmp6.h>
#include <linux/if.h>             /* for IFNAMSIZ */
}

#define HWADDR_MAX 16
#include "rfc6204d.h"
#include "debug.h"

extern const uint8_t all_hosts_addr[];
extern const uint8_t all_rpl_addr[];

enum network_interface_exceptions {
    TOOSHORT = 1,
};

/* used in network_interface::gather_linkinfo() */
struct network_interface_init {
    netprog_debug *debug;
    bool           setup;
};

class network_interface {

public:
    bool mark;

    int announce_network();
    network_interface(void);
    network_interface(int fd);
    network_interface(const char *if_name, netprog_debug *deb);

    // setup the object, open sockets, etc.
    bool setup(void);

    int errors(void) {
        return error_cnt;
    }

    bool is_active() { return alive; };

    void set_debug(class netprog_debug *deb) {
        debug = deb;
    }

    virtual void receive_packet(struct in6_addr ip6_src,
                                struct in6_addr ip6_dst,
                                time_t          now,
                                const u_char *bytes, const int len);

    virtual void send_raw_icmp(struct in6_addr *dest,
                               const unsigned char *icmp_body,
                               const unsigned int icmp_len);
    virtual bool faked(void);

    void        set_if_name(const char *ifname);
    const char *get_if_name(void) { return if_name; };
    int         get_if_index(void);

    /* eui string functions */
    char *eui48_str(char *str, int strlen);
    char *eui64_str(char *str, int strlen);

    static void scan_devices(netprog_debug *deb, bool setup);
    static void main_loop(netprog_debug *debug);
    static network_interface *find_by_ifindex(int ifindex);
    static network_interface *find_by_name(const char *name);
    static int foreach_if(int (*func)(network_interface*, void*), void*arg);
    static void remove_marks(void);
    static bool force_next_event(void);
    static void terminating(void);
    static void clear_events(void);

    struct in6_addr         link_local(void) {
        if(!eui64set) generate_eui64();
        return ipv6_link_addr;
    };

    /* event lists */
    //static class rpl_event_queue   things_to_do;

    static bool                    signal_usr2;
    static bool                    terminating_soon;
    static void                    catch_signal_usr2(int, siginfo_t *, void*);
    static bool                    faked_time;
    static struct timeval          fake_time;
    void set_fake_time(struct timeval n) {
	faked_time = true;
	fake_time  = n;
	//rpl_event::set_fake_time(fake_time);
    };

    struct in6_addr         if_addr;
    bool                    loopbackP() { return loopback; };

protected:
    static int    gather_linkinfo(const struct sockaddr_nl *who,
                                  struct nlmsghdr *n, void *arg);

    static int    adddel_linkinfo(const struct sockaddr_nl *who,
                                  struct nlmsghdr *n, void *arg);
    static int    adddel_ipinfo(const struct sockaddr_nl *who,
                                struct nlmsghdr *n, void *arg);

    /* debugging */
    netprog_debug              *debug;
    int                     if_index;      /* cached value for get_if_index()*/
    bool                    alive;
    bool                    loopback;

    /* maintain list of all interfaces */
    void add_to_list(void);

    unsigned short csum_ipv6_magic(
        const struct in6_addr *saddr,
        const struct in6_addr *daddr,
        __u32 len, unsigned short proto,
        unsigned sum);
    unsigned short csum_partial(
        const unsigned char *buff,
        int len, unsigned sum);

private:
    int packet_too_short(const char *thing, const int avail, const int needed);
    int                     nd_socket;
    int                     dhc_socket;
    int                     error_cnt;

    char                    if_name[IFNAMSIZ];
    int			    if_prefix_len;

    uint8_t		    if_hwaddr[HWADDR_MAX];
    int			    if_hwaddr_len;
    int			    if_maxmtu;

    /* list states */
    bool                    on_list;

    /* timers */
    time_t		    last_multicast_sec;
    suseconds_t		    last_multicast_usec;

    unsigned char          *control_msg_hdr;
    unsigned int            control_msg_hdrlen;

    /* read from our network socket and process result */
    void receive(time_t now);

    /* private helper functions */
    void setup_allrouters_membership(void);
    void setup_alldhc_membership(void);
    void check_allrouters_membership(void);

    unsigned char           optbuff[256];
    unsigned int            optlen;

    /* interface to netlink */
    void                    generate_eui64();
    bool                    eui64set;
    unsigned char           eui48[6];
    unsigned char           eui64[8];
    struct in6_addr         ipv6_link_addr;

    class network_interface        *next;

    /* this is global to all the interfaces */
    static class network_interface *all_if;
    static int                      if_count(void);

    static struct rtnl_handle      *netlink_handle;
    static bool                     open_netlink(void);

};

extern class network_interface *loopback_interface;

class iface_factory {
public:
    virtual network_interface *newnetwork_interface(const char *name, netprog_debug *deb);
};
extern class iface_factory *iface_maker;


#endif /* _UNSTRUNG_IFACE_H_ */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: whitesmith
 * End:
 */

