#ifndef CLICK_BSDIP6LOOKUP_HH
#define CLICK_BSDIP6LOOKUP_HH
#include <click/element.hh>
#include <click/ip6address.hh>
#include "ip6routetable.hh"
#include "../ip/bsdiplookup.hh"

CLICK_DECLS

/*
=c

BSDIP6Lookup(ADDR1/MASK1 [GW1] OUT1, ADDR2/MASK2 [GW2] OUT2, ...)

=s ip6route

IPv6 routing lookup using a variant of PATRICIA trie

=d

Expects a destination IPv6 address annotation with each packet. Looks up that
address in its routing table, using longest-prefix-match, sets the destination
annotation to the corresponding GW (if specified), and emits the packet on the
indicated OUTput port.

Each argument is a route, specifying a destination and mask, an optional
gateway IP address, and an output port.  No destination-mask pair may
occur more than once.

BSDIP6Lookup is optimized for fast database updates, while longest-prefix
lookups are accomplished in at most O(W) time, where W is the width
of the search key.  The implementation is based on the historic
I<PATRICIA trie> lookup scheme borrowed from FreeBSD, described by Keith
Sklower in the paper cited below.

=h table read-only

Outputs a human-readable version of the current routing table.

=h lookup read-only

Reports the OUTput port and GW corresponding to an address.

=h add write-only

Adds a route to the table.  Format should be `C<ADDR/MASK [GW] OUT>'.
Fails if a route for C<ADDR/MASK> already exists.

=h remove write-only

Removes a route from the table.  Format should be `C<ADDR/MASK>'.

=h flush write-only

Clears the entire routing table in a single atomic operation.

=h status read-only

Outputs human-readable report on current database state.

=e

rt :: BSDIP6Lookup(
	10::/128 ::0 0,
	10:20::/128 ::0 0,
	10::/30 ::0 1,
	10:20::/30 ::0 2,
	0::ff:0:0/96 ::0 3,
	::0/0 10::2 1
);

... -> GetIP6Address(24) -> rt;

rt[0] -> ...
rt[1] -> ...

=a BSDIPLookup, LookupIP6Route

Keith Sklower.  "A tree-based packet routing table for Berkeley UNIX".
In Proc. USENIX Winter 1991 Technical Conference, pp. 93-104.

*/


struct nexthop6 {
	IP6Address	gw;
	int32_t		port;
	int32_t		refcount;
	int16_t		ll_next;
	int16_t		ll_prev;
};


class BSDIP6Lookup : public IP6RouteTable {
    public:
	BSDIP6Lookup();
	~BSDIP6Lookup();

	const char *class_name() const	{ return "BSDIP6Lookup"; }
	const char *port_count() const	{ return "-/-"; }
	const char *processing() const	{ return PUSH; }

	int configure(Vector<String> &, ErrorHandler *);
	void add_handlers();

	int add_route(IP6Address, IP6Address, IP6Address, int, ErrorHandler *);
	int remove_route(IP6Address, IP6Address, ErrorHandler *);
	int lookup_route(IP6Address, IP6Address&) const;
	String dump_routes();

	/* Called from pure C, so needs to be public */
	void flush_walk(struct radix_node *);

    protected:
	int nexthop_ref(IP6Address, int);
	int nexthop_unref(int);
	void flush_table();
	static int flush_handler(const String &, Element *, void *,
	    ErrorHandler *);
	static int lookup_handler(int operation, String&, Element*,
	    const Handler*, ErrorHandler*);
	static String status_handler(Element *, void *);

	struct radix_node_head *_ip6_rnh;
	struct nexthop6 *_nexthop_tbl;
	int _prefix_cnt;
	int _nexthops;
	int _nexthop_tbl_size;
	int _nexthop_head;
	int _nexthop_empty_head;
};

CLICK_ENDDECLS
#endif
