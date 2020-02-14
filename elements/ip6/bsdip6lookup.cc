/*
 * bsdip6lookup.{cc,hh} -- looks up next-hop address in radix table
 * Marko Zec (Click glue), Keith Sklower (original BSD radix tree code)
 *
 * Copyright (c) 2014 University of Zagreb
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/error.hh>
#include "bsdip6lookup.hh"

CLICK_DECLS


BSDIP6Lookup::BSDIP6Lookup()
	: _ip6_rnh(NULL), _prefix_cnt(0), _nexthops(0)
{

	rn_init(sizeof(struct sockaddr_ip6));
	rn_inithead((void **)(void *) &_ip6_rnh,
	    offsetof(struct sockaddr_ip6, sac_addr) * 8);
	_nexthop_tbl = (struct nexthop6 *)
	    CLICK_LALLOC(sizeof(*_nexthop_tbl) * VPORTS_MAX);
	assert(_nexthop_tbl != NULL);
	_nexthop_tbl_size = 1;		/* First empty slot */
	_nexthop_head = -1;		/* No allocated nexthops */
	_nexthop_empty_head = -1;	/* Recycle queue empty */

	/* _nexthop_tbl[0] is always used for default route */
	_nexthop_tbl[0].gw = IP6Address();
	_nexthop_tbl[0].port = -1;	/* Init default = discard */
	_nexthop_tbl[0].refcount = 0;	/* must never be referenced! */
}


BSDIP6Lookup::~BSDIP6Lookup()
{
	flush_table();
	CLICK_LFREE(_nexthop_tbl, sizeof(*_nexthop_tbl) * VPORTS_MAX);
}


void
BSDIP6Lookup::add_handlers()
{
	add_write_handler("add", add_route_handler, 0);
	add_write_handler("remove", remove_route_handler, 0);
	add_write_handler("ctrl", ctrl_handler, 0);
	add_read_handler("table", table_handler, 0);
	set_handler("lookup", Handler::OP_READ | Handler::READ_PARAM,
	    lookup_handler);
	add_write_handler("flush", flush_handler, 0, Handler::BUTTON);
	add_read_handler("status", status_handler, 0, Handler::BUTTON);
}


int
BSDIP6Lookup::configure(Vector<String> &conf, ErrorHandler *errh)
{
	assert(_prefix_cnt == 0);

	for (int i = 0; i < conf.size(); i++) {
		IP6Address dst, mask, gw;
		int port;
		bool ok = false;

		Vector<String> words;
		cp_spacevec(conf[i], words);

		if ((words.size()==2 || words.size()==3 )
		    && cp_ip6_prefix(words[0], (unsigned char *)&dst,
		    (unsigned char *)&mask, true, this)
		    && IntArg().parse(words.back(), port)) {
			if (words.size()==3)
				ok = cp_ip6_address(words[1],
				    (unsigned char *)&gw, this);
				else {
					gw = IP6Address();
					ok = true;
				}
		}
 
		if (ok && port >= 0)
			add_route(dst, mask, gw, port, errh);
		else
			errh->error("argument %d should be"
			    " DADDR/MASK [GW] OUTPUT", i + 1);
	}

	if (errh->nerrors())
		return (-1);
	return (0);
}


int
BSDIP6Lookup::lookup_handler(int, String& s, Element* e, const Handler*, ErrorHandler* errh)
{
	BSDIP6Lookup *table = static_cast<BSDIP6Lookup*>(e);
	IP6Address a;

	if (IP6AddressArg().parse(s, a, table)) {
		IP6Address gw;
		int port = table->lookup_route(a, gw);
		if (gw)
			s = String(port) + " " + gw.unparse();
		else
			s = String(port);
		return 0;
	} else
		return errh->error("expected IP6 address");
}


int
BSDIP6Lookup::add_route(IP6Address a, IP6Address m, IP6Address gw, int port, ErrorHandler *)
{
	struct rtentry6 *rt, *rt2;
	struct sockaddr_ip6 mask;

	R_Zalloc(rt, typeof(rt), sizeof(*rt));
	if (rt == NULL)
		return (-ENOMEM);

	/* Populate dst, mask */
	memset(&mask, 0, sizeof(mask));
	rt->dst.sac_len = mask.sac_len = sizeof(struct sockaddr_ip6);
	memcpy(rt->dst.sac_addr, a.data(), 16);
	memcpy(mask.sac_addr, m.data(), 16);

	/* Link dst, mask */
	rt_key(rt) = (struct sockaddr *) &rt->dst;
	rt_mask(rt) = (struct sockaddr *) &mask;

	/* Check for an existing route */
	rt2 = (struct rtentry6 *) _ip6_rnh->rnh_lookup(rt_key(rt),
	    rt_mask(rt), _ip6_rnh);
	if (rt2) {
		Free(rt);
		return (-EEXIST);
	}  else {
		rt2 = (struct rtentry6 *) _ip6_rnh->rnh_addaddr(rt_key(rt),
		    rt_mask(rt), _ip6_rnh, rt->rt_nodes);
		if (rt2 == NULL) {
			Free(rt);
			return (-ENOMEM);
		}
		/* Default route? */
		if (m.mask_to_prefix_len() == 0) {
			_nexthop_tbl[0].gw = gw;
			_nexthop_tbl[0].port = port;
		} else
			rt2->nh = nexthop_ref(gw, port);
		_prefix_cnt++;
	}
	return (0);
}


int
BSDIP6Lookup::remove_route(IP6Address a, IP6Address m, ErrorHandler *)
{
	struct rtentry6 rt, *rt2;
	struct sockaddr_ip6 mask;
  
	/* Populate dst, mask */
	memset(&mask, 0, sizeof(mask));
	rt.dst.sac_len = mask.sac_len = sizeof(struct sockaddr_ip6);
	memcpy(rt.dst.sac_addr, a.data(), 16);
	memcpy(mask.sac_addr, m.data(), 16);

	/* Link dst, mask */
	rt_key(&rt) = (struct sockaddr *) &rt.dst;
	rt_mask(&rt) = (struct sockaddr *) &mask;

	/* Check for an existing route */
	rt2 = (struct rtentry6 *) _ip6_rnh->rnh_lookup(rt_key(&rt),
	    rt_mask(&rt), _ip6_rnh);
	if (rt2 == NULL)
		return (-ENOENT);
	rt2 = (struct rtentry6 *) _ip6_rnh->rnh_deladdr(rt_key(&rt),
	    rt_mask(&rt), _ip6_rnh);
	assert(rt2 != NULL); /* No reason for a failure here! */
	Free(rt2);

	/* Default route? */
	if (m.mask_to_prefix_len() == 0) {
		_nexthop_tbl[0].gw = IP6Address();
		_nexthop_tbl[0].port = -1; /* discard */
	} else
		nexthop_unref(rt2->nh);
	_prefix_cnt--;
	return (0);
}


int
BSDIP6Lookup::lookup_route(IP6Address a, IP6Address &gw) const
{
	struct radix_node *rn;
	struct sockaddr_ip6 sac;
	struct rtentry6 *rt;
 
	sac.sac_len = sizeof(sac);
	memcpy(sac.sac_addr, a.data(), 16);
 
	rn = _ip6_rnh->rnh_matchaddr(&sac, _ip6_rnh);
	if (rn && ((rn->rn_flags & RNF_ROOT) == 0)) {
		rt = (struct rtentry6 *) rn;
		gw = NH2GW(rt->nh);
		return (NH2PORT(rt->nh));
	} else
		return (-1); /* Discard port */
}


struct dump_walk_arg {
	StringAccum sa;
	struct nexthop6 *nht;
};


static int
dump_walker(struct radix_node *rn, void *arg)
{
	struct rtentry6 *rt = (struct rtentry6 *) rn;
	struct dump_walk_arg *varg = (struct dump_walk_arg *) arg;
	IP6Address a, m;

	a = IP6Address((const unsigned char *) rt->dst.sac_addr);
	m = IP6Address((const unsigned char *)
	    ((struct sockaddr_ip6 *)rt_mask(rt))->sac_addr);
	varg->sa << a.unparse() << "/";
	varg->sa << m.mask_to_prefix_len() << "\t";
	varg->sa << varg->nht[rt->nh].gw.unparse() << "\t";
	varg->sa << varg->nht[rt->nh].port << "\n";
	return(0);
}


String
BSDIP6Lookup::dump_routes()
{
	struct dump_walk_arg varg;

	varg.nht = _nexthop_tbl;
	_ip6_rnh->rnh_walktree(_ip6_rnh, dump_walker, (void *) &varg);
	return (varg.sa.take_string());
}


int
BSDIP6Lookup::nexthop_ref(IP6Address gw, int port)
{
	int nh_i;

	/* Search for an existing entry */
	for (nh_i = _nexthop_head; nh_i >= 0; nh_i = _nexthop_tbl[nh_i].ll_next)
		if (gw == _nexthop_tbl[nh_i].gw &&
		    port == _nexthop_tbl[nh_i].port)
			break;

	if (nh_i >= 0)
		_nexthop_tbl[nh_i].refcount++;
	else {
		/* Create a new nexthop entry */
		if (_nexthop_empty_head >= 0) {
			nh_i = _nexthop_empty_head;
			_nexthop_empty_head = _nexthop_tbl[nh_i].ll_next;
		} else
			nh_i = _nexthop_tbl_size++;
		_nexthops++;

		_nexthop_tbl[nh_i].refcount = 1;
		_nexthop_tbl[nh_i].gw = gw;
		_nexthop_tbl[nh_i].port = port;

		/* Add the entry to the nexthop linked list */
		_nexthop_tbl[nh_i].ll_prev = -1;
		_nexthop_tbl[nh_i].ll_next = _nexthop_head;
		if (_nexthop_head >= 0)
			_nexthop_tbl[_nexthop_head].ll_prev = nh_i;
		_nexthop_head = nh_i;
	}
	return (nh_i);
}


int
BSDIP6Lookup::nexthop_unref(int nh_i)
{
	int refc, prev, next;

	if ((refc = --_nexthop_tbl[nh_i].refcount) == 0) {
		_nexthop_tbl[nh_i].port = -1;

		/* Prune our entry from the nexthop list */
		prev = _nexthop_tbl[nh_i].ll_prev;
		next = _nexthop_tbl[nh_i].ll_next;
		if (prev >= 0)
			_nexthop_tbl[prev].ll_next = next;
		else
			_nexthop_head = next;
		if (next >= 0)
			_nexthop_tbl[next].ll_prev = prev;

		/* Add the entry to empty nexthop list */
		_nexthop_tbl[nh_i].ll_next = _nexthop_empty_head;
		_nexthop_empty_head = nh_i;
		_nexthops--;
	}
	return (refc);
}


static int
flush_walk_trampoline(struct radix_node *rn, void *arg)
{
	BSDIP6Lookup *t = static_cast<BSDIP6Lookup *>(arg);

	t->flush_walk(rn);
	return (0);
}
 
  
void
BSDIP6Lookup::flush_walk(struct radix_node *rn)
{
	struct rtentry6 *rt = (struct rtentry6 *) rn;
	struct rtentry6 *rt2;
 
	rt2 = (struct rtentry6 *) _ip6_rnh->rnh_deladdr(rt_key(rt),
	    rt_mask(rt), _ip6_rnh);
	assert(rt2 == rt);
 
	/* Default route? */
	if (rt->nh == 0) {
		_nexthop_tbl[0].gw = IP6Address();
		_nexthop_tbl[0].port = -1; /* discard */
	} else
		nexthop_unref(rt->nh);
	Free(rt);
	_prefix_cnt--;
}


void
BSDIP6Lookup::flush_table()
{

	_ip6_rnh->rnh_walktree(_ip6_rnh, flush_walk_trampoline, (void *) this);
	assert(_nexthop_head == -1); /* No allocated nexthops */
}


int
BSDIP6Lookup::flush_handler(const String &, Element *e, void *, ErrorHandler *)
{
	BSDIP6Lookup *t = static_cast<BSDIP6Lookup *>(e);

	t->flush_table();
	return (0);
}

String
BSDIP6Lookup::status_handler(Element *e, void *)
{
	BSDIP6Lookup *t = static_cast<BSDIP6Lookup *>(e);
	StringAccum sa;

	sa << t->class_name() << ": ";
	sa << t->_prefix_cnt << " prefixes, ";
	sa << t->_nexthops << " unique nexthops\n";
	return (sa.take_string());
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(IP6RouteTable)
ELEMENT_REQUIRES(BSDIPLookup)
EXPORT_ELEMENT(BSDIP6Lookup)
