/**
 * nft_set.c
 *
 * Functions for adding and deleting nft set elements
 *
 * Copyright (c) 2020 Untangle, Inc.
 * All Rights Reserved
 */

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <netinet/in.h>
#include <libnftnl/set.h>
#include <libmnl/libmnl.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

static char*	logsrc = "nft_set";

int manage_set_elem(uint16_t nft_msg_type, char *fam, char *table, char *set, uint32_t ctid, uint64_t timeout)
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct mnl_nlmsg_batch *batch;
	struct nlmsghdr *nlh;
	uint32_t portid, seq, family;
	struct nftnl_set *s;
	struct nftnl_set_elem *e;
	uint32_t data;
	int ret;

	s = nftnl_set_alloc();
	if (s == NULL) {
		logmessage(LOG_ERR,logsrc,"Could not allocate nftnl set\n");
		return EXIT_FAILURE;
	}

	seq = time(NULL);
	if (strcmp(fam, "ip") == 0)
		family = NFPROTO_IPV4;
	else if (strcmp(fam, "ip6") == 0)
		family = NFPROTO_IPV6;
	else if (strcmp(fam, "inet") == 0)
		family = NFPROTO_INET;
	else if (strcmp(fam, "bridge") == 0)
		family = NFPROTO_BRIDGE;
	else if (strcmp(fam, "arp") == 0)
		family = NFPROTO_ARP;
	else {
		logmessage(LOG_ERR,logsrc,"Unknown family: ip, ip6, inet, bridge, arp\n");
		nftnl_set_free(s);
		return EXIT_FAILURE;
	}

	nftnl_set_set_str(s, NFTNL_SET_TABLE, table);
	nftnl_set_set_str(s, NFTNL_SET_NAME, set);

	data = htonl(ctid);

	e = nftnl_set_elem_alloc();
	if (e == NULL) {
		logmessage(LOG_ERR,logsrc,"Could not allocate nftnl set elem\n");
		nftnl_set_free(s);
		return EXIT_FAILURE;
	}
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &data, sizeof(data));
	if(timeout > 0) {
		nftnl_set_elem_set_u64(e, NFTNL_SET_ELEM_TIMEOUT, timeout);
	}
	nftnl_set_elem_add(s, e);

	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				    nft_msg_type, family,
				    NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
				    seq++);
	nftnl_set_elems_nlmsg_build_payload(nlh, s);
	nftnl_set_free(s);
	mnl_nlmsg_batch_next(batch);

	nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
	mnl_nlmsg_batch_next(batch);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		logmessage(LOG_ERR,logsrc,"Could not open mnl socket\n");
		return EXIT_FAILURE;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		logmessage(LOG_ERR,logsrc,"Could bind mnl socket\n");
		mnl_socket_close(nl);
		return EXIT_FAILURE;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
			      mnl_nlmsg_batch_size(batch)) < 0) {
		logmessage(LOG_ERR,logsrc,"Could send on mnl socket\n");
		mnl_socket_close(nl);
		return EXIT_FAILURE;
	}

	mnl_nlmsg_batch_stop(batch);

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, NULL, NULL);
		if (ret <= 0) 
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	mnl_socket_close(nl);
	if (ret == -1 && errno != EEXIST) {
		logmessage(LOG_ERR,logsrc,"Could not run mnl callback: %d ctid %u - %s, %s, %s %u\n", errno, ctid, fam, table, set, portid);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int del_set_elem(char *fam, char *table, char *set, uint32_t ctid)
{
	return manage_set_elem(NFT_MSG_DELSETELEM, fam, table, set, ctid, 0);
}

int add_set_elem(char *fam, char *table, char *set, uint32_t ctid, uint64_t timeout)
{
	return manage_set_elem(NFT_MSG_NEWSETELEM, fam, table, set, ctid, timeout);
}

void bypass_via_nft_set(uint32_t ctid, uint64_t timeout)
{
	add_set_elem("inet", "packetd", "bypass_packetd", ctid, timeout);
}

void remove_bypass_entry(uint32_t ctid)
{
	del_set_elem("inet", "packetd", "bypass_packetd", ctid);
}
