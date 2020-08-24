/* ------------------------------------------------------------------------
 *
 * tipcc.c
 *
 * Short description: TIPC C binding API
 *
 * ------------------------------------------------------------------------
 *
 * Copyright (c) 2015, Ericsson Canada
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name of Ericsson Canada nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Version 0.9: Jon Maloy, 2015
 *
 * ------------------------------------------------------------------------
 */

#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/socket.h>
#include <linux/tipc.h>
#include "tipcc.h"

#ifndef TIPC_SERVICE_ADDR

#define tipc_socket_addr   tipc_portid
#define tipc_service_addr  tipc_name
#define tipc_service_range tipc_name_seq

#define TIPC_SERVICE_RANGE      1
#define TIPC_SERVICE_ADDR       2
#define TIPC_SOCKET_ADDR        3

#define TIPC_TOP_SRV		1
#endif

static uint32_t own_node = 0;
static uint32_t own_socket = 0;

static inline __u8 node2scope(uint32_t node)
{
	if (tipc_own_node() == node)
		return TIPC_NODE_SCOPE;
	else
		return TIPC_CLUSTER_SCOPE;
}

uint32_t tipc_own_socket(void)
{
	tipc_own_node();
	return own_socket;
}

uint32_t tipc_own_node(void)
{
	struct tipc_addr socket;
	int sd;

	if (own_node)
		return own_node;

	sd = tipc_socket(SOCK_RDM);
	if (tipc_sockaddr(sd, &socket) == 0) {
		own_socket = socket.instance;
		own_node = socket.node;
	}
	close(sd);
	return own_node;
}

int tipc_socket(int sk_type)
{
	return socket(AF_TIPC, sk_type, 0);
}

int tipc_sock_non_block(int sd)
{
	int flags;

	flags = fcntl(sd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	flags = O_NONBLOCK;
	if (fcntl(sd, F_SETFL, flags) < 0)
		return -1;
	return sd;
}

int tipc_sock_rejectable(int sd)
{
	int val = 0;

	return setsockopt(sd, SOL_TIPC, TIPC_DEST_DROPPABLE,
			  &val, sizeof(val));
}

int tipc_sock_importance(int sd, uint32_t priority)
{
	return setsockopt(sd, SOL_TIPC, TIPC_IMPORTANCE,
			  &priority, sizeof(priority));
}

int tipc_close(int sd)
{
	return close(sd);
}

int tipc_sockaddr(int sd, struct tipc_addr *addr)
{
	struct sockaddr_tipc saddr;
	socklen_t sz = sizeof(saddr);

	if (!addr)
		return -1;
	if (getsockname(sd, (struct sockaddr *)&saddr, &sz) < 0)
		return -1;
	addr->type = 0;
	addr->instance = saddr.addr.id.ref;
	addr->node = saddr.addr.id.node;
	return 0;
}

int tipc_bind(int sd, uint32_t type, uint32_t lower, uint32_t upper,
	      uint32_t scope)
{
	struct sockaddr_tipc addr = {
		.family                  = AF_TIPC,
		.addrtype                = TIPC_SERVICE_RANGE,
		.scope                   = node2scope(scope),
		.addr.nameseq.type       = type,
		.addr.nameseq.lower      = lower,
		.addr.nameseq.upper      = upper
	};
	printf("scope: %d\n", node2scope(scope));
	// if (scope && scope != tipc_own_node())
	// 	printf("own_node: %d\n", tipc_own_node());
	// 	return -1;
	return bind(sd, (struct sockaddr *)&addr, sizeof(addr));
}

int tipc_unbind(int sd, uint32_t type, uint32_t lower, uint32_t upper)

{
	struct sockaddr_tipc addr = {
		.family                  = AF_TIPC,
		.addrtype                = TIPC_SERVICE_RANGE,
		.scope                   = -1,
		.addr.nameseq.type       = type,
		.addr.nameseq.lower      = lower,
		.addr.nameseq.upper      = upper
	};
	return bind(sd, (struct sockaddr *)&addr, sizeof(addr));
}

int tipc_connect(int sd, const struct tipc_addr *dst)
{
	struct sockaddr_tipc addr;

	if (!dst)
		return -1;
	addr.family                  = AF_TIPC;
	addr.addrtype                = TIPC_SERVICE_ADDR;
	addr.addr.name.name.type     = dst->type;
	addr.addr.name.name.instance = dst->instance;
	addr.addr.name.domain        = dst->node;
	return connect(sd, (struct sockaddr*)&addr, sizeof(addr));
}

int tipc_listen(int sd, int backlog)
{
	return listen(sd, backlog);
}

int tipc_accept(int sd, struct tipc_addr *src)
{
	struct sockaddr_tipc addr;
	socklen_t addrlen = sizeof(addr);
	int rc;

	rc = accept(sd, (struct sockaddr *) &addr, &addrlen);
	if (src) {
		src->type = 0;
		src->instance = addr.addr.id.ref;
		src->node = addr.addr.id.node;
	}
	return rc;
}

int tipc_join(int sd, struct tipc_addr *memberid, bool events, bool loopback)
{
#ifdef TIPC_GROUP_JOIN
	uint32_t node = memberid->node;
	struct tipc_group_req mreq = {
		.type = memberid->type,
		.instance = memberid->instance,
		.scope = node2scope(node),
	};

	if (node && node != tipc_own_node())
		return -1;
	mreq.flags = loopback ? TIPC_GROUP_LOOPBACK : 0;
	mreq.flags |= events ? TIPC_GROUP_MEMBER_EVTS : 0;
	return setsockopt(sd, SOL_TIPC, TIPC_GROUP_JOIN, &mreq, sizeof(mreq));
#else
#warning "tipc_join() not supported by this kernel version"
	printf("tipc_join() not supported by kernel version this was built for\n");
	return -1;
#endif
}

int tipc_leave(int sd)
{
#ifdef TIPC_GROUP_LEAVE
	return setsockopt(sd, SOL_TIPC, TIPC_GROUP_LEAVE, NULL, 0);
#else
#warning "tipc_leave() not supported by this kernel version"
	printf("tipc_leave() not supported by kernel version this was built for\n");
	return -1;
#endif
}

int tipc_send(int sd, const void *msg, size_t msg_len)
{
	return send(sd, msg, msg_len, 0);
}

int tipc_sendmsg(int sd, const struct msghdr *msg)
{
	return sendmsg(sd, msg, 0);
}

int tipc_sendto(int sd, const void *msg, size_t msg_len,
		const struct tipc_addr *dst)
{
	struct sockaddr_tipc addr;

	if(!dst)
		return -1;

	addr.family = AF_TIPC;
	if (dst->type) {
		addr.addrtype = TIPC_SERVICE_ADDR;
		addr.addr.name.name.type = dst->type;
		addr.addr.name.name.instance = dst->instance;
		addr.addr.name.domain = dst->node;
	} else {
		addr.addrtype = TIPC_ADDR_ID;
		addr.addr.id.ref = dst->instance;
		addr.addr.id.node = dst->node;
	}
	return sendto(sd, msg, msg_len, 0,
		      (struct sockaddr*)&addr, sizeof(addr));
}

int tipc_mcast(int sd, const void *msg, size_t msg_len,
	       const struct tipc_addr *dst)
{
	struct sockaddr_tipc addr = {
		.family                  = AF_TIPC,
		.addrtype                = TIPC_ADDR_MCAST,
	};

	if(!dst) {
		return -1;
	}

	addr.scope = dst->scope;
	addr.addr.nameseq.type = dst->type;
	addr.addr.nameseq.lower = dst->instance;
	addr.addr.nameseq.upper = dst->node;

	return sendto(sd, msg, msg_len, 0,
		      (struct sockaddr*)&addr, sizeof(addr));
}

int tipc_recv(int sd, void *buf, size_t buf_len, bool waitall)
{
	int flags = waitall ? MSG_WAITALL : 0;

	return recv(sd, buf, buf_len, flags);

}

int tipc_recvfrom(int sd, void *buf, size_t len, struct tipc_addr *sockid,
		  struct tipc_addr *memberid, int *err)
{
	struct sockaddr_tipc addr[2];
	struct iovec iov = {buf, len};
	struct msghdr msg = {0, };
	struct cmsghdr *anc;
	char anc_space[CMSG_SPACE(8) + CMSG_SPACE(1024) + CMSG_SPACE(16)];
	int rc, _err = 0;

	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = (struct cmsghdr *)anc_space;
	msg.msg_controllen = sizeof(anc_space);

	rc = recvmsg(sd ,&msg ,0);
	if (rc < 0)
		return rc;

	/* Add source addresses */
	if (memberid) {
		if (msg.msg_namelen == sizeof(addr)) {
			memberid->type = addr[1].addr.name.name.type;
			memberid->instance = addr[1].addr.name.name.instance;
		} else {
			memberid->type = 0;
			memberid->instance = 0;
		}
		memberid->node = 0;
	}

	if (sockid) {
		sockid->type = 0;
		sockid->instance = addr[0].addr.id.ref;
		sockid->node = addr[0].addr.id.node;
	}
	if (err)
		*err = 0;

	/* Handle group member event */
	if (msg.msg_flags & MSG_OOB) {
		if (rc)
			return -1;
		if (!err)
			return 0;
		if (msg.msg_flags & MSG_EOR)
			*err = -1;
		else
			*err = 0;
		return 0;
	}

	anc = CMSG_FIRSTHDR(&msg);
	if (!anc || anc->cmsg_type != TIPC_ERRINFO)
		return rc;

	_err = *(int*)(CMSG_DATA(anc));
	rc = MIN(*(int*)(CMSG_DATA(anc) + 4), len);
	anc = CMSG_NXTHDR(&msg, anc);
	memcpy(buf, (char*)CMSG_DATA(anc), rc);
	anc = CMSG_NXTHDR(&msg, anc);
	tipc_sockaddr(sd, sockid);

	if (err)
		*err = _err;
	else if (_err)
		rc = 0;
	return rc;
}

int tipc_topsrv_conn(uint32_t node)
{
	int sd;
	struct tipc_addr srv = {TIPC_TOP_SRV, TIPC_TOP_SRV, node, TIPC_CLUSTER_SCOPE};

	sd = tipc_socket(SOCK_SEQPACKET);
	if (sd <= 0)
		return sd;
	if (tipc_connect(sd, &srv) < 0)
		tipc_close(sd);
	return sd;
}

int tipc_srv_subscr(int sd, uint32_t type, uint32_t lower,
		    uint32_t upper, bool all, int expire)
{
	struct tipc_subscr subscr;

	subscr.seq.type  = type;
	subscr.seq.lower = lower;
	subscr.seq.upper = upper;
	subscr.timeout   = expire < 0 ? TIPC_WAIT_FOREVER : expire;
	subscr.filter    = all ? TIPC_SUB_PORTS : TIPC_SUB_SERVICE;
	if (send(sd, &subscr, sizeof(subscr), 0) != sizeof(subscr))
		return -1;
	return 0;
}

int tipc_srv_evt(int sd, struct tipc_addr *srv, struct tipc_addr *id,
		 bool *available, bool *expired)
{
	struct tipc_event evt;

        if (recv(sd, &evt, sizeof(evt), 0) != sizeof(evt))
                return -1;
	if (evt.event == TIPC_SUBSCR_TIMEOUT) {
		if (expired)
			*expired = true;
		return 0;
	}
	if (srv) {
		srv->type = evt.s.seq.type;
		srv->instance = evt.found_lower;
		srv->node = evt.port.node;
	}
	if (id) {
		id->type = 0;
		id->instance = evt.port.ref;
		id->node = evt.port.node;
	}
	if (available)
		*available = (evt.event == TIPC_PUBLISHED);
	if (expired)
		*expired = false;
	return 0;
}

bool tipc_srv_wait(const struct tipc_addr *srv, int wait)
{
	uint32_t node = srv->node;
	struct tipc_addr addr;
	bool expired = false;
	bool up = false;
	int sd;

	sd = tipc_topsrv_conn(0);
	if (sd < 0)
		return false;
	if (tipc_srv_subscr(sd, srv->type, srv->instance,
			    srv->instance, false, wait))
		goto exit;

	while (!tipc_srv_evt(sd, &addr, 0, &up, &expired)) {
		if (expired)
			break;
		if (node && node != addr.node)
			continue;
		if (up)
			break;
	}
exit:
	close(sd);
	return up && !expired;
}

int tipc_neigh_subscr(uint32_t node)
{
	int sd;

	sd = tipc_topsrv_conn(node);
	if (sd <= 0)
		return -1;
	if (tipc_srv_subscr(sd, TIPC_CFG_SRV, 0, ~0, true, TIPC_WAIT_FOREVER))
		return -1;
	return sd;
}

int tipc_neigh_evt(int sd, uint32_t *neigh_node, bool *available)
{
	struct tipc_addr srv;
	int rc;

	rc = tipc_srv_evt(sd, &srv, 0, available, 0);
	if (neigh_node)
		*neigh_node = srv.instance;
	return rc;
}

int tipc_link_subscr(uint32_t node)
{
	int sd;

	sd = tipc_topsrv_conn(node);
	if (sd <= 0)
		return -1;
	if (tipc_srv_subscr(sd, TIPC_LINK_STATE, 0, ~0,
			    true, TIPC_WAIT_FOREVER))
		return -1;
	return sd;
}

int tipc_link_evt(int sd, uint32_t *neigh_node, bool *available,
	          int *local_bearerid, int *remote_bearerid)
{
	struct tipc_event evt;

        if (recv(sd, &evt, sizeof(evt), 0) != sizeof(evt))
                return -1;

	if (local_bearerid)
		*local_bearerid = evt.port.ref & 0xffff;
	if (remote_bearerid)
		*remote_bearerid = (evt.port.ref >> 16) & 0xffff;
	if (neigh_node)
		*neigh_node = evt.found_lower;
	if (available)
		*available = (evt.event == TIPC_PUBLISHED);
	return 0;
}

char* tipc_linkname(char *buf, size_t len, uint32_t peer, int bearerid)
{
	struct tipc_sioc_ln_req req = {peer, bearerid, {'\0'}};
	int sd, rc;

	buf[0] = 0;
	sd = tipc_socket(SOCK_RDM);
	if (sd <= 0)
		return buf;
	rc = ioctl(sd, SIOCGETLINKNAME, &req);
	if (rc < 0)
		return buf;
	strncpy(buf, req.linkname, len);
	buf[len] = 0;
	return buf;
}

char* tipc_ntoa(const struct tipc_addr *addr, char *buf, size_t len)
{
	if (addr->type)
		snprintf(buf, len, "%u:%u@%x",
			 addr->type, addr->instance, addr->node);
	else
		snprintf(buf, len, "0:%010u@%x",
			 addr->instance, addr->node);
	buf[len] = 0;
	return buf;
}

char* tipc_rtoa(uint32_t type, uint32_t lower, uint32_t upper,
		uint32_t node, char *buf, size_t len)
{
	snprintf(buf, len, "%u:%u:%u@%x", type, lower, upper, node);

	buf[len] = 0;
	return buf;
}
