/*
 * Copyright 2008-2010,2013 Red Hat, Inc.
 * Copyright 2013 Pete Zaitcev <zaitcev@yahoo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#define _GNU_SOURCE	/* asprintf etc. */

#include <sys/types.h>
#include <sys/socket.h>
#include <argp.h>
#include <fcntl.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <event2/event.h>
#include <glib.h>

#include "oserver.h"

#define CLI_MAX_WR_IOV  32			/* max iov per writev(2) */

// const char *argp_program_version = PACKAGE_VERSION;

struct server_socket {
	bool			is_status;
	int			fd;
	struct event		*ev;
};

static const char doc[] = TAG " - drop-in object server daemon";

static const char conf_default[] = "/etc/swift/oserver.conf";
static const char sconf_default[] = "/etc/swift/swft.conf";
static struct argp_option options[] = {
	{ "config", 'C', conf_default, 0,
	  "Configuration file" },
	{ "swift-config", 'c', sconf_default, 0,
	  "Swift configuration file" },
	{ "debug", 'd', NULL, 0,
	  "Enable debugging output" },
	{ "stderr", 'E', NULL, 0,
	  "Switch the log to standard error" },
	{ }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

/* XXX review codes */
static struct {
	const char	*code;
	int		status;
	const char	*msg;
} err_info[] = {
	[AccessDenied] =
	{ "AccessDenied", 403,
	  "Access denied" },

	[BucketAlreadyExists] =
	{ "BucketAlreadyExists", 409,
	  "The requested bucket name is not available" },

	[BucketNotEmpty] =
	{ "BucketNotEmpty", 409,
	  "The bucket you tried to delete is not empty" },

	[InternalError] =
	{ "InternalError", 500,
	  "We encountered an internal error. Please try again." },

	[InvalidArgument] =
	{ "InvalidArgument", 400,
	  "Invalid Argument" },

	[InvalidBucketName] =
	{ "InvalidBucketName", 400,
	  "The specified bucket is not valid" }, /* XXX remove */

	[InvalidURI] =
	{ "InvalidURI", 400,
	  "Could not parse the specified URI" },

	[MissingContentLength] =
	{ "MissingContentLength", 411,
	  "You must provide the Content-Length HTTP header" },

	[NoSuchFile] =
	{ "NoSuchFile", 404,
	  "The specified resource cannot be opened" },

	[NoSuchRes] =
	{ "NoSuchRes", 404,
	  "The resource you requested does not exist" },

	[PreconditionFailed] =
	{ "PreconditionFailed", 412,
	  "Precondition failed" },
};

static int net_open(void);
static int net_open_any(char **actual_port);
static int net_open_known(const char *portstr, bool is_status);
static int net_open_socket(int addr_fam, int sock_type, int sock_prot,
    int addr_len, void *addr_ptr, bool is_status);
static int net_write_port(const char *port_file,
    const char *host, const char *port);
static void net_listen_status(void);
static void net_listen_client(void);
static bool cli_evt_http_req(struct client *cli, unsigned int events);
static void tcp_cli_wr_event(int fd, short events, void *userdata);
static void tcp_cli_event(int fd, short events, void *userdata);
static void tcp_srv_event(int fd, short events, void *userdata);
static char *get_hostname(void);

static struct param par = {
	.conf_name = conf_default,
	.sconf_name = sconf_default,
	.use_syslog = true,
};
static bool server_running = true;
static struct event_base *evbase_main;
int debugging;
struct server oserver;

/* XXX link this to HUP as Swift does - but multiprocess... */
static void term_signal(int signo)
{
	server_running = false;
	event_base_loopbreak(evbase_main);
}

int main(int argc, char *argv[])
{
	error_t aprc;
	int rc;

	// INIT_LIST_HEAD(&oserver.all_stor);
	INIT_LIST_HEAD(&oserver.write_compl_q);

	/* isspace() and strcasecmp() consistency requires this */
	setlocale(LC_ALL, "C");

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, TAG ": argp_parse failed: %s\n",
		    strerror(aprc));
		return 1;
	}

	/*
	 * open applog (currently does not depend on command line, but still)
	 */
	if (par.use_syslog)
		openlog(TAG, LOG_PID, LOG_LOCAL3);
	if (debugging)
		applog(LOG_INFO, "Debug output enabled");

	/*
	 * now we can parse the configuration, errors to applog
	 */
	read_config(&par, par.sconf_name, par.conf_name);
	if (!par.host) {
		oserver.ourhost = get_hostname();
	} else {
		oserver.ourhost = par.host;
		if (debugging)
			applog(LOG_INFO, "Forcing local hostname to %s",
			    oserver.ourhost);
	}

	/*
	 * done configuring, start working
	 */
	evbase_main = event_base_new();

	if (par.status_port) {
		if (net_open_known(par.status_port, true) == 0)
			net_listen_status();
	}
	rc = net_open();
	if (rc)
		goto err_out_net;
	net_listen_client();

	/* XXX fork here */

	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);

	// applog(LOG_INFO, "initialized (%s)",
	//    (tabled_srv.flags & SFL_FOREGROUND)? "fg": "bg");
	applog(LOG_INFO, "initialized");

	while (server_running) {
		rc = event_base_dispatch(evbase_main);
		if (rc < 0) {
			applog(LOG_ERR, "error in event_base_dispatch");
			exit(1);
		}
		if (rc) {
			/* Internal error: did not register any events. */
			fprintf(stderr, TAG ": empty event_base_dispatch\n");
			exit(1);
		}
	}

	if (par.use_syslog)
		closelog();
	return 0;

	/* net_close(); */
err_out_net:
	return rc;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'C':
		/* Very unlikely that a config file starts with a dash, but */
		// if (arg[0] == '-') {
		// 	fprintf(stderr, "Option -C requires an argument\n");
		// 	argp_usage(state);
		// }
		par.conf_name = arg;
		break;
	case 'c':
		par.sconf_name = arg;
		break;
	case 'd':
		debugging = 1;
		break;
	case 'E':
		par.use_syslog = false;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int net_open(void)
{
	char *act_port;
	int rc;

	if (strcmp(par.port, "auto") == 0) {
		rc = net_open_any(&act_port);
		if (rc)
			return rc;
		rc = net_write_port(par.port_file, oserver.ourhost, act_port);
		if (rc) {
			free(act_port);
			return rc;
		}
		oserver.ourport = act_port;
	 } else {
		rc = net_open_known(par.port, false);
		if (rc)
			return rc;
		rc = net_write_port(par.port_file, oserver.ourhost, par.port);
		if (rc)
			return rc;
		oserver.ourport = strdup(par.port);
	}

	oserver.state_net = ST_NET_OPEN;	/* XXX state_net is unused */
	return 0;
}

static int net_open_any(char **actual_port)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int fd4, fd6;
	socklen_t addr_len;
	unsigned short port;
	int rc;

	port = 0;

	/* Thanks to Linux, IPv6 must be bound first. */
	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	memcpy(&addr6.sin6_addr, &in6addr_any, sizeof(struct in6_addr));
	fd6 = net_open_socket(AF_INET6, SOCK_STREAM, 0, sizeof(addr6), &addr6,
			      false);

	if (fd6 >= 0) {
		addr_len = sizeof(addr6);
		if (getsockname(fd6, &addr6, &addr_len) != 0) {
			rc = errno;
			applog(LOG_ERR, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr6.sin6_port);
	}

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);
	/* If IPv6 worked, we must use the same port number for IPv4 */
	if (port)
		addr4.sin_port = htons(port);
	fd4 = net_open_socket(AF_INET, SOCK_STREAM, 0, sizeof(addr4), &addr4,
			      false);

	if (!port) {
		if (fd4 < 0)
			return fd4;

		addr_len = sizeof(addr4);
		if (getsockname(fd4, &addr4, &addr_len) != 0) {
			rc = errno;
			applog(LOG_ERR, "getsockname failed: %s", strerror(rc));
			return -rc;
		}
		port = ntohs(addr4.sin_port);
	}

	applog(LOG_INFO, "Listening on port %u", port);

	rc = asprintf(actual_port, "%u", port);
	if (rc < 0) {
		applog(LOG_ERR, "OOM");
		return -ENOMEM;
	}

	return 0;
}

static int net_open_known(const char *portstr, bool is_status)
{
	int ipv6_found;
	int rc;
	struct addrinfo hints, *res, *res0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, portstr, &hints, &res0);
	if (rc) {
		applog(LOG_ERR, "getaddrinfo(*:%s) failed: %s",
		       portstr, gai_strerror(rc));
		rc = -EINVAL;
		goto err_addr;
	}

	/*
	 * We rely on getaddrinfo to discover if the box supports IPv6.
	 * Much easier to sanitize its output than to try to figure what
	 * to put into ai_family.
	 *
	 * These acrobatics are required on Linux because we should bind
	 * to ::0 if we want to listen to both ::0 and 0.0.0.0. Else, we
	 * may bind to 0.0.0.0 by accident (depending on order getaddrinfo
	 * returns them), then bind(::0) fails and we only listen to IPv4.
	 */
	ipv6_found = 0;
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}

	for (res = res0; res; res = res->ai_next) {
		char listen_host[65], listen_serv[65];

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		rc = net_open_socket(res->ai_family, res->ai_socktype,
				     res->ai_protocol,
				     res->ai_addrlen, res->ai_addr, is_status);
		if (rc < 0)
			goto err_out;
		getnameinfo(res->ai_addr, res->ai_addrlen,
			    listen_host, sizeof(listen_host),
			    listen_serv, sizeof(listen_serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);

		applog(LOG_INFO, "Listening on %s port %s",
		       listen_host, listen_serv);
	}

	freeaddrinfo(res0);
	return 0;

err_out:
	freeaddrinfo(res0);
err_addr:
	return rc;
}

static int net_open_socket(int addr_fam, int sock_type, int sock_prot,
    int addr_len, void *addr_ptr, bool is_status)
{
	struct server_socket *sock;
	int fd, on;
	int rc;

	fd = socket(addr_fam, sock_type, sock_prot);
	if (fd < 0) {
		rc = errno;
		applogerr("tcp socket");
		return -rc;
	}

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		rc = errno;
		applogerr("setsockopt(SO_REUSEADDR)");
		close(fd);
		return -rc;
	}

	if (bind(fd, addr_ptr, addr_len) < 0) {
		rc = errno;
		applogerr("tcp bind");
		close(fd);
		return -rc;
	}

	rc = fsetflags("tcp server", fd, O_NONBLOCK);
	if (rc) {
		close(fd);
		return rc;
	}

	sock = calloc(1, sizeof(*sock));
	if (!sock)
		goto err_calloc;

	sock->fd = fd;
	sock->is_status = is_status;

	sock->ev = event_new(evbase_main, fd, EV_READ | EV_PERSIST,
	    tcp_srv_event, sock);
	if (!sock->ev)
		goto err_event;

	oserver.sockets = g_list_append(oserver.sockets, sock);
	return fd;

err_event:
	free(sock);
err_calloc:
	close(fd);
	return -ENOMEM;
}

static int net_write_port(const char *port_file,
    const char *host, const char *port)
{
	FILE *portf;
	int rc;

	if (!port_file)
		return 0;

	portf = fopen(port_file, "w");
	if (portf == NULL) {
		rc = errno;
		applog(LOG_INFO, "Cannot create port file %s: %s",
		       port_file, strerror(rc));
		return -rc;
	}
	if (fprintf(portf, "%s:%s\n", host, port) < 0) {
		rc = errno;
		fclose(portf);
		return -rc;
	}
	return fclose(portf) ? -errno : 0;
}

static void net_listen_status(void)
{
	GList *tmp;

	for (tmp = oserver.sockets; tmp; tmp = tmp->next) {
		struct server_socket *sock = tmp->data;

		if (!sock->is_status)
			continue;

		if (listen(sock->fd, 10) < 0) {
			applog(LOG_WARNING, "status socket listen: %s",
			       strerror(errno));
			continue;
		}

		if (event_add(sock->ev, NULL) < 0) {
			applog(LOG_WARNING, "status socket event_add error");
			/* FIXME: There is no unlisten other than close. */
			continue;
		}
	}
}

static void net_listen_client(void)
{
	GList *tmp;

	if (oserver.state_net != ST_NET_OPEN)
		return;

	for (tmp = oserver.sockets; tmp; tmp = tmp->next) {
		struct server_socket *sock = tmp->data;

		if (sock->is_status)
			continue;

		if (listen(sock->fd, 100) < 0) {
			if (debugging)
				applog(LOG_INFO, "client socket listen: %s",
				       strerror(errno));
			continue;
		}
		if (debugging)
			applog(LOG_INFO, "client socket listen ok");

		if (event_add(sock->ev, NULL) < 0) {
			applog(LOG_WARNING, "client socket event_add error");
			/* FIXME: There is no unlisten other than close. */
			continue;
		}
	}

	oserver.state_net = ST_NET_LISTEN;
}

bool stat_status(struct client *cli, GList *content)
{
#if 0
	struct db_remote *rp;
	GList *tmp;
#endif
	char *str;
#if 0
	int rc;
#endif

	/*
	 * The loadavg is system dependent, we'll figure it out later.
	 * On Linux, applications read from /proc/loadavg.
	 *
	 * The listening info duplicates the hostname until we split
	 * the replication identifier from hostname.
	 */
	if (asprintf(&str,
		     "<h1>Status</h1>"
		     "<p>Host %s port %s</p>\r\n",
		     oserver.ourhost, oserver.ourport) < 0)
		return false;
	content = g_list_append(content, str);

#if 0 /* XXX */
	if (tabled_srv.rep_remotes) {
		if (asprintf(&str, "<p>") < 0)
			return false;
		content = g_list_append(content, str);
		for (tmp = tabled_srv.rep_remotes; tmp; tmp = tmp->next) {
			rp = tmp->data;
			rc = asprintf(&str, "Peer: name %s dbid %d",
				      rp->name, rp->dbid);
			if (rc < 0)
				return false;
			content = g_list_append(content, str);
			if (rp->host) {
				rc = asprintf(&str, " host %s port %d",
					      rp->host, rp->port);
				if (rc < 0)
					return false;
				content = g_list_append(content, str);
			}
			if (rp == tabled_srv.rep_master) {
				str = strdup(" (master)");
				if (!str)
					return false;
				content = g_list_append(content, str);
			}
			rc = asprintf(&str, "<br />\r\n");
			if (rc < 0)
				return false;
			content = g_list_append(content, str);
		}
		if (asprintf(&str, "</p>\r\n") < 0)
			return false;
		content = g_list_append(content, str);
	}

	if (asprintf(&str,
		     "<p>Stats: "
		     "poll %lu event %lu tcp_accept %lu opt_write %lu</p>\r\n"
		     "<p>Debug: max_write_buf %lu</p>\r\n",
		     tabled_srv.stats.poll,
		     tabled_srv.stats.event,
		     tabled_srv.stats.tcp_accept,
		     tabled_srv.stats.opt_write,
		     tabled_srv.stats.max_write_buf) < 0)
		return false;
	content = g_list_append(content, str);
#endif
	return true;
}

static void cli_write_complete(struct client *cli, struct client_write *tmp)
{
	list_del(&tmp->node);
	list_add_tail(&tmp->node, &oserver.write_compl_q);
}

static bool cli_write_free(struct client_write *tmp, bool done)
{
	struct client *cli = tmp->cb_cli;
	bool rcb = false;

	cli->write_cnt -= tmp->length;
	list_del(&tmp->node);
	if (tmp->cb)
		rcb = tmp->cb(cli, tmp->cb_data, done);
	free(tmp);

	return rcb;
}

static void cli_write_free_all(struct client *cli)
{
	struct client_write *wr, *tmp;

	cli_write_run_compl();
	list_for_each_entry_safe(wr, tmp, &cli->write_q, node) {
		cli_write_free(wr, false);
	}
}

bool cli_write_run_compl(void)
{
	struct client_write *wr;
	bool do_loop;

	do_loop = false;
	while (!list_empty(&oserver.write_compl_q)) {
		wr = list_entry(oserver.write_compl_q.next,
				struct client_write, node);
		do_loop |= cli_write_free(wr, true);
	}
	return do_loop;
}

static void cli_free(struct client *cli)
{
	cli_write_free_all(cli);

	/* clean up network socket */
	if (cli->fd >= 0) {
		if (cli->ev_active && event_del(cli->tcp_ev) < 0)
			applog(LOG_WARNING, "TCP client event_del");
		event_free(cli->tcp_ev);
		if (cli->writing && event_del(cli->wr_ev) < 0)
			applog(LOG_WARNING, "write event_del");
		event_free(cli->wr_ev);
		close(cli->fd);
	}

	/* applog(LOG_INFO, "object-server %s - - [] \"%s %s\" %d %ld \"-\" \"txid\" \"-\" 0.0", cli->addr_host, method, path, status, (unsigned long)length); */
	applog(LOG_INFO,
	    "object-server %s - - [] \"%s %s\" %d %ld \"-\" \"txid\" \"-\" 0.0",
	    cli->addr_host, cli->req.method, cli->res->res_path,
	    0, (unsigned long)0);
	hreq_free(&cli->req);
	res_free(cli->res);

	// if (cli->write_cnt_max > oserver.stats.max_write_buf)
	// 	oserver.stats.max_write_buf = cli->write_cnt_max;

	if (debugging)
		applog(LOG_INFO, "client %s ended", cli->addr_host);

	free(cli);
}

static bool cli_evt_dispose(struct client *cli, unsigned int events)
{
	/* if write queue is not empty, we should continue to get
	 * poll callbacks here until it is
	 */
	if (list_empty(&cli->write_q))
		cli_free(cli);

	return false;
}

static bool cli_evt_recycle(struct client *cli, unsigned int events)
{
	unsigned int slop;

	applog(LOG_INFO,
	    "object-server %s - - [] \"%s %s\" %d %ld \"-\" \"txid\" \"-\" 0.0",
	    cli->addr_host, cli->req.method, cli->res->res_path,
	    0, (unsigned long)0);
	hreq_free(&cli->req);
	res_free(cli->res);  cli->res = NULL;

	cli->hdr_start = NULL;
	cli->hdr_end = NULL;

	slop = cli_req_avail(cli);
	if (slop) {
		memmove(cli->req_buf, cli->req_ptr, slop);
		cli->req_used = slop;

		cli->state = evt_parse_hdr;
	} else {
		cli->req_used = 0;

		cli->state = evt_read_req;
	}
	cli->req_ptr = cli->req_buf;

	memset(&cli->req, 0, sizeof(cli->req));

	return true;
}

static void cli_writable(struct client *cli)
{
	int n_iov;
	struct client_write *tmp;
	ssize_t rc;
	struct iovec iov[CLI_MAX_WR_IOV];

	/* accumulate pending writes into iovec */
	n_iov = 0;
	list_for_each_entry(tmp, &cli->write_q, node) {
		if (n_iov == CLI_MAX_WR_IOV)
			break;
		/* bleh, struct iovec should declare iov_base const */
		iov[n_iov].iov_base = (void *) tmp->buf;
		iov[n_iov].iov_len = tmp->togo;
		n_iov++;
	}

	/* execute non-blocking write */
do_write:
	rc = writev(cli->fd, iov, n_iov);
	if (rc < 0) {
		if (errno == EINTR)
			goto do_write;
		if (errno != EAGAIN)
			goto err_out;
		return;
	}

	/* iterate through write queue, issuing completions based on
	 * amount of data written
	 */
	while (rc > 0) {
		int sz;

		/* get pointer to first record on list */
		tmp = list_entry(cli->write_q.next, struct client_write, node);

		/* mark data consumed by decreasing tmp->len */
		sz = (tmp->togo < rc) ? tmp->togo : rc;
		tmp->togo -= sz;
		tmp->buf += sz;
		rc -= sz;

		/* if tmp->len reaches zero, write is complete,
		 * so schedule it for clean up (cannot call callback
		 * right away or an endless recursion will result)
		 */
		if (tmp->togo == 0)
			cli_write_complete(cli, tmp);
	}

	/* if we emptied the queue, clear write notification */
	if (list_empty(&cli->write_q)) {
		cli->writing = false;
		if (event_del(cli->wr_ev) < 0) {
			applog(LOG_WARNING, "cli_writable event_del");
			goto err_out;
		}
	}

	return;

err_out:
	cli->state = evt_dispose;
	cli_write_free_all(cli);
}

bool cli_write_start(struct client *cli)
{
	if (list_empty(&cli->write_q))
		return true;		/* loop, not poll */

	/* if write-poll already active, nothing further to do */
	if (cli->writing)
		return false;		/* poll wait */

	/* attempt optimistic write, in hopes of avoiding poll,
	 * or at least refill the write buffers so as to not
	 * get -immediately- called again by the kernel
	 */
	cli_writable(cli);
	if (list_empty(&cli->write_q)) {
		// tabled_srv.stats.opt_write++;
		return true;		/* loop, not poll */
	}

	if (event_add(cli->wr_ev, NULL) < 0) {
		applog(LOG_WARNING, "cli_write event_add");
		return true;		/* loop, not poll */
	}

	cli->writing = true;

	return false;			/* poll wait */
}

int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data)
{
	struct client_write *wr;

	if (!buf || !buflen)
		return -EINVAL;

	wr = calloc(1, sizeof(struct client_write));
	if (!wr)
		return -ENOMEM;

	wr->buf = buf;
	wr->togo = buflen;
	wr->length = buflen;
	wr->cb = cb;
	wr->cb_data = cb_data;
	wr->cb_cli = cli;
	list_add_tail(&wr->node, &cli->write_q);
	cli->write_cnt += buflen;
	if (cli->write_cnt > cli->write_cnt_max)
		cli->write_cnt_max = cli->write_cnt;

	return 0;
}

size_t cli_wqueued(struct client *cli)
{
	return cli->write_cnt;
}

/*
 * Return:
 *   0: progress was NOT made (EOF)
 *  >0: some data was gotten
 *  <0: an error happened (equals to system error * -1; includes -EAGAIN)
 */
static int cli_read(struct client *cli)
{
	ssize_t rc;

	/* read into remaining free space in buffer */
do_read:
	rc = read(cli->fd, cli->req_buf + cli->req_used,
		  CLI_REQ_BUF_SZ - cli->req_used);
	if (rc < 0) {
		if (errno == EINTR)
			goto do_read;
		return -errno;
	}

	cli->req_used += rc;

	/* if buffer is full, assume that data will continue
	 * to be received (by a malicious or broken client),
	 * so stop reading now and return an error.
	 *
	 * Therefore, it can be said that the maximum size of a
	 * request to this HTTP server is CLI_REQ_BUF_SZ-1.
	 */
	if (cli->req_used == CLI_REQ_BUF_SZ)
		return -ENOSPC;

	return rc != 0;
}

bool cli_cb_free(struct client *cli, void *cb_data, bool done)
{
	free(cb_data);
	return false;
}

static int cli_write_list(struct client *cli, GList *list)
{
	int rc = 0;
	GList *tmp;

	tmp = list;
	while (tmp) {
		rc = cli_writeq(cli, tmp->data, strlen(tmp->data),
			        cli_cb_free, tmp->data);
		if (rc)
			goto out;

		tmp->data = NULL;
		tmp = tmp->next;
	}

out:
	__strlist_free(list);
	return rc;
}

bool cli_err(struct client *cli, enum errcode code)
{
	int rc;
	char timestr[50], *hdr = NULL, *content = NULL;

	content = g_markup_printf_escaped(
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<Error>\r\n"
"  <Code>%s</Code>\r\n"
"  <Message>%s</Message>\r\n"
"</Error>\r\n",
		     err_info[code].code,
		     err_info[code].msg);
	if (!content)
		return false;

	rc = asprintf(&hdr,
		"HTTP/%d.%d %d x\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: %zu\r\n"
		"Date: %s\r\n"
		"Connection: close\r\n"
		"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     err_info[code].status,
		     strlen(content),
		     hutil_time2str(timestr, sizeof(timestr), time(NULL)));
	if (rc < 0) {
		free(content);
		return false;
	}

	return cli_err_write(cli, hdr, content);
}

bool cli_err_write(struct client *cli, char *hdr, char *content)
{
	int rc;

	cli->state = evt_dispose;

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc)
		return true;
	rc = cli_writeq(cli, content, strlen(content), cli_cb_free, content);
	if (rc)
		return true;

	return cli_write_start(cli);
}

static bool cli_resp(struct client *cli, int http_status,
		     const char *content_type, GList *content)
{
	int rc;
	char *hdr, timestr[50];
	bool rcb, cxn_close = !hreq_http11(&cli->req);

	if (asprintf(&hdr,
"HTTP/%d.%d %d x\r\n"
"Content-Type: %s\r\n"
"Content-Length: %zu\r\n"
"Date: %s\r\n"
"%s"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     http_status,
		     content_type,
		     strlist_len(content),
		     hutil_time2str(timestr, sizeof(timestr), time(NULL)),
		     cxn_close ? "Connection: close\r\n" : "") < 0) {
		__strlist_free(content);
		return false;
	}

	if (cxn_close)
		cli->state = evt_dispose;
	else
		cli->state = evt_recycle;

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		cli->state = evt_dispose;
		return true;
	}

	rc = cli_write_list(cli, content);
	if (rc) {
		cli->state = evt_dispose;
		return true;
	}

	rcb = cli_write_start(cli);

	if (cli->state == evt_recycle)
		return true;

	return rcb;
}

bool cli_resp_xml(struct client *cli, int http_status, GList *content)
{
	return cli_resp(cli, http_status, "application/xml", content);
}

bool cli_resp_html(struct client *cli, int http_status, GList *content)
{
	return cli_resp(cli, http_status, "text/html", content);
}

static bool cli_evt_http_req(struct client *cli, unsigned int events)
{
	struct http_req *req = &cli->req;
	char *host;
	// char *bucket = NULL;
	char *path = NULL;
	// char *user = NULL;
	// char *key = NULL;
	char *method = req->method;
	bool rcb;
	// bool buck_in_path = false;
	bool expect_cont = false;
	struct resource *res;
	enum errcode err;

	/* grab useful headers */
	host = hreq_hdr(req, "host");
	// content_len_str = hreq_hdr(req, "content-length");
	// auth = hreq_hdr(req, "authorization");
	if (req->major > 1 || req->minor > 0) {
		char *expect = hreq_hdr(req, "expect");
		if (expect && strcasestr(expect, "100-continue"))
			expect_cont = true;
	}

	if (!host)
		return cli_err(cli, InvalidArgument);

	path = g_strndup(req->uri.path, req->uri.path_len);

	if (!path)
		path = strdup("/");
	if (debugging)
		applog(LOG_INFO, "client %s method %s path %s",
		    cli->addr_host, method, path);

	res = res_open(path, &par, &err);
	if (!res) {
		rcb = cli_err(cli, err);
		goto out;
	}
	cli->res = res;

	/* no matter whether error or not, this is our next state.
	 * the main question is whether or not we will go immediately
	 * into it (return true) or wait for writes to complete (return false).
	 *
	 * the operations below may override this next-state setting, however.
	 */
	if (hreq_http11(req))
		cli->state = evt_recycle;
	else
		cli->state = evt_dispose;

	/*
	 * pre-operation checks
	 */
#if 0
	if (bucket && !bucket_valid(bucket))
		rcb = cli_err(cli, InvalidBucketName);
#endif

	/*
	 * the meat of method upon resources
	 */
	if (strcmp(method, "HEAD") == 0) {
		rcb = res_http_get(cli->res, cli, false);
	} else if (strcmp(method, "GET") == 0) {
		rcb = res_http_get(cli->res, cli, true);
	} else {
		if (debugging)
			applog(LOG_INFO, "method %s unknown", method);
		rcb = cli_err(cli, InvalidURI); /* wrong method, but meh */
	}

out:
	// free(bucket);
	free(path);
	// free(user);
	// free(key);
	return rcb;

#if 0
err_out:
	rcb = cli_err(cli, err);
	goto out;
#endif
}

int cli_req_avail(struct client *cli)
{
	int skip_len = cli->req_ptr - cli->req_buf;
	int search_len = cli->req_used - skip_len;

	return search_len;
}

static char *cli_req_eol(struct client *cli)
{
	/* find newline in unconsumed portion of buffer */
	return memchr(cli->req_ptr, '\n', cli_req_avail(cli));
}

static char *cli_req_line(struct client *cli)
{
	/* get start and end of line */
	char *buf_start = cli->req_ptr;
	char *buf_eol = cli_req_eol(cli);
	if (!buf_eol)
		return NULL;

	/* nul-terminate line, if found */
	*buf_eol = 0;
	cli->req_ptr = buf_eol + 1;

	/* chomp CR, if present */
	if (buf_eol != buf_start) {
		char *buf_cr = buf_eol - 1;
		if (*buf_cr == '\r')
			*buf_cr = 0;
	}

	/* return saved start-of-line */
	return buf_start;
}

static bool cli_hdr_flush(struct client *cli, bool *loop_state)
{
	char *tmp;
	enum errcode err_resp;

	if (!cli->hdr_start)
		return false;

	/* null terminate entire string (key+value) */
	*cli->hdr_end = 0;

	/* find end of key; ensure no whitespace in key */
	tmp = cli->hdr_start;
	while (*tmp) {
		if (isspace(*tmp)) {
			err_resp = InvalidArgument;
			goto err_out;
		}
		if (*tmp == ':')
			break;
		tmp++;
	}
	if (*tmp != ':') {
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* null terminate key */
	*tmp = 0;

	/* add to list of headers */
	if (hreq_hdr_push(&cli->req, cli->hdr_start, tmp + 1)) {
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* reset accumulation state */
	cli->hdr_start = NULL;
	cli->hdr_end = NULL;

	return false;

err_out:
	*loop_state = cli_err(cli, err_resp);
	return true;
}

static bool cli_evt_parse_hdr(struct client *cli, unsigned int events)
{
	char *buf, *buf_eol;
	bool eoh = false;

	/* get pointer to end-of-line */
	buf_eol = cli_req_eol(cli);
	if (!buf_eol) {
		cli->state = evt_read_hdr;
		return false;
	}

	/* mark data as consumed */
	buf = cli->req_ptr;
	cli->req_ptr = buf_eol + 1;

	/* convert newline into spaces, for continued header lines */
	*buf_eol = ' ';

	/* chomp CR, if present */
	if (buf_eol != buf) {
		char *buf_cr = buf_eol - 1;
		if (*buf_cr == '\r') {
			*buf_cr = ' ';
			buf_eol--;
		}
	}

	/* if beginning of line and buf_eol (beginning of \r\n) are
	 * the same, its a blank line, signalling end of headers
	 */
	if (buf == buf_eol)
		eoh = true;

	/* check need to flush accumulated header data */
	if (eoh || (!isspace(buf[0]))) {
		bool sent_resp, loop;

		sent_resp = cli_hdr_flush(cli, &loop);
		if (sent_resp)
			return loop;
	}

	/* if we have reached end of headers, deliver HTTP request */
	if (eoh) {
		cli->state = evt_http_req;
		return true;
	}

	/* otherwise, continue accumulating header data */
	if (!cli->hdr_start)
		cli->hdr_start = buf;
	cli->hdr_end = buf_eol;

	return true;
}

static bool cli_evt_read_hdr(struct client *cli, unsigned int events)
{
	int rc = cli_read(cli);
	if (rc <= 0) {
		if (rc == -ENOSPC)
			return cli_err(cli, InvalidArgument);
		if (rc == -EAGAIN)
			return false;

		cli->state = evt_dispose;
	} else
		cli->state = evt_parse_hdr;

	return true;
}

static bool cli_evt_parse_req(struct client *cli, unsigned int events)
{
	char *sp1, *sp2, *buf;
	enum errcode err_resp;

	/* get pointer to nul-terminated line received */
	buf = cli_req_line(cli);
	if (!buf) {
		cli->state = evt_read_req;
		return false;
	}

	/* locate the first and second spaces, additionally ensuring
	 * that the first and second tokens are non-empty
	 */
	if (*buf == ' ') {
		err_resp = InvalidArgument;
		goto err_out;
	}
	sp1 = strchr(buf, ' ');
	if ((!sp1) || (*(sp1 + 1) == ' ')) {
		err_resp = InvalidArgument;
		goto err_out;
	}
	sp2 = strchr(sp1 + 1, ' ');
	if (!sp2) {
		err_resp = InvalidArgument;
		goto err_out;
	}

	/* convert the two spaces to nuls, thereby creating three
	 * nul-terminated strings for the three pieces we desire
	 */
	*sp1 = 0;
	*sp2 = 0;

	/* method is the first token, at the beginning of the buffer */
	cli->req.method = buf;
	strup(cli->req.method);

	/* URI is the second token, immediately following the first space */
	if (!huri_parse(&cli->req.uri, sp1 + 1)) {
		err_resp = InvalidURI;
		goto err_out;
	}

	cli->req.orig_path = g_strndup(cli->req.uri.path, cli->req.uri.path_len);

	cli->req.uri.path_len = huri_field_unescape(cli->req.uri.path,
					       cli->req.uri.path_len);

	/* HTTP version is the final token, following second space */
	if ((sscanf(sp2 + 1, "HTTP/%d.%d", &cli->req.major, &cli->req.minor) != 2) ||
	    (cli->req.major != 1) || (cli->req.minor < 0) || (cli->req.minor > 1)) {
		err_resp = InvalidArgument;
		goto err_out;
	}

	cli->state = evt_parse_hdr;
	return true;

err_out:
	return cli_err(cli, err_resp);
}

static bool cli_evt_read_req(struct client *cli, unsigned int events)
{
	int rc = cli_read(cli);
	if (rc <= 0) {
		if (rc == -ENOSPC)
			return cli_err(cli, InvalidArgument);
		if (rc == -EAGAIN)
			return false;

		cli->state = evt_dispose;
	} else
		cli->state = evt_parse_req;

	return true;
}

static cli_evt_func evt_funcs_server[] = {
	[evt_read_req]		= cli_evt_read_req,
	[evt_parse_req]		= cli_evt_parse_req,
	[evt_read_hdr]		= cli_evt_read_hdr,
	[evt_parse_hdr]		= cli_evt_parse_hdr,
	[evt_http_req]		= cli_evt_http_req,
	// [evt_http_data_in]	= cli_evt_http_data_in,   XXX
	[evt_dispose]		= cli_evt_dispose,
	[evt_recycle]		= cli_evt_recycle,
};

static cli_evt_func evt_funcs_status[] = {
	[evt_read_req]		= cli_evt_read_req,
	[evt_parse_req]		= cli_evt_parse_req,
	[evt_read_hdr]		= cli_evt_read_hdr,
	[evt_parse_hdr]		= cli_evt_parse_hdr,
	[evt_http_req]		= stat_evt_http_req,
	// [evt_http_data_in]	= cli_evt_http_data_in,   XXX
	[evt_dispose]		= cli_evt_dispose,
	[evt_recycle]		= cli_evt_recycle,
};

static struct client *cli_alloc(bool is_status)
{
	struct client *cli;

	/* alloc and init client info */
	cli = calloc(1, sizeof(*cli));
	if (!cli) {
		applog(LOG_ERR, "out of memory");
		return NULL;
	}
	cli->par = &par;
	// INIT_LIST_HEAD(&cli->in_ce.evt_list);
	// INIT_LIST_HEAD(&cli->in_ce.buf_list);

	cli->state = evt_read_req;
	cli->evt_table = is_status? evt_funcs_status: evt_funcs_server;
	INIT_LIST_HEAD(&cli->write_q);
	// INIT_LIST_HEAD(&cli->out_ch);
	cli->req_ptr = cli->req_buf;
	memset(&cli->req, 0, sizeof(cli->req) - sizeof(cli->req.hdr));

	return cli;
}

static void tcp_cli_wr_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;

	cli_writable(cli);
	cli_write_run_compl();
}

static void tcp_cli_event(int fd, short events, void *userdata)
{
	struct client *cli = userdata;
	bool loop;

	do {
		loop = cli->evt_table[cli->state](cli, events);
		loop |= cli_write_run_compl();
	} while (loop);
}

static void tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	struct client *cli;
	char host[64];
	int on = 1;

	/* alloc and init client info */
	cli = cli_alloc(sock->is_status);
	if (!cli) {
		struct sockaddr_in6 a;
		int cli_fd = accept(sock->fd, (struct sockaddr *) &a, &addrlen);
		close(cli_fd);
		return;
	}

	/* receive TCP connection from kernel */
	cli->fd = accept(sock->fd, (struct sockaddr *) &cli->addr, &addrlen);
	if (cli->fd < 0) {
		applogerr("tcp accept");
		goto err_out;
	}

	// tabled_srv.stats.tcp_accept++;

	cli->tcp_ev = event_new(evbase_main, cli->fd, EV_READ | EV_PERSIST,
           tcp_cli_event, cli);
	if (!cli->tcp_ev) {
		applog(LOG_ERR, "event_new: no core");
		goto err_evnew_tcp;
	}
	cli->wr_ev = event_new(evbase_main, cli->fd, EV_WRITE | EV_PERSIST,
	   tcp_cli_wr_event, cli);
	if (!cli->wr_ev) {
		applog(LOG_ERR, "event_new: no core");
		goto err_evnew_wr;
	}

	/* mark non-blocking, for upcoming poll use */
	if (fsetflags("tcp client", cli->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	/* disable delay of small output packets */
	if (setsockopt(cli->fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		applog(LOG_WARNING, "TCP_NODELAY failed: %s",
		       strerror(errno));

	/* add to poll watchlist */
	if (event_add(cli->tcp_ev, NULL) < 0) {
		applog(LOG_WARNING, "tcp client event_add");
		goto err_out_set;
	}
	cli->ev_active = true;

	/* pretty-print incoming cxn info */
	memset(host, 0, sizeof(host));
	getnameinfo((struct sockaddr *) &cli->addr, addrlen,
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;
	if (debugging)
		applog(LOG_INFO, "client %s connected", host);
	strcpy(cli->addr_host, host);

	return;

err_out_set:
err_out_fd:
	event_free(cli->wr_ev);
err_evnew_wr:
	event_free(cli->tcp_ev);
err_evnew_tcp:
	close(cli->fd);
err_out:
	free(cli);
}


/*
 * Find out own hostname.
 * This is needed for:
 *  - announcing ourselves in CLD in case we're DB master
 *  - finding the local domain and its SRV records
 * Do this before our state machines start ticking, so we can quit with
 * a meaningful message easily.
 */
static char *get_hostname(void)
{
	enum { hostsz = 64 };
	char hostb[hostsz];
	char *ret;

	if (gethostname(hostb, hostsz-1) < 0) {
		applog(LOG_ERR, "get_hostname: gethostname error (%d): %s",
		       errno, strerror(errno));
		exit(1);
	}
	hostb[hostsz-1] = 0;
	if ((ret = strdup(hostb)) == NULL) {
		applog(LOG_ERR, "get_hostname: no core (%ld)",
		       (long)strlen(hostb));
		exit(1);
	}
	return ret;
}

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (par.use_syslog) {
		vsyslog(prio, fmt, ap);
	} else {
		char *f;
		int len;
		int pid;

		pid = getpid() & 0xFFFFFFFF;
		len = sizeof(TAG "[0123456789]: ") + strlen(fmt) + 2;
		f = alloca(len);
		sprintf(f, TAG "[%u]: %s\n", pid, fmt);
		vfprintf(stderr, f, ap);	/* atomic write to stderr */
	}
	va_end(ap);
}
