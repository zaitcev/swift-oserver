#ifndef __OSERVER_H__
#define __OSERVER_H__

/*
 * Copyright 2008-2009,2013 Red Hat, Inc.
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

#include <stdbool.h>
#include <glib.h>
#include <event2/event.h>
#include <openssl/md5.h>
#include <hstor.h>

#include "elist.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define TAG "oserver"

#define CLI_REQ_BUF_SZ    8192		/* buffer for req + hdrs */
#define CLI_DATA_BUF_SZ  65536

enum errcode {
	RedirectClient,
	AccessDenied,
	BucketAlreadyExists,
	BucketNotEmpty,
	InternalError,
	InvalidArgument,
	InvalidBucketName,
	InvalidURI,
	MissingContentLength,
	NoSuchFile,
	NoSuchRes,
	PreconditionFailed,
	SignatureDoesNotMatch,
};

struct param {
	const char *conf_name, *sconf_name;
	bool use_syslog;
	char *hash_suffix, *hash_prefix;
	char *host;
	char *port;			/* bind port */
	char *port_file;
	char *status_port;		/* status webserver */
	char *node_dir;			/* "/srv/node" */
};

struct resource {
	int res_type;
	char *res_path;
	char *datadir;
	int fd;
};

struct client;

/* internal client socket state */
enum client_state {
	evt_read_req,				/* read request line */
	evt_parse_req,				/* parse request line */
	evt_read_hdr,				/* read header line */
	evt_parse_hdr,				/* parse header line */
	evt_http_req,				/* HTTP request fully rx'd */
	evt_http_data_in,			/* HTTP request's content */
	evt_dispose,				/* dispose of client */
	evt_recycle,				/* restart HTTP request parse */
};

typedef bool (*cli_evt_func)(struct client *, unsigned int);
typedef bool (*cli_write_func)(struct client *, void *, bool);

struct client_write {
	const void		*buf;		/* write buffer pointer */
	int			togo;		/* write buffer remainder */

	int			length;		/* length for accounting */
	cli_write_func		cb;		/* callback */
	void			*cb_data;	/* data passed to cb */
	struct client		*cb_cli;	/* cli passed to cb */

	struct list_head	node;
};

struct client {
	enum client_state	state;		/* socket state */
	cli_evt_func		*evt_table;
	const struct param	*par;

	struct sockaddr_in6	addr;		/* inet address */
	char			addr_host[64];	/* ASCII version of inet addr */
	int			fd;		/* socket */
	bool			ev_active;
	struct event		*tcp_ev;
	struct event		*wr_ev;

	struct list_head	write_q;	/* list of async writes */
	size_t			write_cnt;	/* water level */
	bool			writing;
	/* some debugging stats */
	size_t			write_cnt_max;

	unsigned int		req_used;	/* amount of req_buf in use */
	char			*req_ptr;	/* start of unexamined data */

	char			*hdr_start;	/* current hdr start */
	char			*hdr_end;	/* current hdr end (so far) */

	struct resource		*res;
	unsigned long		in_len;

	// struct list_head	out_ch;		/* open_chunk.link */
	char			*out_bucket;
	char			*out_key;
	char			*out_user;
	MD5_CTX			out_md5;
	long			out_len;
	uint64_t		out_size;
	// uint64_t		out_objid;
	char			*out_buf;
	size_t			out_bcnt;	/* used length of out_buf */
	int			out_nput;	/* number of users of out_buf */

	/* we put the big arrays and objects at the end... */

	struct http_req		req;		/* HTTP request */

	char			req_buf[CLI_REQ_BUF_SZ]; /* input buffer */
};

/* XXX .... see config.c */
struct listen_cfg {
	/* bool			encrypt; */
	/* char			*host; */
	char			*port;
	char			*port_file;
};

enum st_net {
	ST_NET_INIT, ST_NET_OPEN, ST_NET_LISTEN
};

struct server {
	unsigned long		flags;		/* SFL_xxx above */
	int			pid_fd;		/* fd of pid_file */
	GMutex			*bigmutex;
	// struct event_base	*evbase_main;
	// int			ev_pipe[2];
	// struct event		pevt;
	struct list_head	write_compl_q;	/* list of done writes */

	char			*ourhost;
	char			*ourport;

	// char			*pid_file;	/* PID file */

	GList			*sockets;	/* struct server_socket */
#if 0
	struct list_head	all_stor;	/* struct storage_node */
	int			num_stor;	/* number of storage_node's  */
	uint64_t		object_count;
#endif

	enum st_net		state_net;

	// struct server_stats	stats;		/* global statistics */
};


/* util.c */
extern size_t strlist_len(GList *l);
extern void __strlist_free(GList *l);
extern void strlist_free(GList *l);
extern void req_free(struct http_req *req);
extern int req_hdr_push(struct http_req *req, char *key, char *val);
extern char *req_hdr(struct http_req *req, const char *key);
extern GHashTable *req_query(struct http_req *req);
extern void applogerr(const char *prefix);
extern void strup(char *s);
extern int write_pid_file(const char *pid_fn);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern void md5str(const unsigned char *digest, char *outstr);
extern void req_sign(struct http_req *req, const char *bucket, const char *key,
	      char *b64hmac_out);

/* main.c */
extern int debugging;
extern struct server oserver;
// extern struct compiled_pat patterns[];
extern bool stat_status(struct client *cli, GList *content);
extern bool cli_err(struct client *cli, enum errcode code);
extern bool cli_err_write(struct client *cli, char *hdr, char *content);
extern bool cli_resp_xml(struct client *cli, int http_status, GList *content);
extern bool cli_resp_html(struct client *cli, int http_status, GList *content);
extern int cli_writeq(struct client *cli, const void *buf, unsigned int buflen,
		     cli_write_func cb, void *cb_data);
extern size_t cli_wqueued(struct client *cli);
extern bool cli_cb_free(struct client *cli, void *cb_data, bool done);
extern bool cli_write_start(struct client *cli);
extern bool cli_write_run_compl(void);
extern int cli_req_avail(struct client *cli);
extern void applog(int prio, const char *fmt, ...);
extern void cld_update_cb(void);
extern int stor_update_cb(void);
extern int tdb_slave_login_cb(int srcid);
extern void tdb_slave_disc_cb(void);
extern void tdb_conn_scrub_cb(void);
extern struct db_remote *tdb_find_remote_byname(const char *name);
extern struct db_remote *tdb_find_remote_byid(int id);

/* resource.c */
struct resource *res_open(const char *path, const struct param *par,
    enum errcode *errp);
void res_free(struct resource *res);
bool res_http_get(struct resource *res, struct client *cli, bool want_body);

/* status.c */
extern bool stat_evt_http_req(struct client *cli, unsigned int events);

/* config.c */
extern void read_config(struct param *p, const char *sconf, const char *conf);

#endif /* __OSERVER_H__ */
