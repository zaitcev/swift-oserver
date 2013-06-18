/*
 * ??? XXX
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openssl/md5.h>

#include "oserver.h"

static void cli_in_end(struct client *cli);
static bool object_get_more(struct client *cli, void *cb_data, bool done);
/* static void object_get_event(struct open_chunk *ochunk); */
static bool object_get_poke(struct client *cli);
static ssize_t stor_get_buf(struct resource *res, void *buf, size_t len);
static char *make_open_path(const char *url_path, const struct param *par,
    enum errcode *errp);

struct str_sp {
	const char *ptr;
	int len;
};
static int str_split(struct str_sp *wvec, int wlen, const char *url_path,
    char sep);

/* XXX return errno so we throw a 500 for ENOMEM instead of 404. */
struct resource *res_open(const char *path, const struct param *par)
{
	struct resource *res;

	res = malloc(sizeof(struct resource));
	if (!res)
		goto err_alloc;
	memset(res, 0, sizeof(struct resource));
	res->fd = -1;

	/*
	 * For now, all resources are Swift objects. So, res_type==0.
	 */
	res->res_path = strdup(path);
	if (!res)
		goto err_path;

	return res;

err_path:
	free(res);
err_alloc:
	return NULL;
}

void res_free(struct resource *res)
{
	if (!res)
		return;
	if (res->fd != -1)
		close(res->fd);
	free(res->res_path);
	free(res);
}

static void cli_in_end(struct client *cli)
{
	struct resource *res;

	if (!cli)
		return;
	res = cli->res;
	if (res->fd != -1) {
		close(res->fd);
		res->fd = -1;
	}
	cli->in_len = 0;
}

/*
 * Uses the cli_xxx protocol for now: form the HTTP error and return the 
 * scheduling bool.
 */
bool res_http_get(struct resource *res, struct client *cli, bool want_body)
{
	enum errcode err = InternalError;
	char *md5;
	char *open_path;
	struct stat statb;
	off_t file_len;
	time_t file_mtime;
	char timestr[64], modstr[64], *hdr, *tmp;
	char buf[4096];		/* XXX malloc ahead and read disk_block_size */
	int rc;
	ssize_t bytes;

	/* XXX Maybe move opening into res_open, once it can return codes? */
	open_path = make_open_path(res->res_path, cli->par, &err);
	if (!open_path)
		goto err_open_path;

	/* if (debugging) */
		applog(LOG_INFO, "open_path %s", open_path);

#if 0 /* XXX implement this */
	if (deny_dotdot(open_path) != 0) {
		goto err_dotdot;
	}
#endif
	if ((res->fd = open(open_path, O_RDONLY)) == -1) {
		err = NoSuchFile;
		goto err_open;
	}

	if (fstat(res->fd, &statb) != 0)
		goto err_stat;
	file_len = statb.st_size;
	file_mtime = statb.st_mtime;
#if 0 /* XXX */
............ fetch obj equivalent from metadata and stat
	cli->in_len = GUINT64_FROM_LE(obj->size);
	if (file_len != obj_len) ........
	md5 = obj->md5;
#endif
	cli->in_len = file_len;
	md5 = "d41d8cd98f00b204e9800998ecf8427e";

	if (asprintf(&hdr,
"HTTP/%d.%d %d x\r\n"
"Content-Length: %llu\r\n"
"ETag: \"%s\"\r\n"
"Date: %s\r\n"
"Last-Modified: %s\r\n"
"\r\n",
		     cli->req.major,
		     cli->req.minor,
		     200,
		     (unsigned long long) cli->in_len,
		     md5,
		     hutil_time2str(timestr, sizeof(timestr), time(NULL)),
		     hutil_time2str(modstr, sizeof(modstr), file_mtime)) < 0)
		goto err_out_in_end;

	if (!want_body) {
		cli_in_end(cli);

		rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
		if (rc) {
			free(hdr);
			free(open_path);
			return true;
		}
		free(open_path);
		return cli_write_start(cli);
	}

	bytes = stor_get_buf(res, buf, MIN(cli->in_len, sizeof(buf)));
	if (bytes < 0) {
		applog(LOG_ERR, "read failed on %s (%d)", res->res_path,
		       (int) bytes);
		goto err_out_in_end;
	}
	if (bytes == 0) {
		if (!cli->in_len)
			cli_in_end(cli);

		rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
		if (rc) {
			free(hdr);
			goto err_out_in_end;
		}
		free(open_path);
		return cli_write_start(cli);
	}

	cli->in_len -= bytes;

	if (!cli->in_len)
		cli_in_end(cli);

	tmp = malloc(bytes);
	if (!tmp)
		goto err_out_in_end;
	memcpy(tmp, buf, bytes);

	rc = cli_writeq(cli, hdr, strlen(hdr), cli_cb_free, hdr);
	if (rc) {
		free(hdr);
		free(tmp);
		free(open_path);
		return true;
	}

	if (cli_writeq(cli, tmp, bytes,
	    cli->in_len ? object_get_more : cli_cb_free, tmp))
		goto err_out_in_end;

	free(open_path);
	return cli_write_start(cli);

err_out_in_end:
	cli_in_end(cli);
	/* No close(res->fd), it happens when freeing res. */
err_stat:
err_open:
err_dotdot:
	free(open_path);
err_open_path:
	return cli_err(cli, err);
}

/* callback from the client side: a queued write is being disposed */
static bool object_get_more(struct client *cli, void *cb_data, bool done)
{

	/* free now-written buffer */
	free(cb_data);

	/* do not queue more, if !completion or fd was closed early */
	if (!done)	/* FIXME We used to test for input errors here. */
		return false;
	if (!cli->in_len)
		return false;

	return object_get_poke(cli);		/* won't hurt to try */
}

#if 0 /* XXX Useful for AIO */
/* callback from the chunkd side: some data is available */
static void object_get_event(struct open_chunk *ochunk)
{
	object_get_poke(ochunk->cli);
	cli_write_run_compl();
}
#endif

/*
 * Return true iff cli_writeq was called. This is compatible with the
 * convention for cli continuation callbacks, so object_get_more can call us.
 */
static bool object_get_poke(struct client *cli)
{
	char *buf;
	ssize_t bytes;

	/* The checks for in_len in caller should protect us, but let's see. */
	if (cli->res == NULL || cli->res->fd == -1) {
		applog(LOG_ERR, "read on closed chunk, in_len %ld",
		       (long) cli->in_len);
		return false;
	}

	buf = malloc(CLI_DATA_BUF_SZ);
	if (!buf)
		return false;

	bytes = stor_get_buf(cli->res, buf, MIN(cli->in_len, CLI_DATA_BUF_SZ));
	if (bytes < 0) {
		applog(LOG_ERR, "read failed on %s (%d)", cli->res->res_path,
		       (int) bytes);
		goto err_out;
	}
	if (bytes == 0) {
		if (!cli->in_len) {
			cli_in_end(cli);
			cli_write_start(cli);
		}
		free(buf);
		return false;
	}

	cli->in_len -= bytes;
	if (!cli->in_len) {
		if (cli_writeq(cli, buf, bytes, cli_cb_free, buf))
			goto err_out;
		cli_in_end(cli);
		cli_write_start(cli);
	} else {
		if (cli_writeq(cli, buf, bytes, object_get_more, buf))
			goto err_out;
		if (cli_wqueued(cli) >= CLI_DATA_BUF_SZ)
			cli_write_start(cli);
	}
	return true;

err_out:
	cli_in_end(cli);
	free(buf);
	return false;
}

/*
 * The old stor_get_buf() protocol was set to read from remote nodes
 * ("chunkservers") so it supported asynchronous operation by returning
 * zero when there wasn't anything to read.
 *
 * For now we plug it with synchronous reads.
 * XXX The whole point of swift-oserver is to use io_submit().
 */
static ssize_t stor_get_buf(struct resource *res, void *buf, size_t len)
{
	ssize_t bytes;

	bytes = read(res->fd, buf, len);
	if (bytes == -1)
		return -errno;
	return bytes;
}

static char *make_open_path(const char *url_path, const struct param *par,
    enum errcode *errp)
{
	MD5_CTX md5ctx;
	unsigned char md[MD5_DIGEST_LENGTH];
	struct str_sp wordv[6];
	char md5[33];
	char *retpath;
	int rc;

	/* XXX uudecode open_path */

	/* /dev2/92714/AUTH_test/testcont/testobj */
	rc = str_split(wordv, ARRAY_SIZE(wordv), url_path, '/');
	if (rc != 5) {
		*errp = InvalidArgument;
		return NULL;
	}

	MD5_Init(&md5ctx);
	MD5_Update(&md5ctx, par->hash_prefix, strlen(par->hash_prefix));
	MD5_Update(&md5ctx, "/", 1);
	MD5_Update(&md5ctx, wordv[2].ptr, wordv[2].len);
	MD5_Update(&md5ctx, "/", 1);
	MD5_Update(&md5ctx, wordv[3].ptr, wordv[3].len);
	MD5_Update(&md5ctx, "/", 1);
	MD5_Update(&md5ctx, wordv[4].ptr, wordv[4].len);
	MD5_Update(&md5ctx, par->hash_suffix, strlen(par->hash_suffix));
	MD5_Final(md, &md5ctx);

	md5str(md, md5);

	rc = asprintf(&retpath, "%s/%.*s/objects/%.*s/%s/%s",
			par->node_dir,
			wordv[0].len, wordv[0].ptr,
			wordv[1].len, wordv[1].ptr,
			md5+29,
			md5);
	if (rc < 0) {
		*errp = InternalError;
		return NULL;
	}
	return retpath;

	/* XXX lsdir here */
}

static int str_split(struct str_sp *wvec, int wmax, const char *url_path,
    char sep)
{
	int cnt = 0;
	const char *p, *start;
	int l;

	p = start = url_path;
	l = 0;
	for (;;) {
		if (*p == '\0') {
			if (l) {
				if (cnt < wmax) {
					wvec[cnt].ptr = start;
					wvec[cnt].len = l;
					cnt++;
				}
			}
			return cnt;
		}
		if (*p == sep) {
			if (l) {
				if (cnt < wmax) {
					wvec[cnt].ptr = start;
					wvec[cnt].len = l;
					cnt++;
				}
			}
			p++;
			start = p;
			l = 0;
			continue;
		}
		p++;
		l++;
	}
}
