#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oserver.h"

static char *load_val(GKeyFile *kf, const char *kfname,
    const char *group, const char *key, const char *def);

/*
 * hash_suffix, hash_prefix
 * host (was ourhost in tabled)
 * port
 * port_file
 * status_port -- XXX not set while we're deciding if we want all that code
 * node_dir
 *
 * We _update_ the struct param, which is a bit annoying.
 */
void read_config(struct param *p, const char *sconf, const char *conf)
{
	GKeyFile *kf;
	GError *err = NULL;

	kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, sconf, G_KEY_FILE_NONE, &err)) {
		fprintf(stderr, TAG ": error loading `%s': %s\n",
		    sconf, err->message);
		g_error_free(err);
		exit(1);
	}
	p->hash_suffix = load_val(kf, sconf, "swift-hash",
				 "swift_hash_path_suffix", "");
	p->hash_prefix = load_val(kf, sconf, "swift-hash",
				 "swift_hash_path_prefix", "");
	g_key_file_free(kf);

	kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, conf, G_KEY_FILE_NONE, &err)) {
		fprintf(stderr, TAG ": error loading `%s': %s\n",
		    conf, err->message);
		g_error_free(err);
		exit(1);
	}

	p->host = load_val(kf, conf, NULL, "bind_ip", NULL);
	if (!p->port) {
		p->port = load_val(kf, conf, NULL, "bind_port", "6000");
		/* Do not validate port here, redundant. */
	}
	if (!p->port_file) {
		p->port_file = load_val(kf, conf, NULL, "port_file", NULL);
	}

	p->node_dir = load_val(kf, conf, NULL, "devices", "/srv/node");

	g_key_file_free(kf);
}

static char *load_val(GKeyFile *kf, const char *kfname,
    const char *group, const char *key, const char *def)
{
	const char default_group[] = "DEFAULT";
	GError *err = NULL;
	char *val;

	if (!group)
		group = default_group;
	val = g_key_file_get_value(kf, group, key, &err);
	if (val)
		return val;
	if (err->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
		fprintf(stderr, TAG ": cannot find `%s' in `%s': %s\n",
		    key, kfname, err->message);
		g_error_free(err);
		exit(1);
	}
	g_error_free(err);
	if (def)
		return strdup(def);
	return NULL;
}
