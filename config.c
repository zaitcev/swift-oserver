#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oserver.h"

static char *load_val(GKeyFile *kf, const char *conf,
    const char *key, const char *def);

/*
 * port
 * port_file
 * status_port
 * ourhost for forcing
 *
 * We _update_ the struct param, which is a bit annoying.
 */
void read_config(struct param *p, const char *conf)
{
	GKeyFile *kf;
	GError *err = NULL;

	kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, conf, G_KEY_FILE_NONE, &err)) {
		fprintf(stderr, TAG ": error loading `%s': %s\n",
		    conf, err->message);
		g_error_free(err);
		exit(1);
	}

	p->host = load_val(kf, conf, "bind_ip", NULL);
	if (!p->port) {
		p->port = load_val(kf, conf, "bind_port", "6000");
		/* Do not validate port here, redundant. */
	}
	if (!p->port_file) {
		p->port_file = load_val(kf, conf, "port_file", NULL);
	}

	// if (!p->port_file)

	g_key_file_free(kf);
}

static char *load_val(GKeyFile *kf, const char *conf,
    const char *key, const char *def)
{
	const char default_group[] = "DEFAULT";
	GError *err = NULL;
	char *val;

	val = g_key_file_get_value(kf, default_group, key, &err);
	if (val)
		return val;
	if (err->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
		fprintf(stderr, TAG ": cannot find `%s' in `%s': %s\n",
		    key, conf, err->message);
		g_error_free(err);
		exit(1);
	}
	g_error_free(err);
	if (def)
		return strdup(def);
	return NULL;
}
