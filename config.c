#include <string.h>

#include "oserver.h"

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

	if (!p->port)
		p->port = strdup("6000");

	// if (!p->port_file)
}
