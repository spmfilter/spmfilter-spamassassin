/* spmfilter-spamassassin - spmfilter Spamassassin Plugin
 * Copyright (C) 2009-2010 Axel Steiner and SpaceNet AG
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>

#include <spmfilter.h>

#define DEFAULT_CONF "/etc/spmfilter.conf"

static gchar *quarantine_dir = NULL;
static gchar *nexthop = NULL;

void delete_message(gchar *path) {
	if (g_remove(path) != 0) {
		g_printerr("failed to remove message\n");
		exit(1);
	}

	if (g_remove(g_strdup_printf("%s.i",path)) != 0) {
		g_printerr("failed to remove message\n");
		exit(1);
	}
}

void release_message(gchar *path) {
	gchar *info_path = NULL;
	gchar *info = NULL;
	gchar **lines = NULL;
	GError *error = NULL;
	SMFMessageEnvelope_T *envelope = smf_message_envelope_new();
	
	info_path = g_strdup_printf("%s.i",path);

	if(!g_file_get_contents(info_path,&info,NULL,&error)) {
		g_printerr("%s\n",error->message);
		g_error_free(error);
		exit(1);
	}

	lines = g_strsplit(info,"\n",0);
	while(*lines != NULL) {
		gchar **tokens = NULL;
		tokens = g_strsplit(*lines,":",2);
		if (g_str_has_prefix(*lines,"sender"))
			envelope->from = g_strdup(tokens[1]);
		else if (g_str_has_prefix(*lines,"recipient"))
			envelope = smf_message_envelope_add_rcpt(envelope,tokens[1]);

		g_strfreev(tokens);
		lines++;
	}
	
	envelope->nexthop = g_strdup(nexthop);
	envelope->message_file = g_strdup(path);

	smf_message_deliver(envelope);
	smf_message_envelope_unref(envelope);

	delete_message(path);
	g_free(info);
	g_free(info_path);
}

void show_message(gchar *path) {
	GError *error = NULL;
	gchar *message = NULL;

	if(!g_file_get_contents(path,&message,NULL,&error)) {
		g_printerr("%s\n",error->message);
		g_error_free(error);
	} else {
		g_print(message);
	}
}

char *get_path(char *qid) {
	GString *path;
	GString *prefix;
	gchar *s = NULL;
	GDir *dh;
	GError *error = NULL;
	const gchar *entryname;
	int i;

	path = g_string_new(quarantine_dir);
	prefix = g_string_new(NULL);

	for (i=0; i < strlen(qid); i++){
		if ((g_str_has_suffix(quarantine_dir,"/") && (i==0)) || (i>=6)) {
			if (i>=6)
				prefix = g_string_append_c(prefix,g_ascii_tolower(qid[i]));
			else
				path = g_string_append_c(path,g_ascii_tolower(qid[i]));
		} else
			g_string_append_printf(path,"/%c",g_ascii_tolower(qid[i]));
	}

	dh = g_dir_open(path->str, 0, &error);
	if (error) {
		g_printerr("g_dir_open(%s) failed - %s\n", path->str, error->message);
		g_error_free(error);
		exit(1);
	}

	while ((entryname = g_dir_read_name(dh))) {
		if (g_str_has_prefix(entryname,prefix->str) &&
				(!g_str_has_suffix(entryname,".i"))) {
			s = g_strconcat(path->str, G_DIR_SEPARATOR_S, entryname, NULL);
			break;
		}
	}

	g_dir_close(dh);
	g_string_free(prefix,TRUE);
	g_string_free(path,TRUE);
	return s;
}

char *search_quarantine_dir(char *config_file) {
	GError *error = NULL;
	GKeyFile *keyfile;
	char *quarantine_dir = NULL;

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_file (keyfile, config_file, G_KEY_FILE_NONE, &error)) {
		g_printerr("Error loading config: %s\n",error->message);
		g_error_free(error);
		exit(-1);
	}

	quarantine_dir = g_key_file_get_string(keyfile, "spamassassin", "quarantine_dir", &error);
	if (quarantine_dir == NULL) {
		g_printerr("config error: %s\n", error->message);
		g_error_free(error);
		exit(1);
	}

	nexthop = g_key_file_get_string(keyfile, "global","nexthop",&error);
	if (nexthop == NULL) {
		g_printerr("config error: %s\n",error->message);
		g_error_free(error);
		exit(1);
	}

	g_key_file_free(keyfile);
	return quarantine_dir;
}

int main(int argc, char *argv[]) {
	GOptionContext *context;
	GError *error = NULL;
	gchar *config_file = NULL;
	gboolean release = FALSE;
	gboolean delete = FALSE;
	gboolean show = FALSE;
	gchar *message_path = NULL;
	gchar *qid = NULL;

	/* all cmd args */
	GOptionEntry entries[] = {
		{ "file", 'f', 0, G_OPTION_ARG_STRING, &config_file, "spmfilter config file", NULL},
		{ "release", 'r', 0, G_OPTION_ARG_NONE, &release, "release message from quarantine", NULL},
		{ "delete", 'd', 0, G_OPTION_ARG_NONE, &delete, "delete message from quarantine", NULL},
		{ "show", 's', 0, G_OPTION_ARG_NONE, &show, "show message", NULL},
		{ "id", 'i', 0, G_OPTION_ARG_STRING, &qid, "message quarantine id",NULL},
		{ NULL }
	};

	/* parse cmd args */
	context = g_option_context_new ("- smf-spamctl options");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_option_context_free(context);
		g_print("%s\n", error->message);
		g_error_free(error);
		return 1;
	}

	g_option_context_free(context);
	if (config_file == NULL) {
		if (!g_file_test(DEFAULT_CONF,G_FILE_TEST_IS_REGULAR)) {
			g_print("Can't find config file\n");
			exit(1);
		} else {
			config_file = g_strdup(DEFAULT_CONF);
		}
	}

	quarantine_dir = search_quarantine_dir(config_file);

	if (quarantine_dir == NULL) {
		g_printerr("Can't determine quarantine directory\n");
		exit(1);
	}

	if (release || delete || show) {
		if (qid == NULL) {
			g_printerr("Please supply quarantine id\n");
			exit(1);
		}
	}

	message_path = get_path(qid);

	if (message_path == NULL) {
		g_printf("ID [%s] unknown\n",qid);

	} else {
		if (delete) {
			delete_message(message_path);
			g_printf("Message [%s] deleted\n",qid);
		} else if (release) {
			release_message(message_path);
			g_printf("Message [%s] released\n",qid);
		} else if (show) {
			show_message(message_path);
		}
	}

	g_free(message_path);
	g_free(qid);
	g_free(config_file);
	g_free(quarantine_dir);
	return 0;
}
