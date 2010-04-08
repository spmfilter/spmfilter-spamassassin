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
#include <glib.h>
#include <glib/gstdio.h>

#include <spmfilter.h>

void check_quarantine(char *quarantine_dir) {
	printf("Cheers!\n");
}

char *search_quarantine_dir(char *config_file) {
	GError *error = NULL;
	GKeyFile *keyfile;
	char *quarantine_dir = NULL;

	keyfile = g_key_file_new ();
	if (!g_key_file_load_from_file (keyfile, config_file, G_KEY_FILE_NONE, &error)) {
		printf("Error loading config: %s\n",error->message);
		g_error_free(error);
		exit(-1);
	}

	quarantine_dir = g_key_file_get_string(keyfile, "spamassassin", "quarantine_dir", &error);
	if (quarantine_dir == NULL) {
		printf("config error: %s\n", error->message);
		g_error_free(error);
		exit(1);
	}
	
	return quarantine_dir;
}

int main(int argc, char *argv[]) {
	GOptionContext *context;
	GError *error = NULL;
	char *config_file = NULL;
	char *quarantine_dir = NULL;

	/* all cmd args */
	GOptionEntry entries[] = {
		{ "file", 'f', 0, G_OPTION_ARG_STRING, &config_file, "spmfilter config file", NULL},
		{ "quarantine", 'q', 0, G_OPTION_ARG_STRING, &quarantine_dir, "spam quarantine directory", NULL},
		{ NULL }
	};

	/* parse cmd args */
	context = g_option_context_new ("- smf-spam-liberator options");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_option_context_free(context);
		g_print("%s\n", error->message);
		g_error_free(error);
		return 1;
	}

	g_option_context_free(context);
	if (config_file == NULL) {
		if (!g_file_test("/etc/spmfilter.conf",G_FILE_TEST_IS_REGULAR)) {
			if (quarantine_dir == NULL) {
				printf("Neither config file, nor quarantine directory provided\n");
				return 1;
			} else {
				check_quarantine(quarantine_dir);
			}
		} else {
			/* searching quarantine dir in config file */
			quarantine_dir = search_quarantine_dir(g_strdup("/etc/spmfilter.conf"));
		}
	} else
		quarantine_dir = search_quarantine_dir(config_file);

	if (quarantine_dir == NULL) {
		printf("Neither config file, nor quarantine directory provided\n");
		return 1;
	} else
		check_quarantine(quarantine_dir);

	if (config_file != NULL)
		free(config_file);

	if (quarantine_dir != NULL)
		free(quarantine_dir);
	return 0;
}
