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
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>

gboolean empty = TRUE;

int scan_directory(gchar *directory) {
	GDir *dh;
	GError *error = NULL;
	const gchar *entryname;
	struct stat st_info;
	
	dh = g_dir_open(directory, 0, &error);

	if (error) {
		g_printerr("g_dir_open(%s) failed - %s\n", directory, error->message);
		g_error_free(error);
		return -1;
	}

	while ((entryname = g_dir_read_name(dh))) {
		gchar *fullpath;

		fullpath = g_strconcat(directory, G_DIR_SEPARATOR_S, entryname, NULL);
		if (fullpath) {
			g_stat(fullpath,&st_info);
			if(S_ISDIR(st_info.st_mode)) {
				if (scan_directory(fullpath)!= 0) {
					return -1;
				}
			} else if(S_ISREG(st_info.st_mode)) {
				if (g_str_has_suffix(fullpath,"i")) {
					gchar *contents = NULL;
					gchar **lines = NULL;

					/* extract informations from file */
					if(!g_file_get_contents(fullpath,&contents,NULL,&error)) {
						g_printerr("%s\n",error->message);
						g_error_free(error);
					} else {
						if (contents != NULL) {
							lines = g_strsplit(contents,"\n",0);
							int num_to = 0;
							char **recipients = NULL;
							char *sender = NULL;
							char *qid = NULL;
							char *score = NULL;
							char *date = NULL;
							while(*lines != NULL) {
								char **tokens = NULL;
								tokens = g_strsplit(*lines,":",2);
								if (g_str_has_prefix(*lines,"date"))
									date = g_strdup(tokens[1]);
								else if (g_str_has_prefix(*lines,"score"))
									score = g_strdup(tokens[1]);
								else if (g_str_has_prefix(*lines,"recipient")) {
									recipients = g_realloc(
										recipients,
										sizeof(gchar) * (num_to + 1));
									recipients[num_to] = g_strdup(tokens[1]);
									num_to++;
									recipients[num_to] = NULL;
								} else if (g_str_has_prefix(*lines,"sender"))
									sender = g_strdup(tokens[1]);
								else if (g_str_has_prefix(*lines,"qid"))
									qid = g_strdup(tokens[1]);
								g_strfreev(tokens);
								lines++;
							}
							g_free(contents);

							if (empty)
								g_printf("-ID-\t\t-Score-\t\t-Date-\t\t\t-Sender/Recipient-\n");

							empty = FALSE;

							g_printf("%s\t%s\t\t%s",g_ascii_strup(qid,-1),score,date);
							g_printf("\t%s\n",sender);
							if (*recipients != NULL) {
								while (*recipients != NULL) {
									g_printf("\t\t\t\t\t\t\t%s\n",*recipients);
									free(*recipients);
									recipients++;
								}
							}
							g_printf("\n");
							
							if (sender != NULL)
								free(sender);
							if (qid != NULL)
								free(qid);
							if (score != NULL)
								free(score);
							if (date != NULL)
								free(date);
						}
					}
				}
			}
		}
	}

	return 0;
}

int main(int argc, char *argv[]) {
	GOptionContext *context;
	GError *error = NULL;
	gchar *quarantine_dir = NULL;

	/* all cmd args */
	GOptionEntry entries[] = {
		{ "directory", 'd', 0, G_OPTION_ARG_STRING, &quarantine_dir, "spam quarantine diretctory", NULL},
		{ NULL }
	};

	/* parse cmd args */
	context = g_option_context_new("- smf-spamq options");
	g_option_context_set_help_enabled(context,TRUE);
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_option_context_free(context);
		g_print("%s\n", error->message);
		g_error_free(error);
		return 1;
	}

	g_option_context_free(context);
	if (quarantine_dir != NULL) {
		if (!g_file_test(quarantine_dir,G_FILE_TEST_IS_DIR)) {
			g_print("Invalid quarantine directory\n");
			return 1;
		}
	} else {
		g_print("Please provide quarantine directory\n");
		return 1;
	}

	scan_directory(quarantine_dir);

	if (empty)
		g_print("Quarantine is empty\n");

	if (quarantine_dir != NULL)
		g_free(quarantine_dir);
	return 0;
}
