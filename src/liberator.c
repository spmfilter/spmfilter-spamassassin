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

#include "liberator.h"

static GSList *messages_found = NULL;
static gchar *quarantine_dir = NULL;
static gchar *nexthop = NULL;

void separator(void) {
	int i;
	for (i=0; i< 80; i++)
		g_printf("-");
	g_printf("\n");
}

gboolean check_valid_id(int id) {
	if (g_slist_length(messages_found) >= id)
		return TRUE;
	else
		return FALSE;
}

void get_input(int type, int given) {
	int id;
	char choice[1];

	separator();
	g_printf("\nPlease select:\n\t- (D)elete message\n\t- (R)elease message\n");
	if (type == 0)
		g_printf("\t- (S)how message\n");
	if (type == 1)
		g_printf("\t- (B)ack to quarantine\n");
	g_printf("\t- (Q)uit\n");

	g_printf("Choice: ");
	fscanf(stdin, "%s", choice);

	if (strlen(choice) == 0)
		g_printf("Invalid choice\n");

	if(g_ascii_strcasecmp(choice,"q") == 0) {
		exit(0);
	}

	if ((g_ascii_strcasecmp(choice,"s") == 0) && (type == 0)) {
		g_printf("Please enter ID: ");
		fscanf(stdin, "%d", &id);
		if (check_valid_id(id))
			show_message(id);
		else {
			g_printf("Invalid ID\n");
			get_input(type,given);
		}
	} else if(g_ascii_strcasecmp(choice,"d") == 0) {
		if (given != 0)
			delete_message(given);
		else {
			g_printf("Please enter ID: ");
			fscanf(stdin, "%d", &id);
			if (check_valid_id(id))
				delete_message(id - 1);
			else {
				g_printf("Invalid ID\n");
				get_input(type,given);
			}
		}
		check_quarantine();
	} else if(g_ascii_strcasecmp(choice,"r") == 0) {
		if (given != 0)
			release_message(given);
		else {
			g_printf("Please enter ID: ");
			fscanf(stdin, "%d", &id);
			if (check_valid_id(id))
				release_message(id);
			else {
				g_printf("Invalid ID\n");
				get_input(type,given);
			}
		}
	} else if((g_ascii_strcasecmp(choice,"b") == 0) && (type == 1)) {
		check_quarantine();
	} else {
		g_printf("Unknown choice\n");
		get_input(type,given);
	}
}


int release_message(int id) {
	SMFMessageEnvelope_T *envelope = smf_message_envelope_new();
	SMFSpamInfo_T *info = (SMFSpamInfo_T *)g_slist_nth_data(messages_found,id - 1);

	while (*info->envelope_to != NULL) {
		envelope = smf_message_envelope_add_rcpt(envelope,*info->envelope_to);
		info->envelope_to++;
	}

	envelope->from = g_strdup(info->envelope_from);
	envelope->nexthop = g_strdup(nexthop);

	envelope->message_file = info->path;

	smf_message_deliver(envelope);
	smf_message_envelope_unref(envelope);

	delete_message(id);
	return 0;
}

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
				if (g_str_has_suffix(fullpath,"info")) {
					gchar *contents = NULL;
					gchar **lines = NULL;	
					SMFSpamInfo_T *info = g_slice_new(SMFSpamInfo_T);
					info->path = g_strndup(fullpath,strlen(fullpath) - 5);
					info->envelope_to = g_malloc(sizeof(gchar));
					info->message_to = g_malloc(sizeof(gchar));
					/* extract informations from file */
					if(!g_file_get_contents(fullpath,&contents,NULL,&error)) {
						g_printerr("%s\n",error->message);
						g_error_free(error);
					} else {
						if (contents != NULL) {
							lines = g_strsplit(contents,"\n",0);
							int num_env_to = 0;
							int num_mes_to = 0;
							while(*lines != NULL) {
								char **tokens = NULL;
								tokens = g_strsplit(*lines,":",2);
								if (g_str_has_prefix(*lines,"subject"))
									info->subject = g_strdup(tokens[1]);
								else if (g_str_has_prefix(*lines,"date"))
									info->date = g_strdup(tokens[1]);
								else if (g_str_has_prefix(*lines,"score"))
									info->score = g_strdup(tokens[1]);
								else if (g_str_has_prefix(*lines,"envelope-to")) {
									info->envelope_to = g_realloc(
										info->envelope_to,
										sizeof(gchar) * (num_env_to + 1));
									info->envelope_to[num_env_to] = g_strdup(tokens[1]);
									num_env_to++;
									info->envelope_to[num_env_to] = NULL;
								} else if (g_str_has_prefix(*lines,"envelope-from"))
									info->envelope_from = g_strdup(tokens[1]);
								else if (g_str_has_prefix(*lines,"message-to")) {
									info->message_to = g_realloc(
										info->message_to,
										sizeof(gchar) * (num_mes_to + 1));
									info->message_to[num_mes_to] = g_strdup(tokens[1]);
									num_mes_to++;
									info->message_to[num_mes_to] = NULL;
								} else if (g_str_has_prefix(*lines,"message-from"))
									info->message_from = g_strdup(tokens[1]);
								else if (g_str_has_prefix(*lines,"mid"))
									info->mid = g_strdup(tokens[1]);
								g_strfreev(tokens);
								lines++;
							}
							g_free(contents);
							messages_found = g_slist_append(messages_found,info);
						}
					}
				}
			}
		}
	}

	return 0;
}

void display_info(int id, SMFSpamInfo_T *info) {
	g_printf("%d\t%s\t\t%s",id,info->score,info->date);
	if (info->envelope_from != NULL)
		g_printf("\t%s\n",info->envelope_from);
	else if(info->message_from != NULL)
		g_printf("\t%s\n",info->message_from);
	else
		g_printf("\tundef\n");

	if (*info->envelope_to != NULL) {
		while (*info->envelope_to != NULL) {
			g_printf("\t\t\t\t\t\t%s\n",*info->envelope_to);
			info->envelope_to++;
		}
	} else if (*info->message_to != NULL) {
		while (*info->message_to != NULL) {
			g_printf("\t\t\t\t\t\t%s\n",*info->message_to);
			info->message_to++;
		}
	} else
		g_printf("\t\t\t\t\t\tundef\n");
	g_printf("\n");
}

void show_message(int id) {
	GError *error = NULL;
	gchar *message = NULL;
	SMFSpamInfo_T *info = (SMFSpamInfo_T *)g_slist_nth_data(messages_found,id - 1);

	if(!g_file_get_contents(info->path,&message,NULL,&error)) {
		g_printerr("%s\n",error->message);
		g_error_free(error);
	} else {
		separator();
		g_printf("%s",message);
	}

	get_input(1,id);
}

void delete_message(int id) {
	SMFSpamInfo_T *info = (SMFSpamInfo_T *)g_slist_nth_data(messages_found,id);
	if (g_remove(info->path) != 0) {
		g_printerr("failed to remove message\n");
		exit(1);
	}

	if (g_remove(g_strdup_printf("%s.info",info->path)) != 0) {
		g_printerr("failed to remove message\n");
		exit(1);
	}

	messages_found = g_slist_remove(messages_found,info);
	check_quarantine();
}

void check_quarantine(void) {
	int i = 1;
	GSList *iter;
	if (messages_found == NULL)
		scan_directory(quarantine_dir);

	g_printf("-ID-\t-Score-\t\t-Date-\t\t\t-Sender/Recipient-\n");
	iter = messages_found;
	while (iter) {
		display_info(i, (SMFSpamInfo_T *)iter->data);
		iter = iter->next;
		i++;
	}

	get_input(0,0);
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

	/* all cmd args */
	GOptionEntry entries[] = {
		{ "file", 'f', 0, G_OPTION_ARG_STRING, &config_file, "spmfilter config file", NULL},
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
	} else
		check_quarantine();

	if (messages_found != NULL)
		g_slist_free(messages_found);

	if (config_file != NULL)
		g_free(config_file);

	if (quarantine_dir != NULL)
		g_free(quarantine_dir);
	return 0;
}
