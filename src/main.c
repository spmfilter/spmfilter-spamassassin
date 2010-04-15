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
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <spmfilter.h>

#include "main.h"

#define THIS_MODULE "spamassassin"

SpamSettings_T *spam_settings;

int write_to_quarantine(char *score) {
	SMFSession_T *session = smf_session_get();
	char *quarantine_path;
	char *quarantine_filename;
	char *quarantine_info;
	char *filename;
	char *md5;
	int c,i;
	FILE *fh;
	time_t now;
	struct tm tim;
	char tmp_buffer[256];
	char *strrand;

	filename = smf_core_get_maildir_filename();
	md5 = smf_md5sum(filename);

	quarantine_path = g_strdup(spam_settings->quarantine_dir);
	for(c=0; c <=5; c++) {
		quarantine_path = g_strdup_printf("%s/%c",quarantine_path,md5[c]);
	}

	if (g_mkdir_with_parents(quarantine_path,0755) == -1) {
		TRACE(TRACE_ERR,"failed to create quarantine dir");
		free(md5);
		free(quarantine_path);
		return -1;
	}

	srand(time(0));
	strrand = malloc(3);
	for(i=0;i < 3; i++)
		strrand[i] = RANDPOOL[rand()%strlen(RANDPOOL)];
	strrand[i++] = '\0';
	quarantine_filename = g_strdup_printf("%s/%s.%s",quarantine_path,strrand,filename);
	quarantine_info = g_strdup_printf("%s.i",quarantine_filename);
	TRACE(TRACE_DEBUG,"writting message to quarantine [%s]",quarantine_filename);
	smf_session_to_file(quarantine_filename);

	fh = fopen(quarantine_info,"w");
	if (fh == NULL) {
		TRACE(TRACE_ERR,"failed to write quarantine info");
		free(md5);
		free(filename);
		free(quarantine_path);
		free(quarantine_filename);
		free(quarantine_info);
		return -1;
	}

	if (session->envelope_from != NULL)
		fprintf(fh,"sender:%s\n",session->envelope_from->addr);
	else if (session->message_from != NULL)
		fprintf(fh,"sender:%s\n",session->message_from->addr);
	else
		fprintf(fh,"sender:undef\n");
	
	if (session->envelope_to != NULL) {
		for(i = 0; i < session->envelope_to_num; i++) {
			fprintf(fh,"recipient:%s\n",session->envelope_to[i]->addr);
		}
	} else if (session->message_to != NULL) {
		for(i = 0; i < session->message_to_num; i++) {
			fprintf(fh,"recipient:%s\n",session->message_to[i]->addr);
		}
	} else
		fprintf(fh,"recipient:undef\n");

	now = time(NULL);
	tim = *(localtime(&now));
	strftime(tmp_buffer,256,"%F %H:%M:%S",&tim);
    fprintf(fh,"date:%s\n",tmp_buffer);

	fprintf(fh,"score:%s\n",score);
	fprintf(fh,"qid:");
	for(c=0; c <=5; c++)
		fprintf(fh,"%c",md5[c]);
	fprintf(fh,"%s\n",strrand);

	fclose(fh);

	free(md5);
	free(filename);
	free(quarantine_path);
	free(quarantine_filename);
	free(quarantine_info);
	free(strrand);
	return 0;
}

int perform_scan(char *username) {
	SMFSession_T *session = smf_session_get();
	int fd_socket, errno, ret, fh,fh2;
	gboolean is_spam = FALSE;
	struct sockaddr_in sa;
	char buf[BUFSIZE];
	char *cmd_size;
	char *cmd_username;
	char *new_queue_file;
	char *score;
	GIOChannel *spamd = NULL;
	GIOChannel *queue = NULL;
	GIOChannel *new_queue = NULL;
	
	sa.sin_family = AF_INET;
	sa.sin_port = htons(spam_settings->port);
	sa.sin_addr.s_addr = inet_addr(spam_settings->host);

	TRACE(TRACE_DEBUG, "connecting to [%s] on port [%d]",spam_settings->host,spam_settings->port);
	fd_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(fd_socket < 0) {
		TRACE(TRACE_ERR,"create socket failed: %s",strerror(errno));
		return -1;
	}

	ret = connect(fd_socket, (struct sockaddr *)&sa, sizeof(sa));
	if(ret < 0) {
		TRACE(TRACE_ERR, "unable to connect to [%s]: %s", spam_settings->host, strerror(errno));
		return -1;
	}

	spamd = g_io_channel_unix_new(fd_socket);
	g_io_channel_set_encoding(spamd, NULL, NULL);
	TRACE(TRACE_DEBUG,"sending command: %s",CMD_PROCESS);

	ret = send(fd_socket, CMD_PROCESS, strlen(CMD_PROCESS), 0);
	if (ret <= 0) {
		TRACE(TRACE_ERR, "sending of command failed: %s",strerror(errno));
		close(fd_socket);
		return -1;
	}

	cmd_size = g_strdup_printf("%s %d\r\n",CMD_SIZE, session->msgbodysize);
	TRACE(TRACE_DEBUG,"sending command: %s",cmd_size);

	ret = send(fd_socket, cmd_size , strlen(cmd_size), 0);
	if (ret <= 0) {
		TRACE(TRACE_ERR, "sending of command failed: %s",strerror(errno));
		close(fd_socket);
		return -1;
	}

	if (username != NULL) {
		cmd_username = g_strdup_printf("%s %s\r\n",CMD_USERNAME, username);
		TRACE(TRACE_DEBUG,"sending command: %s",cmd_username);

		ret = send(fd_socket, cmd_username, strlen(cmd_username), 0);
		if (ret <= 0) {
			TRACE(TRACE_ERR, "sending of command failed: %s",strerror(errno));
			close(fd_socket);
			return -1;
		}
	}

	TRACE(TRACE_DEBUG,"sending blank line");
	ret = send(fd_socket, "\r\n" , strlen("\r\n"), 0);
	if (ret <= 0) {
		TRACE(TRACE_ERR, "sending of command failed: %s",strerror(errno));
		close(fd_socket);
		return -1;
	}


	fh = open(session->queue_file, O_RDONLY);
	if(fh == -1) {
		TRACE(TRACE_ERR, "unable to open queue file [%s]: %s", session->queue_file, strerror(errno));
		close(fd_socket);
		return -1;
	}

	queue = g_io_channel_unix_new(fh);
	g_io_channel_set_encoding(queue, NULL, NULL);
	while(g_io_channel_read_chars(queue,buf,BUFSIZE,NULL,NULL) == G_IO_STATUS_NORMAL) {
		ret = send(fd_socket, buf, BUFSIZE, 0);
		if(ret <= 0) {
			TRACE(TRACE_ERR,"failed to send a chunk: %s",strerror(errno));
			close(fd_socket);
			g_io_channel_shutdown(queue,FALSE,NULL);
			close(fh);
			return -1;
		}
	}
	g_io_channel_shutdown(queue,FALSE,NULL);
	close(fh);

	smf_core_gen_queue_file(&new_queue_file);
	if ((fh2 = open(new_queue_file,O_WRONLY|O_CREAT)) == -1) {
		TRACE(TRACE_ERR,"failed writing queue file");
		close(fd_socket);
		return -1;
	}

	new_queue = g_io_channel_unix_new(fh2);
	g_io_channel_set_encoding(new_queue, NULL, NULL);
	while((ret = recv(fd_socket,buf,BUFSIZE, 0)) > 0) {
		if (g_strrstr(buf,"SPAMD/1.1") != NULL) {
			gchar **token = NULL;
			int pos = 0;
			token = g_strsplit(buf,"\r\n\r\n",2);
			pos = 4;
			if (token == NULL) {
				token = g_strsplit(buf,"\n\n",2);
				pos = 2;
			}

			if (g_strrstr(token[1],"X-Spam-Flag: YES") != NULL) {
				score = smf_core_get_substring(".*X-Spam-Status:\\s+Yes,\\s+score=(.*)\\s+required.*",token[1],1);
				TRACE(TRACE_INFO,"message [%s] identified as spam, score [%s]",smf_session_header_get("message-id"),score);
				is_spam = TRUE;
			}
			pos += strlen(token[0]);
			g_io_channel_write_chars(new_queue,buf + pos,ret - pos,NULL,NULL);
			g_strfreev(token);
			
		} else {
			g_io_channel_write_chars(new_queue,buf,ret,NULL,NULL);
		}
	}

	g_io_channel_shutdown(new_queue,TRUE,NULL);
	close(fh2);
	close(fd_socket);

	if (g_remove(session->queue_file) != 0) {
		TRACE(TRACE_ERR,"failed to remove queue file");
		return -1;
	}

	if(g_rename(new_queue_file,session->queue_file) != 0) {
		TRACE(TRACE_ERR,"failed to rename queue file");
		return -1;
	}

	g_free(new_queue_file);

	if (is_spam) {
		if (spam_settings->reject_spam) {
			if (spam_settings->reject_msg != NULL) 
				session->response_msg = g_strdup(spam_settings->reject_msg);

			return 554;
		} else {
			if (spam_settings->quarantine_dir != NULL) {
				if (write_to_quarantine(score) != 0) {
					if (score != NULL)
						free(score);
					return -1;
				}

			} else
				TRACE(TRACE_INFO,"no quarantine configured, message discarded");

			if (score	!= NULL)
				free(score);
			return 1;
		}
	} else
		return 0;
}

int get_spam_config(void) {
	spam_settings = g_slice_new(SpamSettings_T);

	if (smf_settings_group_load(THIS_MODULE) != 0) {
		TRACE(TRACE_ERR,"config group spamassassin does not exist");
		return -1;
	}

	spam_settings->host = smf_settings_group_get_string("host");
	
	spam_settings->port = smf_settings_group_get_integer("port");
	if (!spam_settings->port)
		spam_settings->port = 783;

	spam_settings->quarantine_dir = smf_settings_group_get_string("quarantine_dir");
	spam_settings->reject_spam = smf_settings_group_get_boolean("reject_spam");
	spam_settings->reject_msg = smf_settings_group_get_string("reject_msg");
	
	TRACE(TRACE_DEBUG,"spam_settings->host: %s",spam_settings->host);
	TRACE(TRACE_DEBUG,"spam_settings->port: %d",spam_settings->port);
	TRACE(TRACE_DEBUG,"spam_settings->quarantine_dir: %s", spam_settings->quarantine_dir);
	TRACE(TRACE_DEBUG,"spam_settings->reject_spam: %d",spam_settings->reject_spam);
	TRACE(TRACE_DEBUG,"spam_settings->reject_msg: %s",spam_settings->reject_msg);

	return 0;
}

int load(SMFSession_T *session) {
	int ret;
	TRACE(TRACE_DEBUG,"spamassassin loaded");
	if (get_spam_config()!=0)
		return -1;

	ret = perform_scan(NULL);
	g_slice_free(SpamSettings_T,spam_settings);

	return ret;
}
