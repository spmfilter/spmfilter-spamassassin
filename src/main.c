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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>

#include <spmfilter.h>

#include "main.h"

#define THIS_MODULE "spamassassin"

SpamSettings_T *spam_settings;

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
	
	TRACE(TRACE_DEBUG,"spam_settings->host: %s",spam_settings->host);
	TRACE(TRACE_DEBUG,"spam_settings->port: %d",spam_settings->port);
	
	return 0;
}

int load(SMFSession_T *session) {
	int fd_socket, errno, ret, fh;
	struct sockaddr_in sa;
	int bytes = 0;
	char buf[BUFSIZE];
	char *cmd_size;

	TRACE(TRACE_DEBUG,"spamassassin loaded");
	if (get_spam_config()!=0)
		return -1;

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

	TRACE(TRACE_DEBUG,"sending blank line");
	ret = send(fd_socket, "\r\n" , strlen("\r\n"), 0);
	if (ret <= 0) {
		TRACE(TRACE_ERR, "sending of command failed: %s",strerror(errno));
		close(fd_socket);
		return -1;
	}

	
	fh = open(session->queue_file, O_RDONLY);
	if(fh < 0) {
		TRACE(TRACE_ERR, "unable to open queue file [%s]: %s", session->queue_file, strerror(errno));
		close(fd_socket);
		return -1;
	}


	while((bytes = read(fh, buf, BUFSIZE)) > 0) {
		ret = send(fd_socket, buf, BUFSIZE, 0);
		if(ret <= 0) {
			TRACE(TRACE_ERR,"failed to send a chunk: %s",strerror(errno));
			close(fd_socket);
			close(fh);
			return -1;
		}
	}

	close(fh);

	ret = recv(fd_socket, buf, BUFSIZE, 0);
	TRACE(TRACE_DEBUG,"got %d bytes back, message was: %s", ret, buf);
	close(fd_socket);

	g_slice_free(SpamSettings_T,spam_settings);

	return 0;
}
