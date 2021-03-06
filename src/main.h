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

#ifndef _MAIN_H
#define	_MAIN_H

#define CMD_PROCESS "PROCESS SPAMC/1.2\r\n"
#define CMD_SIZE "Content-length:"
#define CMD_USERNAME "User:"
#define RANDPOOL "0123456789abcdefghijklmnopqrstuvwxyz"
#define DEFAULT_MSG "Message blocked, identified as spam"

enum {
	BUFSIZE = 1024
};

typedef struct {
	gchar *host;
	int port;
	gchar *quarantine_dir;
	gboolean reject_spam;
	gchar *reject_msg;
} SpamSettings_T;

#endif	/* _MAIN_H */

