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

#ifndef _LIBERATOR_H
#define	_LIBERATOR_H

typedef struct {
	gchar *subject;
	gchar *date;
	gchar *score;
	gchar *mid;
	gchar **envelope_to;
	gchar *envelope_from;
	gchar **message_to;
	gchar *message_from;
	gchar *path;
} SMFSpamInfo_T;

#endif	/* _LIBERATOR_H */

