/*
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA  02110-1301, USA.

    ---
    Special thanx to Aleksey B. <hidden>
    Copyright (C) 2010, Vladimir Rudnyh <mail@dreadatour.ru>
 */

#ifndef _MRA_H_
#define _MRA_H_

#define VERSION_TXT "pidgin-mra 0.1"

#define MRA_HOST "mrim20.mail.ru"
#define MRA_PORT 2041
#define MRA_BUF_LEN 65536
#define MAX_GROUP   20
#define TYPING_TIMEOUT 10

/* This one is needed to prevent "implicit declaration of function ‘strptime’" warning */
#define _GNU_SOURCE
/* This one is used to prevent "unused parameter X" warnings */
#define UNUSED(expr) do { (void)(expr); } while (0)

#include <glib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <glib/gi18n.h>
#include <sys/types.h>
#include <time.h>
#include <proxy.h>
#include <sslconn.h>
#include <prpl.h>
#include <version.h>
#include <debug.h>
#include <connection.h>
#include <request.h>
#include <dnsquery.h>
#include <accountopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct _mra_user_info {   
    uint32_t weather_city;
    uint32_t messages_total;
    uint32_t messages_unread;
    char *mrim_nickname;
    char *client_endpoint;
} mra_user_info;

typedef struct _mra_anketa_info {
	char *username;
	char *domain;
	char *nickname;
	char *firstname;
	char *lastname;
	unsigned short sex;
	char *birthday;
	unsigned int city_id;
	char *location;
	unsigned short zodiak;
	unsigned short bmounth;
	unsigned short bday;
	unsigned short country_id;
	char *phone;
	unsigned short age;
} mra_anketa_info;

typedef struct _mra_contact {
    uint32_t id; 
    uint32_t status;
    gchar *email;
    gchar *nickname;
    uint32_t flags;
    uint32_t group_id;
    uint32_t intflags;
} mra_contact;

typedef struct _mra_group {
    uint32_t id; 
    gchar *name;
    uint32_t flags;
} mra_group;

typedef struct _mra_auth_request {
    gpointer mmp;
    char *email;
} mra_auth_request;

typedef struct _mra_add_buddy_req
{
    PurpleConnection *pc;
    PurpleBuddy *buddy;
    PurpleGroup *group;
} mra_add_buddy_req;


#include "proto.h"
#include "mra_net.h"

#define MRA_STATUS_ID_OFFLINE		    "offline"
#define MRA_STATUS_ID_ONLINE		    "available"
#define MRA_STATUS_ID_AWAY		        "away"
#define MRA_STATUS_ID_UNDETERMINATED	"custom"
#define MRA_STATUS_ID_INVISIBLE	        "invisible"

gboolean mra_email_is_valid(const char *);

void mra_contact_set_status(gpointer, char *, uint32_t);

void mra_hello_cb(gpointer);
void mra_login_cb(gpointer, uint32_t, char *);
void mra_logout_cb(gpointer, char *);
void mra_user_info_cb(gpointer, mra_user_info *);
void mra_contact_list_cb(gpointer, uint32_t, size_t, mra_group *, size_t, mra_contact *);
void mra_user_status_cb(gpointer, char *, uint32_t);
void mra_auth_request_add_cb(gpointer data);
void mra_auth_request_cancel_cb(gpointer data);
void mra_auth_request_cb(gpointer, char *, char *);
void mra_typing_notify_cb(gpointer, char *);
void mra_message_cb(gpointer, char *, char *, char *, time_t, uint32_t);
void mra_anketa_info_cb(gpointer, const char *, mra_anketa_info *);
void mra_mail_notify_cb(gpointer, uint32_t);

void mra_connect_cb(gpointer, gint, const gchar *);
int mra_send_im(PurpleConnection *, const char *, const char *, PurpleMessageFlags);
unsigned int mra_send_typing(PurpleConnection *, const char *, PurpleTypingState);
void mra_set_status(PurpleAccount *, PurpleStatus *);
void mra_add_buddy_ok_cb(mra_add_buddy_req *, char *);
void mra_add_buddy_cancel_cb(mra_add_buddy_req *, char *);
void mra_add_buddy(PurpleConnection *, PurpleBuddy *, PurpleGroup *);
void mra_remove_buddy(PurpleConnection *, PurpleBuddy *, PurpleGroup *);
void mra_alias_buddy(PurpleConnection *, const char *, const char *);
void mra_login(PurpleAccount *);
void mra_close(PurpleConnection *);
void mra_get_anketa(PurpleConnection *, const char *);

GList *mra_statuses(PurpleAccount *);
void mra_set_status_cb(PurplePluginAction *);
GList *mra_actions(PurplePlugin *, gpointer);

gboolean plugin_load(PurplePlugin *);
gboolean plugin_unload(PurplePlugin *);

#endif /* _MRA_H_ */

