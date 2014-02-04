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

#ifndef _MRA_NET_H_
#define _MRA_NET_H_

#define MRA_LOGIN_SUCCESSFUL        0x0000
#define MRA_LOGIN_FAILED            0x0001

#define MRA_MESSAGE_TYPE_MESSAGE    0x0001
#define MRA_MESSAGE_TYPE_SYSTEM     0x0002
#define MRA_MESSAGE_TYPE_CONTACTS   0x0003

#define LPSLENGTH(s) (*((uint32_t *)(s)))
#define LPSSIZE(s)   (LPSLENGTH(s) + sizeof(uint32_t))
#define LPSALLOC(c)  ((char *) malloc((c) + sizeof(uint32_t)))

typedef struct _mra_serv_conn {
    PurpleAccount *acct;
    PurpleConnection *gc;
    PurpleProxyConnectData *connect_data;
    gint fd;
    gchar *name;
    GHashTable *users;
    GHashTable *users_is_authorized;
    GHashTable *groups;
    gboolean connected;
    gboolean authorized;
    mra_user_info *user_info;
    char *mra_server;
    unsigned int mra_port;
    unsigned int seq;
    char *tx_buf;
    unsigned int tx_len;
    guint tx_handler;
    char *rx_buf;
    unsigned int rx_len;
    mra_group *groups_list;
    mra_contact *contacts_list;

    // handlers
    guint ping_timer;
    
    // callbacks
    void (*callback_hello)(gpointer);                                                                   // hello
    void (*callback_login)(gpointer, uint32_t, gchar*);                                                 // auth
    void (*callback_logout)(gpointer, gchar*);                                                          // auth
    void (*callback_user_info)(gpointer, mra_user_info*);                                               // user info
    void (*callback_contact_list)(gpointer, uint32_t, size_t, mra_group*, size_t, mra_contact*);    // contact list
    void (*callback_user_status)(gpointer, char*, uint32_t);                                            // user status
    void (*callback_auth_request)(gpointer, char*, char*);                                              // auth request
    void (*callback_typing_notify)(gpointer, char*);                                                    // typing notify
    void (*callback_message)(gpointer, char*, char*, char*, time_t, uint32_t);                          // message
	void (*callback_anketa_info)(gpointer, const char *, mra_anketa_info *);                            // anketa info
	void (*callback_mail_notify)(gpointer, uint32_t);                                                   // new mails notify
} mra_serv_conn;

char *check_p(gpointer, char *, char *, char);
char *cp1251_to_utf8(const char *);
char *utf8_to_cp1251(const char *);
char *to_crlf(const char *);
char *mra_net_mklps(const char *);
char *mra_net_mksz(char *);

void mra_net_fill_cs_header(mrim_packet_header_t *, uint32_t, uint32_t, uint32_t);
void mra_net_send(gpointer, gpointer, size_t);
gboolean mra_net_send_flush(gpointer);

gboolean mra_net_ping_timeout_cb(mra_serv_conn *);

gboolean mra_net_send_ping(mra_serv_conn *);
gboolean mra_net_send_hello(mra_serv_conn *);
gboolean mra_net_send_auth(mra_serv_conn *, const char *, const char *, uint32_t);
gboolean mra_net_send_device_id(mra_serv_conn *, const char*);
gboolean mra_net_send_receive_ack(mra_serv_conn *, char *, uint32_t);
gboolean mra_net_send_message(mra_serv_conn *, const char *, const char *, uint32_t);
gboolean mra_net_send_typing(mra_serv_conn *, const char *);
gboolean mra_net_send_authorize_user(mra_serv_conn *, char *);
gboolean mra_net_send_add_user(mra_serv_conn *, char *, char *, uint32_t, uint32_t);
gboolean mra_net_send_change_user(mra_serv_conn *, uint32_t, uint32_t, char *, char *, uint32_t);
gboolean mra_net_send_status(mra_serv_conn *, uint32_t);
gboolean mra_net_send_anketa_info(mra_serv_conn *, const char *);

void mra_net_read_cb(gpointer, gint, PurpleInputCondition);
gboolean mra_net_read_proceed(gpointer);

void mra_net_read_hello(gpointer, char *, size_t);
void mra_net_read_login_successful(gpointer, char *, size_t);
void mra_net_read_login_failed(gpointer, char *, size_t);
void mra_net_read_logout(gpointer, char *, size_t);
void mra_net_read_user_info(gpointer, char *, size_t);
void mra_net_read_contact_list(gpointer, char *, size_t);
void mra_net_read_user_status(gpointer, char *, uint32_t);
void mra_net_read_message(gpointer, char *, uint32_t);
void mra_net_read_message_status(gpointer, char *, uint32_t);
void mra_net_read_message_offline(gpointer, char *, uint32_t);
void mra_net_read_add_contact_ack(gpointer, char *, uint32_t);
void mra_net_read_modify_contact_ack(gpointer, char *, uint32_t);
void mra_net_read_auth_ack(gpointer, char *, uint32_t);
void mra_net_read_anketa_info(gpointer, char *, uint32_t);
void mra_net_read_mailbox_status(gpointer, char *, uint32_t);

#endif /* _MRA_NET_H_ */

