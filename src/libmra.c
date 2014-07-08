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

#define PURPLE_PLUGIN

#include "libmra.h"

static PurplePlugin *this_plugin;

/**************************************************************************************************
    Check email
**************************************************************************************************/
gboolean mra_email_is_valid(const char *email)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    purple_debug_info("mra", "[%s] check email '%s'\n", __func__, email);               /* FIXME */

    // check email by purple
    if (!purple_email_is_valid(email)) {
        purple_debug_info("mra", "[%s] failed check 'purple_email_is_valid'\n", __func__);  /* FIXME */
        return FALSE;
    }

    char **eml = g_strsplit(email, "@", 2);
    gboolean ret = TRUE;

    // check if email is too long
    if (strlen(eml[0]) > 32) {
        ret = FALSE;
        purple_debug_info("mra", "[%s] failed check 'username length'\n", __func__);        /* FIXME */
    }

    // check username (allowed symbols)
    if (ret) {
        while (*email != '@') {
            // only 'a-z', 'A-Z', '0-9', '_', '-' and '.' allowed
            if (ret && (*email < '0' || *email > '9') && (*email < 'a' || *email > 'z') && (*email < 'A' || *email > 'Z') && *email != '_' && *email != '-' && *email != '.') {
                ret = FALSE;
                purple_debug_info("mra", "[%s] failed check 'allowed symbols'\n", __func__);/* FIXME */
                break;
            }
            email++;
        }
    }

    // check domain
    if (ret && strcmp(eml[1], "mail.ru") != 0 && strcmp(eml[1], "list.ru") != 0 && strcmp(eml[1], "inbox.ru") != 0 && strcmp(eml[1], "bk.ru") != 0 && strcmp(eml[1], "corp.mail.ru") != 0 && strcmp(eml[1], "chat.agent") != 0) {
        ret = FALSE;
        purple_debug_info("mra", "[%s] failed check 'allowed domains'\n", __func__);    /* FIXME */
    }

    g_strfreev(eml);

    return ret;
}

/**************************************************************************************************
    Load server to connect to callback
**************************************************************************************************/
void mra_get_connection_server_cb(PurpleUtilFetchUrlData *url_data, gpointer data, const gchar *url_text, gsize len, const gchar *error_message) {
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(url_data);
    UNUSED(len);
    UNUSED(error_message);

    gchar **srv = NULL;
    gchar *server = NULL;
    int port = 0;

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp != NULL);

    PurpleAccount *acct = mmp->acct;
    g_return_if_fail(acct != NULL);

    PurpleConnection *gc = mmp->gc;
    g_return_if_fail(gc != NULL);

    if (!url_text) {
        purple_debug_info("mra", "[%s] failed to get server to connect to\n", __func__);
                                                                                        /* FIXME */
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Connection problem"));
        return;
    }

    purple_debug_info("mra", "[%s] server to connect to: '%s'\n", __func__, url_text);  /* FIXME */

    srv = g_strsplit(url_text, ":", 2);
    server = g_strdup(srv[0]);
    port = atoi(srv[1]);

    mmp->connect_data = purple_proxy_connect(gc, acct, server, port, mra_connect_cb, gc);
    if (mmp->connect_data == NULL) {
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Connection problem"));
    }

    g_strfreev(srv);
    g_free(server);
}

/**************************************************************************************************
    Get server to connect to
**************************************************************************************************/
void mra_get_connection_server(gpointer data, const char *server, int port) {
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    gchar *url = NULL;

    url = g_strdup_printf("http://%s:%u/", server, port);

    purple_debug_info("mra", "[%s] connection server url: %s\n", __func__, url);                   /* FIXME */

    purple_util_fetch_url(url, TRUE, NULL, TRUE, mra_get_connection_server_cb, data);

    g_free(url);
}

/**************************************************************************************************
    Load user avatar callback
**************************************************************************************************/
void mra_load_avatar_cb(PurpleUtilFetchUrlData *url_data, gpointer data, const gchar *url_text, gsize len, const gchar *error_message) {
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(url_data);
    UNUSED(error_message);

    PurpleAccount *account = NULL;
    PurpleBuddy *buddy = NULL;

    buddy = data;
    g_return_if_fail(buddy != NULL);
    g_return_if_fail(buddy->name != NULL);

    // check email by purple
    if (!purple_email_is_valid(buddy->name)) {
        purple_debug_info("mra", "[%s] user is invalid: %s (%s)\n", __func__, buddy->name, buddy->alias);
                                                                                        /* FIXME */
        return;
    }

    purple_debug_info("mra", "[%s] downloaded avatar for user %s\n", __func__, buddy->name);
                                                                                        /* FIXME */

    if (error_message) {
        purple_debug_info("mra", "[%s] error: %s\n", __func__, error_message);          /* FIXME */
    }

    purple_debug_info("mra", "[%s] downloaded: %" G_GSIZE_FORMAT " bytes\n", __func__, len);
                                                                                        /* FIXME */

    if (!url_text) {
        purple_debug_info("mra", "[%s] failed to download avatar for %s\n", __func__, buddy->name);
                                                                                        /* FIXME */
        return;
    }

    account = purple_buddy_get_account(buddy);
    g_return_if_fail(account != NULL);

    purple_buddy_icons_set_for_user(account, buddy->name, g_memdup((gchar *)url_text, len), len, NULL);
}

/**************************************************************************************************
    Load user avatar
**************************************************************************************************/
void mra_load_avatar(gpointer data, const char *email) {
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    PurpleBuddy *buddy;
    mra_serv_conn *mmp;
    gchar **eml = NULL;
    gchar *domain = NULL;
    gchar *url = NULL;

    mmp = data;
    g_return_if_fail(mmp != NULL);

    buddy = purple_find_buddy(mmp->acct, email);
    g_return_if_fail(buddy != NULL);

    purple_debug_info("mra", "[%s] find avatar for email: %s\n", __func__, email);      /* FIXME */

    eml = g_strsplit(email, "@", 2);
    if (strcmp(eml[1], "corp.mail.ru") == 0) {
        domain = g_strdup("corp");
    } else if (strcmp(eml[1], "mail.ru") == 0) {
        domain = g_strdup("mail");
    } else if (strcmp(eml[1], "list.ru") == 0) {
        domain = g_strdup("list");
    } else if (strcmp(eml[1], "inbox.ru") == 0) {
        domain = g_strdup("inbox");
    } else if (strcmp(eml[1], "bk.ru") == 0) {
        domain = g_strdup("bk");
    } else {
        purple_debug_info("mra", "[%s] unknown email domain: %s\n", __func__, eml[1]);  /* FIXME */
        g_strfreev(eml);
        return;
    }

    url = g_strdup_printf("http://obraz.foto.mail.ru/%s/%s/_mrimavatar", domain, eml[0]);

    purple_debug_info("mra", "[%s] avatar url: %s\n", __func__, url);                   /* FIXME */

    purple_util_fetch_url(url, TRUE, NULL, TRUE, mra_load_avatar_cb, buddy);

    g_strfreev(eml);
    g_free(domain);
    g_free(url);
}

/**************************************************************************************************
    Set contact status
**************************************************************************************************/
void mra_contact_set_status(gpointer data, char *email, uint32_t status)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp != NULL);

    purple_debug_info("mra", "[%s] %s status: 0x%08x\n", __func__, email, status);      /* FIXME */

    if (status & STATUS_FLAG_INVISIBLE) {
        purple_debug_info("mra", "[%s] %s status is invisible\n", __func__, email);     /* FIXME */
        purple_prpl_got_user_status(mmp->acct, email, MRA_STATUS_ID_INVISIBLE, NULL);
    }

    switch (status & 0x7FFFFFFF) {
        case STATUS_OFFLINE:
            purple_debug_info("mra", "[%s] %s status is offline\n", __func__, email);   /* FIXME */
            purple_prpl_got_user_status(mmp->acct, email, MRA_STATUS_ID_OFFLINE, NULL);
            break;
        case STATUS_ONLINE:
            purple_debug_info("mra", "[%s] %s status is online\n", __func__, email);    /* FIXME */
            purple_prpl_got_user_status(mmp->acct, email, MRA_STATUS_ID_ONLINE, NULL);
            break;
        case STATUS_AWAY:
            purple_debug_info("mra", "[%s] %s status is away\n", __func__, email);      /* FIXME */
            purple_prpl_got_user_status(mmp->acct, email, MRA_STATUS_ID_AWAY, NULL);
            break;
        case STATUS_UNDETERMINATED:
        default:
            purple_debug_info("mra", "[%s] %s status is unknown\n", __func__, email);   /* FIXME */
            purple_prpl_got_user_status(mmp->acct, email, MRA_STATUS_ID_UNDETERMINATED, NULL);
    }

    // load avatar
    mra_load_avatar(data, email);
}

/**************************************************************************************************
    Callback for 'hello' function
**************************************************************************************************/
void mra_hello_cb(gpointer data)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp       != NULL);
    g_return_if_fail(mmp->acct != NULL);
    g_return_if_fail(mmp->gc   != NULL);

    const char *username = purple_account_get_username(mmp->acct);
    const char *password = purple_account_get_password(mmp->acct);
    uint32_t status  = STATUS_ONLINE;

    purple_connection_update_progress(mmp->gc, _("Connecting"), 3, 3);

    mra_net_send_auth(mmp, username, password, status);

    const char *device_id = purple_account_get_string(mmp->acct, "dev_id", "");
    mra_net_send_device_id(mmp, device_id);
}

/**************************************************************************************************
    Callback for 'login' function
**************************************************************************************************/
void mra_login_cb(gpointer data, uint32_t status, char *message)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp     != NULL);
    g_return_if_fail(mmp->gc != NULL);

    if (status != MRA_LOGIN_SUCCESSFUL) {
        purple_debug_error("mra", "[%s] got error\n", __func__);                        /* FIXME */

        gchar *tmp;
        tmp = g_strdup_printf(_("Connection problem:\n%s"), message);
        purple_connection_error_reason(mmp->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);

        mra_close(mmp->gc);
    } else {
        purple_connection_update_progress(mmp->gc, _("Connecting"), 3, 3);
        mmp->authorized = TRUE;

        purple_debug_info("mra", "mra_login is OK\n");                                  /* FIXME */
    }
}

/**************************************************************************************************
    Logout callback
**************************************************************************************************/
void mra_logout_cb(gpointer data, char *reason)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp       != NULL);
    g_return_if_fail(mmp->acct != NULL);
    g_return_if_fail(mmp->gc   != NULL);

    const char *username = purple_account_get_username(mmp->acct);

    purple_debug_error("mra", "[%s] got reason: %s\n", __func__, reason);               /* FIXME */

    gchar *tmp;
    tmp = g_strdup_printf(_("Account %s is used on another computer or device.\n"), username);
    purple_connection_error_reason(mmp->gc, PURPLE_CONNECTION_ERROR_NAME_IN_USE, tmp);
    g_free(tmp);
}

/**************************************************************************************************
    Callback for 'user_info' function
**************************************************************************************************/
void mra_user_info_cb(gpointer data, mra_user_info *user_info)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(data);
    UNUSED(user_info);
}

/**************************************************************************************************
    Callback for 'contact list' function
**************************************************************************************************/
void mra_contact_list_cb(gpointer data, uint32_t status, size_t group_cnt, mra_group *groups, size_t contact_cnt, mra_contact *contacts)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(status);

    mra_serv_conn *mmp = data;
    size_t i;
    char *group;
    PurpleGroup *g = NULL;
    PurpleBuddy *buddy;

    g_return_if_fail(mmp                      != NULL);
    g_return_if_fail(mmp->acct                != NULL);
    g_return_if_fail(mmp->groups              != NULL);
    g_return_if_fail(mmp->users               != NULL);
    g_return_if_fail(mmp->users_is_authorized != NULL);

    mmp->groups_list   = groups;
    mmp->contacts_list = contacts;

    // proceed all groups
    for (i = 0; i < group_cnt; i++) {
        purple_debug_info("mra", "[%s] group %s (%d)\n",
                          __func__, groups[i].name, groups[i].id);                      /* FIXME */

        if (groups[i].removed || groups[i].name == NULL || *groups[i].name == '\0') {
            continue;
        }

        // insert group into groups hash
        g_hash_table_insert(mmp->groups, g_strdup_printf("%d", groups[i].id), groups[i].name);

        // add group into pidgin, if not exists
        if ((purple_find_group(groups[i].name)) == NULL) {
            g = purple_group_new(groups[i].name);
            purple_blist_add_group(g, NULL);
        }
    }

    // proceed all users
    for (i = 0; i < contact_cnt; i++) {
        purple_debug_info("mra", "[%s] user %s (%d)\n",
                          __func__, contacts[i].email, contacts[i].id);                 /* FIXME */

        buddy = purple_find_buddy(mmp->acct, contacts[i].email);

        if (contacts[i].removed || contacts[i].skip_user || contacts[i].email == NULL || *contacts[i].email == '\0') {
            if (contacts[i].skip_user) {
                continue;
            }
            if (buddy != NULL) {
                purple_blist_remove_buddy(buddy);
            }
            continue;
        }

        if (!(contacts[i].intflags & CONTACT_INTFLAG_NOT_AUTHORIZED)) {
            g_hash_table_insert(mmp->users_is_authorized, contacts[i].email, "TRUE");
            purple_debug_info("mra", "[%s] users_is_authorized = %s\n", __func__, contacts[i].email);             /* FIXME */
        }

        g_hash_table_insert(mmp->users, contacts[i].email, g_strdup_printf("%d", contacts[i].id));

        // add user into pidgin, if user not found
        if (buddy == NULL) {
            // get group name by id
            group = g_hash_table_lookup(mmp->groups, g_strdup_printf("%d", contacts[i].group_id));

            // get group by name
            g = purple_find_group(group);
            // add group into pidgin, if not exists
            if (g == NULL) {
                if (groups[contacts[i].group_id].name != NULL && *groups[contacts[i].group_id].name != '\0') {
                    g = purple_group_new(groups[contacts[i].group_id].name);
                    purple_blist_add_group(g, NULL);
                } else {
                    g = purple_group_new(_("Buddies"));
                }
            }

            purple_debug_info("mra", "[%s] group %s\n", __func__, g->name);             /* FIXME */

            // create new buddy
            buddy = purple_buddy_new(mmp->acct, contacts[i].email, contacts[i].nickname);

            purple_debug_info("mra", "[%s] buddy %s\n", __func__, buddy->name);         /* FIXME */

            // add buddy into pidgin
            purple_blist_add_buddy(buddy, NULL, g, NULL);
        }

        // set buddy status
        if (contacts[i].nickname != NULL && *contacts[i].nickname != '\0') {
            purple_blist_alias_buddy(buddy, contacts[i].nickname);
        } else {
            purple_blist_alias_buddy(buddy, contacts[i].email);
        }
        mra_contact_set_status(mmp, contacts[i].email, contacts[i].status);
    }
}

/**************************************************************************************************
    Callback for 'user_status' function
**************************************************************************************************/
void mra_user_status_cb(gpointer data, char *email, uint32_t status)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp != NULL);

    mra_contact_set_status(mmp, email, status);
}

/**************************************************************************************************
    Callback for 'auth_request accepted' function
**************************************************************************************************/
void mra_auth_request_add_cb(gpointer data)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_auth_request *auth_request = data;
    g_return_if_fail(auth_request != NULL);
    g_return_if_fail(auth_request->mmp != NULL);

    // send auth user answer
    mra_net_send_authorize_user(auth_request->mmp, auth_request->email);
    // send 'add user into group' packet. group = 0 <- TODO (is it neccecary?)
    mra_net_send_add_user(auth_request->mmp, auth_request->email, auth_request->email, 0, 0);

    g_free(auth_request->email);
    g_free(auth_request);
}

/**************************************************************************************************
    Callback for 'auth_request canceled' function
**************************************************************************************************/
void mra_auth_request_cancel_cb(gpointer data)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_auth_request *auth_request = data;
    g_return_if_fail(auth_request != NULL);

    // TODO: remove this callback in future?!

    g_free(auth_request->email);
    g_free(auth_request);
}

/**************************************************************************************************
    Callback for 'auth_request' function
**************************************************************************************************/
void mra_auth_request_cb(gpointer data, char *from, char *message)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp       != NULL);
    g_return_if_fail(mmp->acct != NULL);

    mra_auth_request *auth_request = g_new0(mra_auth_request, 1);

    auth_request->mmp = mmp;
    auth_request->email = g_strdup(from);

    purple_account_request_authorization(mmp->acct, from, NULL, NULL, message,
                                         purple_find_buddy(mmp->acct, from) != NULL,
                                         mra_auth_request_add_cb, mra_auth_request_cancel_cb, auth_request);
}

/**************************************************************************************************
    Callback for 'typing_notify' function
**************************************************************************************************/
void mra_typing_notify_cb(gpointer data, char *from)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp     != NULL);
    g_return_if_fail(mmp->gc != NULL);

    serv_got_typing(mmp->gc, from, TYPING_TIMEOUT, PURPLE_TYPING);
}

/**************************************************************************************************
    Callback for 'mail_notify' function
**************************************************************************************************/
void mra_mail_notify_cb(gpointer data, uint32_t status)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

	char buff[128];
    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp       != NULL);
    g_return_if_fail(mmp->gc   != NULL);
    g_return_if_fail(mmp->acct != NULL);

    // skip notify if no such setting
    if (!purple_account_get_check_mail(mmp->acct))
        return;

	if (status < 1)
		return;

	sprintf(buff, "Dear %s.\nYou have %u unread mail(s) in your mailbox", mmp->acct->username, status);
	purple_notify_message(mmp->gc, PURPLE_NOTIFY_MSG_INFO, "New Mail", buff, NULL, NULL, NULL);

}

/**************************************************************************************************
    Callback for 'message' function
**************************************************************************************************/
void mra_message_cb(gpointer data, char *from, char *message, char *message_rtf, time_t time, uint32_t type)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(message_rtf);
    UNUSED(type);

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp       != NULL);
    g_return_if_fail(mmp->acct != NULL);

    PurpleConversation *conv;
//    PurpleBuddyIcon *icon;

    // TODO: add buddy icon here

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, mmp->acct);
    if (conv) {
        purple_debug_info("mra", "[%s] conversation was found\n", __func__);            /* FIXME */

        purple_conversation_set_name(conv, from);
    } else {
        purple_debug_info("mra", "[%s] conversation not found\n", __func__);            /* FIXME */

        conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, mmp->acct, from);
    }

    serv_got_im(mmp->gc, from, purple_markup_escape_text(message, strlen(message)), 0, time);
}

/**************************************************************************************************
    Connection result
**************************************************************************************************/
void mra_connect_result(gpointer data, gint status, char *error)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(data);

    purple_debug_error("mra", "[%s] connect result: %d (%s)\n",
                       __func__, status, error);                                        /* FIXME */
}

/**************************************************************************************************
    Connect to server callback
**************************************************************************************************/
void mra_connect_cb(gpointer data, gint source, const gchar *error_message)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    PurpleConnection *gc = data;
    g_return_if_fail(gc != NULL);

    mra_serv_conn *mmp = gc->proto_data;
    g_return_if_fail(mmp       != NULL);
    g_return_if_fail(mmp->acct != NULL);

    const char *username = purple_account_get_username(mmp->acct);

    // Don't need to cancel connection any more since it is established.
    mmp->connect_data = NULL;

    // return error if connection is invalid
    if (!PURPLE_CONNECTION_IS_VALID(gc)) {
        purple_debug_error("mra", "purple connection is invalid\n");                    /* FIXME */
        close(source);
        return;
    }

    // return error if no source
    if (source < 0) {
        purple_debug_error("mra", "source < 0\n");
        gchar *tmp;
        tmp = g_strdup_printf(_("Could not establish a connection with the server:\n%s"),
                              error_message);
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);
        return;
    }

    // fill proto data
    mmp->fd = source;
    mmp->connected = TRUE;
    mmp->name = g_strdup_printf("%s:%d",
                                purple_account_get_string(gc->account, "host", MRA_HOST),
                                purple_account_get_int(gc->account, "port", MRA_PORT));

    purple_connection_set_display_name(gc, username);
    purple_connection_set_state(gc, PURPLE_CONNECTED);
    purple_debug_info("mra", "[%s] Connected\n", __func__);                             /* FIXME */
    purple_debug_info("mra", "[%s] Trying to login user...\n", __func__);               /* FIXME */

    // set handler for incoming data
    mmp->tx_handler = purple_input_add(mmp->fd, PURPLE_INPUT_READ, (PurpleInputFunction) mra_net_read_cb, mmp);

    // set all callbacks
    mmp->callback_hello         = mra_hello_cb;
    mmp->callback_login         = mra_login_cb;
    mmp->callback_logout        = mra_logout_cb;
    mmp->callback_user_info     = mra_user_info_cb;
    mmp->callback_contact_list  = mra_contact_list_cb;
    mmp->callback_user_status   = mra_user_status_cb;
    mmp->callback_auth_request  = mra_auth_request_cb;
    mmp->callback_typing_notify = mra_typing_notify_cb;
    mmp->callback_message       = mra_message_cb;
	mmp->callback_anketa_info	= mra_anketa_info_cb;
	mmp->callback_mail_notify	= mra_mail_notify_cb;

    // send 'hello' packet
    mra_net_send_hello(mmp);
}

/**************************************************************************************************
    Send message
**************************************************************************************************/
int mra_send_im(PurpleConnection *gc, const char *to, const char *message, PurpleMessageFlags flags)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(flags);

    g_return_val_if_fail(gc != NULL, 0);

    mra_serv_conn *mmp = gc->proto_data;
    g_return_val_if_fail(mmp != NULL, 0);

    char *message_plain = purple_unescape_html(message);
    gboolean ret = FALSE;

    purple_debug_info("mra", "[%s] send message {%s} to {%s}\n", __func__, message, to);/* FIXME */

    ret = mra_net_send_message(mmp, to, message_plain, 0);

    g_free(message_plain);

    if (ret) {
        return 1;
    }

    return 0;
}

/**************************************************************************************************
    Set info
**************************************************************************************************/
void mra_set_info(PurpleConnection *gc, const char *rawinfo)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(gc);
    UNUSED(rawinfo);

//    mra_serv_conn *mmp = gc->proto_data;
}

/**************************************************************************************************
    Send typing
**************************************************************************************************/
unsigned int mra_send_typing(PurpleConnection *gc, const char *to, PurpleTypingState state)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    g_return_val_if_fail(gc != NULL, 0);

    mra_serv_conn *mmp = gc->proto_data;
    g_return_val_if_fail(mmp != NULL, 0);

    if (state == PURPLE_TYPING) {
        if (mra_net_send_typing(mmp, to)) {
            return 1;
        }
    }

    return 0;
}

/**************************************************************************************************
    Set status
**************************************************************************************************/
void mra_set_status(PurpleAccount *acct, PurpleStatus *status)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    g_return_if_fail(acct != NULL);

    PurpleConnection *gc = purple_account_get_connection(acct);
    g_return_if_fail(gc != NULL);

    mra_serv_conn *mmp = gc->proto_data;
    g_return_if_fail(mmp != NULL);

    const gchar *status_id;
    uint32_t mra_status;

    if (!purple_status_is_active(status))
        return;

    if (!purple_account_is_connected(acct))
        return;

    status_id = purple_status_get_id(status);

    if (!strcmp(status_id, MRA_STATUS_ID_ONLINE)) {
        mra_status = STATUS_ONLINE;
    } else if (!strcmp(status_id, MRA_STATUS_ID_AWAY)) {
        mra_status = STATUS_AWAY;
    } else if (!strcmp(status_id, MRA_STATUS_ID_INVISIBLE)) {
        mra_status = STATUS_FLAG_INVISIBLE | STATUS_ONLINE;
    } else {
        mra_status = STATUS_ONLINE;
    }

    mra_net_send_status(mmp, mra_status);
}

/**************************************************************************************************
    Add buddy confirmed
**************************************************************************************************/
void mra_add_buddy_ok_cb(mra_add_buddy_req *data, char *msg)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    PurpleConnection *pc;
    PurpleBuddy *buddy;
    PurpleGroup *group;
    mra_serv_conn *mmp;
    gchar *email;
    gchar *alias;

    g_return_if_fail(data        != NULL);
    g_return_if_fail(data->pc    != NULL);
    g_return_if_fail(data->buddy != NULL);
    g_return_if_fail(data->group != NULL);

    pc = data->pc;

    buddy = data->buddy;
    group = data->group;
    g_free(data);

    mmp = pc->proto_data;

    if (mmp == NULL || mmp->users_is_authorized == NULL) {
        return;
    }

    email = strdup(purple_buddy_get_name(buddy));
    alias = strdup(purple_buddy_get_alias(buddy));

    if (g_hash_table_lookup(mmp->users_is_authorized, email) == NULL) {
        g_hash_table_insert(mmp->users_is_authorized, email, "TRUE");
        purple_debug_info("mra", "[%s] users_is_authorized = %s\n", __func__, email);             /* FIXME */
    }

    mra_net_send_add_user(mmp, email, alias, 0, 0);
    mra_net_send_message(mmp, purple_buddy_get_name(buddy), msg, MESSAGE_FLAG_AUTHORIZE);

    g_free(email);
    g_free(alias);
}

/**************************************************************************************************
    Add buddy canceled
**************************************************************************************************/
void mra_add_buddy_cancel_cb(mra_add_buddy_req *data, char *msg)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(msg);

    g_return_if_fail(data != NULL);

    // Remove from local list
    purple_blist_remove_buddy(data->buddy);

    g_free(data);
}

/**************************************************************************************************
    Add buddy
**************************************************************************************************/
void mra_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    const char *email;
    mra_add_buddy_req *data;

    if (gc == NULL) {
        return;
    }
    if (buddy == NULL) {
        purple_debug_info("mra", "[%s] I can't add user because I have no buddy!\n", __func__);
                                                                                        /* FIXME */
        return;
    }
    if (group == NULL) {
        purple_debug_info("mra", "[%s] I can't add user because I have no group!\n", __func__);
                                                                                        /* FIXME */
        return;
    }

    email = purple_buddy_get_name(buddy);

/*
    if (!mra_email_is_valid(email)) {
        gchar *buf;
        buf = g_strdup_printf(_("Unable to add the buddy %s because the username is invalid.  Usernames must be valid email addresses."), email);
        if (!purple_conv_present_error(email, purple_connection_get_account(gc), buf)) {
            purple_notify_error(gc, NULL, _("Unable to Add"), buf);
        }
        g_free(buf);

        // Remove from local list
        purple_blist_remove_buddy(buddy);

        return;
    }
*/

    data = g_new0(mra_add_buddy_req, 1);
    data->pc = gc;
    data->buddy = buddy;
    data->group = group;

    purple_request_input(gc, NULL, _("Authorization Request Message:"),
                         NULL, _("Please authorize me!"), TRUE, FALSE, NULL,
                         _("_OK"), G_CALLBACK(mra_add_buddy_ok_cb),
                         _("_Cancel"), G_CALLBACK(mra_add_buddy_cancel_cb),
                         purple_connection_get_account(gc), email, NULL, data);
}

/**************************************************************************************************
    Remove buddy
**************************************************************************************************/
void mra_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(group);

    g_return_if_fail(gc    != NULL);
    g_return_if_fail(buddy != NULL);

    mra_serv_conn *mmp = gc->proto_data;
    gpointer buddy_user_id;
    uint32_t user_id;
    uint32_t group_id = 0;
    char *email;
    char *name;

    g_return_if_fail(mmp        != NULL);
    g_return_if_fail(mmp->users != NULL);

    email = (char *) purple_buddy_get_name(buddy);
    if (email == NULL) {
        purple_debug_info("mra", "[%s] I can't remove user because I can't find email!\n", __func__);
                                                                                        /* FIXME */
        return;
    }
    name  = (char *) purple_buddy_get_alias(buddy);
    if (name == NULL) {
        purple_debug_info("mra", "[%s] I can't remove user because I can't find name!\n", __func__);
                                                                                        /* FIXME */
        return;
    }
    buddy_user_id = g_hash_table_lookup(mmp->users, email);
    if (buddy_user_id == NULL) {
        purple_debug_info("mra", "[%s] I can't remove user because I can't find user_id!\n", __func__);
                                                                                        /* FIXME */
        return;
    }
    user_id = atol(buddy_user_id);

    purple_debug_info("mra", "[%s] Remove user %s (%s), user_id: %d\n",
                      __func__, email, name, user_id);                                  /* FIXME */

    mra_net_send_change_user(mmp, user_id, group_id, email, name, CONTACT_FLAG_REMOVED);
}

/**************************************************************************************************
    Alias buddy
**************************************************************************************************/
void mra_alias_buddy(PurpleConnection *gc, const char *name, const char *alias)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */
    purple_debug_info("mra", "[%s] name: %s, alias: %s\n",  __func__, name, alias);     /* FIXME */

    g_return_if_fail(gc    != NULL);
    g_return_if_fail(alias != NULL);

    mra_serv_conn *mmp = gc->proto_data;
    PurpleBuddy *buddy;
    gpointer buddy_user_id;
    uint32_t user_id;
    uint32_t group_id = 0;

    g_return_if_fail(mmp        != NULL);
    g_return_if_fail(mmp->acct  != NULL);
    g_return_if_fail(mmp->users != NULL);

    buddy = purple_find_buddy(mmp->acct, name);
    if (buddy == NULL) {
        purple_debug_info("mra", "[%s] I can't rename buddy because I can't find name!\n", __func__);
                                                                                        /* FIXME */
        return;
    }

    buddy_user_id = g_hash_table_lookup(mmp->users, name);
    if (buddy_user_id == NULL) {
        purple_debug_info("mra", "[%s] I can't remove user because I can't find user_id!\n", __func__);
                                                                                        /* FIXME */
        return;
    }
    user_id = atol(buddy_user_id);

    purple_debug_info("mra", "[%s] Rename user %s (%d) to '%s'\n",
                      __func__, name, user_id, alias);                                    /* FIXME */

//    purple_blist_alias_buddy(buddy, alias);
	mra_net_send_change_user(mmp, user_id, group_id, (char *) name, (char *) alias, 0);
}

/**************************************************************************************************
    Get Anleta Info
**************************************************************************************************/
void mra_get_anketa(PurpleConnection *gc, const char *who)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    g_return_if_fail(gc != NULL);

    mra_serv_conn *mmp = gc->proto_data;
    g_return_if_fail(mmp != NULL);

	mra_net_send_anketa_info(mmp, who);
}

/**************************************************************************************************
    Check && Generate device id
**************************************************************************************************/
const char* mra_generate_device_id()
{
#define MRA_UUID_LEN 125
    static char buf[MRA_UUID_LEN];
    int fd = open("/proc/sys/kernel/random/uuid", O_RDONLY);
    if (fd == -1)
    {
        purple_debug_info("mra", "%s failed open uuid file: %s", __func__, strerror(errno));
        return NULL;
    }

    ssize_t len = 0;
    ssize_t r = 0;
    while (r = read(fd, buf + len, sizeof(buf) - len))
    {
        if (r == -1)
        {
            purple_debug_info("mra", "%s failed read uuid file: %s", __func__, strerror(errno));
            return NULL;
        }

        len += r;
    }

    buf[len - 1] = '\0'; // last symbol is \n - not needed
    return buf;
}

void mra_check_device_id(PurpleAccount *acct)
{
    const char* device_id = purple_account_get_string(acct, "dev_id", "");
    if (device_id[0] != '\0')
    {
        purple_debug_info("mra", "%s device id %s", __func__, device_id);
        return;
    }

    device_id = mra_generate_device_id();
    if (!device_id)
    {
        purple_debug_error("mra", "%s Failed to generate device id, will continue without it!", __func__);
        return;
    }
    
    purple_account_set_string(acct, "dev_id", device_id);
}

/**************************************************************************************************
    Connect to server
**************************************************************************************************/
void mra_login(PurpleAccount *acct)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    gchar *server = NULL;
    int port = 0;
    const char *username = NULL;

    g_return_if_fail(acct != NULL);

    PurpleConnection *gc = purple_account_get_connection(acct);
    g_return_if_fail(gc != NULL);

    username = purple_account_get_username(acct);

    mra_serv_conn *mmp;

    purple_debug_info("mra", "[%s] Try to connect to server\n", __func__);              /* FIXME */

    gc->proto_data = mmp = g_new0(mra_serv_conn, 1);
    mmp->fd = -1;
    mmp->gc = gc;
    mmp->acct = acct;
    mmp->connected = FALSE;
    mmp->authorized = FALSE;
    mmp->seq = 0;
    mmp->users = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    mmp->users_is_authorized = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    mmp->groups = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    mmp->tx_buf = (char *) malloc(MRA_BUF_LEN + 1);
    mmp->tx_len = 0;
    mmp->tx_handler = 0;
    mmp->rx_buf = (char *) malloc(MRA_BUF_LEN + 1);
    mmp->rx_len = 0;

    mmp->groups_list   = NULL;
    mmp->contacts_list = NULL;

    purple_connection_update_progress(gc, _("Connecting"), 1, 3);

    server = g_strdup(purple_account_get_string(acct, "host", MRA_HOST));
    port   = purple_account_get_int(acct,    "port", MRA_PORT);

    mra_check_device_id(acct);
            
/*
    // return error if username is invalid
    if (!mra_email_is_valid(username)) {
        purple_debug_error("mra", "[%s] email '%s' is invalid\n", __func__, username);
        purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_INVALID_SETTINGS, _("Username is invalid"));
    } else if (strcmp(server, "mrim.mail.ru") == 0) {
*/
    if (strcmp(server, "mrim.mail.ru") == 0) {
        purple_debug_info("mra", "[%s] Get server to connect to: %s:%u\n", __func__, server, port);
                                                                                        /* FIXME */
        mra_get_connection_server(mmp, server, port);
    } else {
        purple_debug_info("mra", "[%s] Connect directly to server %s:%u\n", __func__, server, port);
                                                                                        /* FIXME */
        mmp->connect_data = purple_proxy_connect(gc, acct, server, port, mra_connect_cb, gc);
        if (mmp->connect_data == NULL) {
            purple_connection_error_reason(gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Connection problem"));
        }
    }
    g_free(server);
}

/**************************************************************************************************
    Close connection
**************************************************************************************************/
void mra_close(PurpleConnection *gc)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp;

    g_return_if_fail(gc != NULL);

    mmp = gc->proto_data;
    g_return_if_fail(mmp != NULL);

    if (mmp->ping_timer) {
        purple_timeout_remove(mmp->ping_timer);
    }
    if (mmp->connect_data != NULL) {
        purple_proxy_connect_cancel(mmp->connect_data);
    }
    if (mmp->fd) {
        close(mmp->fd);
    }
    if (mmp->tx_handler) {
        purple_input_remove(mmp->tx_handler);
    }

    if (mmp->users) {
        g_hash_table_destroy(mmp->users);
    }
    if (mmp->users_is_authorized) {
        g_hash_table_destroy(mmp->users_is_authorized);
    }
    if (mmp->groups) {
        g_hash_table_destroy(mmp->groups);
    }
    if (mmp->groups_list) {
        g_free(mmp->groups_list);
    }
    if (mmp->contacts_list) {
        g_free(mmp->contacts_list);
    }
    if (mmp) {
        g_free(mmp);
    }
    gc->proto_data = NULL;

    purple_connection_set_protocol_data(gc, NULL);
    purple_prefs_disconnect_by_handle(gc);

    purple_debug_error("mra", "[%s] connection was closed\n", __func__);                /* FIXME */
}

/**************************************************************************************************
    Rerequest auth
**************************************************************************************************/
void mra_rerequest_auth(PurpleBlistNode *node, gpointer ignored) {
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(ignored);

    PurpleBuddy *buddy;
    PurpleGroup *group;
    PurpleConnection *gc;
    mra_serv_conn *mmp;
    const char *email;
    mra_add_buddy_req *data;

    buddy = (PurpleBuddy *) node;
    g_return_if_fail(buddy != NULL);

    group = purple_buddy_get_group(buddy);
    g_return_if_fail(group != NULL);

    gc = purple_account_get_connection(purple_buddy_get_account(buddy));
    g_return_if_fail(gc != NULL);

    mmp = gc->proto_data;
    g_return_if_fail(mmp != NULL);

    email = purple_buddy_get_name(buddy);

    data = g_new0(mra_add_buddy_req, 1);
    data->pc = gc;
    data->buddy = buddy;
    data->group = group;

    purple_request_input(gc, NULL, _("Authorization Request Message:"),
                         NULL, _("Please authorize me!"), TRUE, FALSE, NULL,
                         _("_OK"), G_CALLBACK(mra_add_buddy_ok_cb),
                         _("_Cancel"), NULL,
                         purple_connection_get_account(gc), email, NULL, data);
}

/**************************************************************************************************
    Buddy menu
**************************************************************************************************/
GList *mra_buddy_menu(PurpleBuddy *buddy) {
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    PurpleConnection *gc;
    mra_serv_conn *mmp;
    GList *menu;
    PurpleMenuAction *act;
    char *email;
    char *authorized;
    char *user_id;

    g_return_val_if_fail(buddy != NULL, NULL);

    gc = purple_account_get_connection(purple_buddy_get_account(buddy));
    g_return_val_if_fail(gc != NULL, NULL);

    menu = NULL;

    mmp = gc->proto_data;
    g_return_val_if_fail(mmp                      != NULL, NULL);
    g_return_val_if_fail(mmp->users               != NULL, NULL);
    g_return_val_if_fail(mmp->users_is_authorized != NULL, NULL);

    email = (char *) purple_buddy_get_name(buddy);
    authorized = g_hash_table_lookup(mmp->users_is_authorized, email);
    user_id = g_hash_table_lookup(mmp->users, email);

    if (authorized == NULL && user_id == NULL) {
        purple_debug_info("mra", "[%s] user %s is not authorized\n", __func__, email);  /* FIXME */

        act = purple_menu_action_new(_("Re-request Authorization"), PURPLE_CALLBACK(mra_rerequest_auth), NULL, NULL);
        menu = g_list_prepend(menu, act);
    }
    menu = g_list_reverse(menu);

    return menu;
}

/**************************************************************************************************
    Add buddy menu
**************************************************************************************************/
GList *mra_blist_node_menu(PurpleBlistNode *node) {
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
        return mra_buddy_menu((PurpleBuddy *) node);
    } else {
        return NULL;
    }
}


/**************************************************************************************************
    Add statuses types
**************************************************************************************************/
GList *mra_statuses(PurpleAccount *acct)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(acct);

    GList *types = NULL;
	PurpleStatusType *status;

	//Online people have a status message and also a date when it was set
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "ONLINE", _("Online"), FALSE, TRUE, FALSE, "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING), "message_date", _("Message changed"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types  = g_list_append(types, status);

	//Away people have a status message and also a date when it was set
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "AWAY", _("Away"), FALSE, TRUE, FALSE, "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING), "message_date", _("Message changed"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types  = g_list_append(types, status);

	//Unavailable people have a status message and also a date when it was set
	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "UNAVIALABLE", _("Unavailable"), FALSE, TRUE, FALSE, "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING), "message_date", _("Message changed"), purple_value_new(PURPLE_TYPE_STRING), NULL);
	types  = g_list_append(types, status);

	//Offline people dont have messages
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "OFFLINE", _("Offline"), FALSE, TRUE, FALSE);
	types  = g_list_append(types, status);

	return types;
}

/**************************************************************************************************
    Set mail.ru agent status callback
**************************************************************************************************/
void mra_set_status_cb(PurplePluginAction *action)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(action);
}

/**************************************************************************************************
    Get anketa info
**************************************************************************************************/
void mra_anketa_info_cb(gpointer data, const char *who, mra_anketa_info *anketa)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mra_serv_conn *mmp = data;
    g_return_if_fail(mmp     != NULL);
    g_return_if_fail(mmp->gc != NULL);

	PurpleNotifyUserInfo *user_info;

	user_info = purple_notify_user_info_new();

	purple_notify_user_info_add_section_break(user_info);
	purple_notify_user_info_prepend_pair(user_info, "Phone", anketa->phone);
	purple_notify_user_info_prepend_pair(user_info, "Location", anketa->location);
	purple_notify_user_info_prepend_pair(user_info, "Zodiac sign", ((anketa->zodiak == 1) ? "The Ram" : (anketa->zodiak == 2) ? "The Bull" : (anketa->zodiak == 3) ? "The Twins" : (anketa->zodiak == 4) ? "The Crab" : (anketa->zodiak == 5) ? "The Lion" : (anketa->zodiak == 6) ? "The Virgin" : (anketa->zodiak == 7) ? "The Balance" : (anketa->zodiak == 8) ? "The Scorpion" : (anketa->zodiak == 9) ? "The Archer" : (anketa->zodiak == 10) ? "The Capricorn" : (anketa->zodiak == 11) ? "The Water-bearer" : (anketa->zodiak == 12) ? "The Fish" : "" ));
	purple_notify_user_info_prepend_pair(user_info, "Birthday", anketa->birthday);
	purple_notify_user_info_prepend_pair(user_info, "Sex", ((anketa->sex == 1) ? "Male" : (anketa->sex == 2) ? "Female" : "" ));
	purple_notify_user_info_prepend_pair(user_info, "Lastname", anketa->lastname);
	purple_notify_user_info_prepend_pair(user_info, "Firstname", anketa->firstname);
	purple_notify_user_info_prepend_pair(user_info, "Nickname", anketa->nickname);
	purple_notify_user_info_prepend_pair(user_info, "Domain", anketa->domain);
	purple_notify_user_info_prepend_pair(user_info, "Username", anketa->username);
	purple_notify_user_info_prepend_pair(user_info, "E-Mail", who);

	purple_notify_userinfo(mmp->gc, who, user_info, 0, 0);
	purple_notify_user_info_destroy(user_info);
}

/**************************************************************************************************
    Actions to provide additional features
**************************************************************************************************/
GList *mra_actions(PurplePlugin *plugin, gpointer context)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(plugin);
    UNUSED(context);

    GList *m = NULL;
//	PurplePluginAction *act;

//	act = purple_plugin_action_new(_("Set Mail.ru Agent status..."), mra_set_status_cb);
//	m = g_list_append(m, act);

	return m;
}

/**************************************************************************************************
    List of icons
**************************************************************************************************/
static const char *mra_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
    UNUSED(account);
    UNUSED(buddy);

    return "mra";
}

/**************************************************************************************************
    List of emblems
**************************************************************************************************/
const char *mra_list_emblem(PurpleBuddy *buddy)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    PurpleConnection *gc;
    mra_serv_conn *mmp;
    char *email;
    char *authorized;
    char *user_id;

    g_return_val_if_fail(buddy != NULL, NULL);

    gc = purple_account_get_connection(purple_buddy_get_account(buddy));
    g_return_val_if_fail(gc        != NULL,             NULL);
    g_return_val_if_fail(gc->state == PURPLE_CONNECTED, NULL);

    mmp = gc->proto_data;
    g_return_val_if_fail(mmp                      != NULL, NULL);
    g_return_val_if_fail(mmp->users               != NULL, NULL);
    g_return_val_if_fail(mmp->users_is_authorized != NULL, NULL);

    email = (char *) purple_buddy_get_name(buddy);
    authorized = g_hash_table_lookup(mmp->users_is_authorized, email);
    user_id = g_hash_table_lookup(mmp->users, email);

    purple_debug_info("mra", "[%s] get %s emblem: %s, id: %s\n", __func__, email, authorized, user_id);
                                                                                        /* FIXME */

    if (authorized == NULL && user_id == NULL) {
        purple_debug_info("mra", "[%s] user %s is not authorized\n", __func__, email);  /* FIXME */
        return "not-authorized";
    }

    return NULL;
}

/**************************************************************************************************
	Status text
**************************************************************************************************/
char *mra_status_text(PurpleBuddy *buddy)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    PurplePresence *presence;
	PurpleStatus *status;
    char *text;
    char *tmp;

    g_return_val_if_fail(buddy != NULL, NULL);

	presence = purple_buddy_get_presence(buddy);
    g_return_val_if_fail(presence != NULL, NULL);

    status = purple_presence_get_active_status(presence);
    g_return_val_if_fail(status != NULL, NULL);

    tmp = purple_utf8_salvage(purple_status_get_name(status));
    text = g_markup_escape_text(tmp, -1);
    g_free(tmp);

    return text;
}

/**************************************************************************************************
    Load plugin
**************************************************************************************************/
gboolean plugin_load(PurplePlugin *plugin)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(plugin);

	return TRUE;
}

/**************************************************************************************************
    Unload plugin
**************************************************************************************************/
gboolean plugin_unload(PurplePlugin *plugin)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(plugin);

	return TRUE;
}

/**************************************************************************************************
    Get account text table
**************************************************************************************************/
static GHashTable * mra_get_account_text_table(PurpleAccount *acct)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    UNUSED(acct);

    GHashTable *table;
    table = g_hash_table_new(g_str_hash, g_str_equal);
    g_hash_table_insert(table, "login_label", (gpointer)_("Email Address..."));
    return table;
}

/**************************************************************************************************
    Info about Mail.ru Agent protocol - list of functions for actions
**************************************************************************************************/
static PurplePluginProtocolInfo prpl_info = {
	OPT_PROTO_MAIL_CHECK | OPT_PROTO_IM_IMAGE,
	NULL,                                           // user_splits
	NULL,                                           // protocol_options
	{"jpg",0,0,50,50,-1,PURPLE_ICON_SCALE_SEND},    // icon_spec
	mra_list_icon,                                  // list_icon
	mra_list_emblem,                                // list_emblems
	mra_status_text,                                // status_text
	NULL,                                           // tooltip_text
	mra_statuses,                                   // status_types
	mra_blist_node_menu,                            // blist_node_menu
	NULL,                                           // chat_info
	NULL,                                           // chat_info_defaults
	mra_login,                                      // login
	mra_close,                                      // close
	mra_send_im,                                    // send_im
	mra_set_info,                                   // set_info
	mra_send_typing,                                // send_typing
	mra_get_anketa,                                 // get_info
	mra_set_status,                                 // set_status
	NULL,                                           // set_idle
	NULL,                                           // change_passwd
	mra_add_buddy,                                  // add_buddy
	NULL,                                           // add_buddies
	mra_remove_buddy,                               // remove_buddy
	NULL,                                           // remove_buddies
	NULL,                                           // add_permit
	NULL,                                           // add_deny
	NULL,                                           // rem_permit
	NULL,                                           // rem_deny
	NULL,                                           // set_permit_deny
	NULL,                                           // join_chat
	NULL,                                           // reject chat invite
	NULL,                                           // get_chat_name
	NULL,                                           // chat_invite
	NULL,                                           // chat_leave
	NULL,                                           // chat_whisper
	NULL,                                           // chat_send
	NULL,                                           // keepalive
	NULL,                                           // register_user
	NULL,                                           // get_cb_info
	NULL,                                           // get_cb_away
	mra_alias_buddy,                                // alias_buddy
	NULL,                                           // group_buddy
	NULL,                                           // rename_group
	NULL,                                           // buddy_free
	NULL,                                           // convo_closed
	NULL,                                           // normalize
	NULL,                                           // set_buddy_icon
	NULL,                                           // remove_group
	NULL,                                           // get_cb_real_name
	NULL,                                           // set_chat_topic
	NULL,                                           // find_blist_chat
	NULL,                                           // roomlist_get_list
	NULL,                                           // roomlist_cancel
	NULL,                                           // roomlist_expand_category
	NULL,                                           // can_receive_file
	NULL,                                           // send_file
	NULL,                                           // new_xfer
	NULL,                                           // offline_message
	NULL,                                           // whiteboard_prpl_ops
	NULL,                                           // send_raw
	NULL,                                           // roomlist_room_serialize
	NULL,                                           // unregister_user
	NULL,                                           // send_attention
	NULL,                                           // attention_types
	sizeof(PurplePluginProtocolInfo),               // struct_size
    mra_get_account_text_table,                     // get_account_text_table
    NULL,                                           // initiate_media
#if PURPLE_MAJOR_VERSION >= 2 && PURPLE_MINOR_VERSION >= 7
    NULL,                                           // can_do_media
    NULL,						                    // get_moods
    NULL,						                    // set_public_alias
    NULL						                    // get_public_alias
#else
    NULL                                            // can_do_media
#endif
};

/**************************************************************************************************
    Initialize plugin
**************************************************************************************************/
static void plugin_init(PurplePlugin *plugin)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    this_plugin = plugin;

//  initialize variables and structs
	PurpleAccountOption *option;
	PurplePluginInfo *info = plugin->info;
	PurplePluginProtocolInfo *prpl_info = info->extra_info;

//  user defined variable: server to connect (mrim14.mail.ru)
	option = purple_account_option_string_new(_("Server"), "host", MRA_HOST);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);

//  user defined variable: port to connect (2041)
	option = purple_account_option_int_new(_("Port"), "port", MRA_PORT);
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);

//  auto generated device id
	option = purple_account_option_string_new(_("Device ID"), "dev_id", "");
	prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);
}

/**************************************************************************************************
    Info about plugin
**************************************************************************************************/
static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,                            // purple plugin magic
	PURPLE_MAJOR_VERSION,                           // major version of purple
	PURPLE_MINOR_VERSION,                           // minor version of purple
	PURPLE_PLUGIN_PROTOCOL,                         // type
	NULL,                                           // ui_requirement
	0,                                              // flags
	NULL,                                           // dependencies
	PURPLE_PRIORITY_DEFAULT,                        // priority
	"prpl-mra",                                     // id
	"Mail.ru Agent",                                // name
	"0.1",                                          // version
	"Connects to the Mail.ru Agent protocol",       // summary
	"Connects to the Mail.ru Agent protocol",       // description
	"Vladimir Rudnyh <dreadatour@mail.ru>",         // author
	"http://agent.mail.ru/",                        // homepage
	plugin_load,                                    // load
	plugin_unload,                                  // unload
	NULL,                                           // destroy
	NULL,                                           // ui_info
	&prpl_info,                                     // extra_info
	NULL,                                           // prefs_info
	mra_actions,                                    // actions
	NULL,                                           // padding
	NULL,
	NULL,
	NULL
};

//  and now we will go and initialize our plugin
PURPLE_INIT_PLUGIN(mra, plugin_init, info);

