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

#include "libmra.h"

/////////////////////////////////////XXX///////////////////////////////////////////////////////////
#define LPS_DEBUG(c, s) (unsigned char) c[s+3], (unsigned char) c[s+2], (unsigned char) c[s+1], (unsigned char) c[s]
char *debug_data(char *data, int len) {
    int i;
    char *buffer;
    
    if (!data || len == 0) 
        return "error";

    if (len < 44) {
        buffer = (char * ) malloc(2 * len + 1);
        for (i = 0; i < len; i++) {
            sprintf(buffer + 2 * i + 8, "%02x", (unsigned char) data[i]);
        }
    } else {
        buffer = (char * ) malloc(2 * len + 9);
        sprintf(buffer,      "%02x%02x%02x%02x-", LPS_DEBUG(data, 0));  // magic
        sprintf(buffer + 9,  "%02x%02x%02x%02x-", LPS_DEBUG(data, 4));  // proto
        sprintf(buffer + 18, "%02x%02x%02x%02x-", LPS_DEBUG(data, 8));  // seq
        sprintf(buffer + 27, "%02x%02x%02x%02x-", LPS_DEBUG(data, 12)); // msg
        sprintf(buffer + 36, "%02x%02x%02x%02x-", LPS_DEBUG(data, 16)); // dlen
        sprintf(buffer + 45, "%02x%02x%02x%02x-", LPS_DEBUG(data, 20)); // from
        sprintf(buffer + 54, "%02x%02x%02x%02x ", LPS_DEBUG(data, 24)); // fromport
        for (i = 0; i < len - 44; i++)
            sprintf(buffer + 2 * i + 63, "%02x", (unsigned char) data[44 + i]);
    }
    return buffer;
}
char *debug_plain(char *data, int len) {
    int i;
    char *buffer;
    
    if (!data || len == 0) 
        return "error";

    buffer = (char * ) malloc(2 * len + 1);
    for (i = 0; i < len; i++) {
        sprintf(buffer + 2 * i, "%02x", (unsigned char) data[i]);
    }
    return buffer;
}
/////////////////////////////////////XXX///////////////////////////////////////////////////////////

/**************************************************************************************************
    Check pointer
**************************************************************************************************/
char *check_p(gpointer data, char *p, char *m, char type)
{
    mra_serv_conn *mmp = data;
    unsigned int diff = m - p;
    if ((type != 'u' && type != 's' && type != 'z') || (type != 'z' && diff < sizeof(u_int))) {
        purple_debug_info("mra", "[%s] Can't parse data\n", __func__);          /* FIXME */
        purple_connection_error_reason(mmp->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Can't parse incoming data"));
        mra_close(mmp->gc);
        return NULL;
    }
    if (type == 'u') {
        return p + sizeof(u_int);
    } else if (type == 's') {
        return p + LPSLENGTH(p) + sizeof(u_int);
    } else {
        while (p < m) {
            if (*(p++)=='\0') {
                return p;
            }
        }
    }
    return NULL;
}

/**************************************************************************************************
    Convert cp1251 string to utf8
**************************************************************************************************/
char *cp1251_to_utf8(const char *text) 
{
    gsize br = strlen(text);
    gsize bw = br * 2;
    GError *err = NULL;
    gchar *res;
    char *conv;
    const char *p;
    char *q;

    conv = g_malloc0(strlen(text) + 1);
    for (p = text, q = conv; *p; p++) {
        *q++ = *p;
    }
    res = g_convert(conv, strlen(conv), "UTF-8", "WINDOWS-1251", &br, &bw, &err);
    if(!res) {
        purple_debug_info("mra", "[%s] Covertion CP1251->UTF8 failed: %s\n", 
                          __func__, err->message);                                      /* FIXME */
        return conv;
    }
    g_free(conv);
    return res;
}

/**************************************************************************************************
    Convert utf8 string to  cp1251
**************************************************************************************************/
char *utf8_to_cp1251(const char *text)
{
    gsize br = strlen(text);
    gsize bw = br * 2; 
    GError *err = NULL;
    char *conv;

    conv = g_convert(text, strlen(text), "WINDOWS-1251", "UTF-8", &br, &bw, &err);
    if(!conv) {
        purple_debug_info("mra", "[%s] Covertion UTF8->CP1251 failed: %s\n", 
                          __func__, err->message);                                      /* FIXME */
        return g_strdup(text);
    }    
    return conv;
}

/**************************************************************************************************
    Add '\r' before '\n'
**************************************************************************************************/
char *to_crlf(const char *text)
{
    int n = 0; 
    const gchar *   p;   
    gchar * res; 
    gchar * r; 

    for (p = text; *p; p++) {
        if(*p == '\n' && *(p - 1) != '\r') n++; 
    }    
    res = (gchar *) g_malloc0(strlen(text) + n + 1);
    for (p = text, r = res; *p; p++) {
        if (*p == '\n' && *(p - 1) != '\r') {
            *r++ = '\r';
        }    
        *r++ = *p;
    }    
    return res; 
}

/**************************************************************************************************
    Convert string to LPS
**************************************************************************************************/
char *mra_net_mklps(const char *sz)
{
    unsigned int len;
    char *lps = LPSALLOC(strlen(sz));

    len = strlen(sz);
    *((unsigned int *)lps) = len;
    memcpy(lps + sizeof(unsigned int), sz, strlen(sz));
    return lps;
}

/**************************************************************************************************
    Convert LPS to string
**************************************************************************************************/
char *mra_net_mksz(char *lps)
{
    unsigned int len;
    char *sz = (char *) malloc(1 + LPSLENGTH(lps));
                         
    len = *((unsigned int *)lps);
    memcpy(sz, lps + sizeof(unsigned int), len);
    *(sz + len) = 0;
    return sz;
}

/**************************************************************************************************
    Fill client->server header
**************************************************************************************************/
void mra_net_fill_cs_header(mrim_packet_header_t *head, u_int seq, u_int msg, u_int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    head->proto    = PROTO_VERSION;
    head->magic    = CS_MAGIC;
    head->seq      = seq;
    head->msg      = msg;
    head->dlen     = len;
    head->from     = 0;
    head->fromport = 0;
}

/**************************************************************************************************
    Add data to output buffer
**************************************************************************************************/
void mra_net_send(gpointer conn, gpointer data, u_int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */
    
    mra_serv_conn *mmp = conn;
    if(!len || !data) return;
    mmp->tx_buf = (char *) g_realloc(mmp->tx_buf, mmp->tx_len + len);
    memcpy(mmp->tx_buf + mmp->tx_len, data, len);
    mmp->tx_len += len;
}

/**************************************************************************************************
    Send all data to server and clear buffer
**************************************************************************************************/
gboolean mra_net_send_flush(gpointer conn)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */
    
    int ret = 0;
    mra_serv_conn *mmp = conn;
    ret = write(mmp->fd, mmp->tx_buf, mmp->tx_len);
    purple_debug_info("mra", "[%s] bytes sent: %d\n", __func__, ret);                   /* FIXME */
    purple_debug_info("mra", "send: %s\n", debug_data(mmp->tx_buf, mmp->tx_len));       /* FIXME */
    if (ret < 0) {
        return FALSE;
    } else {
        mmp->tx_buf = '\0';
        mmp->tx_len = 0;
        return TRUE;
    }
}

/**************************************************************************************************
    Ping timer callback
**************************************************************************************************/
gboolean mra_net_ping_timeout_cb(mra_serv_conn *mmp)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */
    if (mra_net_send_ping(mmp))
        return TRUE;
    else
        return FALSE;
}

/**************************************************************************************************
    Send 'ping' packet
**************************************************************************************************/
gboolean mra_net_send_ping(mra_serv_conn *mmp)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mrim_packet_header_t head;

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_PING, 0);
    mra_net_send(mmp, &head, sizeof(head));
    return mra_net_send_flush(mmp);
}

/**************************************************************************************************
    Send 'hello' packet
**************************************************************************************************/
gboolean mra_net_send_hello(mra_serv_conn *mmp)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mrim_packet_header_t head;

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_HELLO, 0);
    mra_net_send(mmp, &head, sizeof(head));
    return mra_net_send_flush(mmp);
}

/**************************************************************************************************
    Send 'authentificate' packet
**************************************************************************************************/
gboolean mra_net_send_auth(mra_serv_conn *mmp, const char *username, const char *password, unsigned int status)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mrim_packet_header_t head;
    char *username_lps;
    char *password_lps;
    char *desc_lps;
    unsigned int dw = 0;
    int i;
    gboolean ret = FALSE;
    
    // convert username, password and desc to LPS
    username_lps = mra_net_mklps(username);
    password_lps = mra_net_mklps(password);
    desc_lps     = mra_net_mklps(VERSION_TXT);

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_LOGIN2, LPSSIZE(username_lps) + LPSSIZE(password_lps) + LPSSIZE(desc_lps) + sizeof(unsigned int) * 6);
    mra_net_send(mmp, &head,        sizeof(head));
    mra_net_send(mmp, username_lps, LPSSIZE(username_lps));
    mra_net_send(mmp, password_lps, LPSSIZE(password_lps));
    mra_net_send(mmp, &status,      sizeof(status));
    mra_net_send(mmp, desc_lps,     LPSSIZE(desc_lps));
    for (i = 0; i < 5; i++) {
        mra_net_send(mmp, &dw,          sizeof(dw));
    }
    ret = mra_net_send_flush(mmp);

    g_free(username_lps);
    g_free(password_lps);
    g_free(desc_lps);
    
    return ret;
}

/**************************************************************************************************
    Send 'receive ack' packet
**************************************************************************************************/
gboolean mra_net_send_receive_ack(mra_serv_conn *mmp, char *from, unsigned int msg_id)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mrim_packet_header_t head;
    char *from_lps = mra_net_mklps(from);
    gboolean ret = FALSE;

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_MESSAGE_RECV, LPSSIZE(from_lps) + sizeof(msg_id));
    mra_net_send(mmp, &head,    sizeof(head));
    mra_net_send(mmp, from_lps, LPSSIZE(from_lps));
    mra_net_send(mmp, &msg_id,  sizeof(msg_id));
    ret = mra_net_send_flush(mmp);
    
    g_free(from_lps);

    return ret;
}

/**************************************************************************************************
    Send 'message' packet
**************************************************************************************************/
gboolean mra_net_send_message(mra_serv_conn *mmp, const char *to, const char *message, u_int flags)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mrim_packet_header_t head;
    char *to_lps;
    char *message_lps;
    char *message_rtf_lps;
    gboolean ret = FALSE;

    to_lps = mra_net_mklps(to);
    message_lps = mra_net_mklps(to_crlf(utf8_to_cp1251(message)));
    message_rtf_lps = mra_net_mklps(to_crlf(utf8_to_cp1251(g_strdup(" "))));

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_MESSAGE, sizeof(u_int) + LPSSIZE(to_lps) + LPSSIZE(message_lps) + LPSSIZE(message_rtf_lps));
    mra_net_send(mmp, &head,  sizeof(head));
    mra_net_send(mmp, &flags, sizeof(flags));
    mra_net_send(mmp, to_lps, LPSSIZE(to_lps));
    mra_net_send(mmp, message_lps, LPSSIZE(message_lps));
    mra_net_send(mmp, message_rtf_lps, LPSSIZE(message_rtf_lps));
    ret = mra_net_send_flush(mmp);

    g_free(to_lps);
    g_free(message_lps);
    g_free(message_rtf_lps);

    return ret;
}

/**************************************************************************************************
    Send 'typing' packet
**************************************************************************************************/
gboolean mra_net_send_typing(mra_serv_conn *mmp, const char *to) 
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mrim_packet_header_t head;
    char *to_lps;
    char *message_lps;
    char *message_rtf_lps;
    u_int flags = MESSAGE_FLAG_NOTIFY;
    gboolean ret = FALSE;

    to_lps = mra_net_mklps(to);
    message_lps = mra_net_mklps(to_crlf(utf8_to_cp1251(" ")));
    message_rtf_lps = mra_net_mklps(to_crlf(utf8_to_cp1251(" ")));

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_MESSAGE, sizeof(u_int) + LPSSIZE(to_lps) + LPSSIZE(message_lps) + LPSSIZE(message_rtf_lps));
    mra_net_send(mmp, &head,  sizeof(head));
    mra_net_send(mmp, &flags, sizeof(flags));
    mra_net_send(mmp, to_lps, LPSSIZE(to_lps));
    mra_net_send(mmp, message_lps, LPSSIZE(message_lps));
    mra_net_send(mmp, message_rtf_lps, LPSSIZE(message_rtf_lps));
    ret = mra_net_send_flush(mmp);

    g_free(to_lps);
    g_free(message_lps);
    g_free(message_rtf_lps);

    return ret;
}

/**************************************************************************************************
    Send 'remove offline message' packet
**************************************************************************************************/
gboolean mra_net_send_delete_offline(mra_serv_conn *mmp, char *uidl)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */
    
    mrim_packet_header_t head;

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_DELETE_OFFLINE_MESSAGE, 8);
    mra_net_send(mmp, &head,  sizeof(head));
    mra_net_send(mmp, uidl, 8);
    return mra_net_send_flush(mmp);
}

/**************************************************************************************************
    Send 'auth request accepted' packet
**************************************************************************************************/
gboolean mra_net_send_authorize_user(mra_serv_conn *mmp, char *email)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */
    
    mrim_packet_header_t head;
    char *email_lps;
    gboolean ret = FALSE;
    
    purple_debug_info("mra", "[%s] email: %s\n", __func__, email);                      /* FIXME */
    
    email_lps = mra_net_mklps(email);

    mra_net_fill_cs_header(&head, ++mmp->seq, MRIM_CS_AUTHORIZE, LPSSIZE(email_lps));
    mra_net_send(mmp, &head,  sizeof(head));
    mra_net_send(mmp, email_lps, LPSSIZE(email_lps));
    ret = mra_net_send_flush(mmp);

    g_free(email_lps);

    return ret;
}

/**************************************************************************************************
    Send 'add user into contact list' packet
**************************************************************************************************/
gboolean mra_net_send_add_user(mra_serv_conn *mmp, char *email, char *name, u_int group_id, u_int flags)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */
    
    mrim_packet_header_t head;
    char *email_lps;
    char *name_lps;
    char *zero_lps;
    gboolean ret = FALSE;

    email_lps = mra_net_mklps(email);
    name_lps  = mra_net_mklps(utf8_to_cp1251(name));
    zero_lps  = mra_net_mklps(" ");

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_ADD_CONTACT, sizeof(flags) + sizeof(group_id) + LPSSIZE(email_lps) + LPSSIZE(name_lps) + LPSSIZE(zero_lps));
    mra_net_send(mmp, &head,  sizeof(head));
    mra_net_send(mmp, &flags, sizeof(flags));
    mra_net_send(mmp, &group_id, sizeof(group_id));
    mra_net_send(mmp, email_lps, LPSSIZE(email_lps));
    mra_net_send(mmp, name_lps, LPSSIZE(name_lps));
    mra_net_send(mmp, zero_lps, LPSSIZE(zero_lps));
    ret = mra_net_send_flush(mmp);

    g_free(email_lps);
    g_free(name_lps);
    g_free(zero_lps);

    return ret;
}

/**************************************************************************************************
    Send 'change user' packet
**************************************************************************************************/
gboolean mra_net_send_change_user(mra_serv_conn *mmp, unsigned int user_id, unsigned int group_id, char *email, char *name, unsigned int flags)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */
    
    mrim_packet_header_t head;
    char *email_lps;
    char *name_lps;
    char *zero_lps;
    gboolean ret = FALSE;

    email_lps = mra_net_mklps(email);
    name_lps  = mra_net_mklps(utf8_to_cp1251(name));
    zero_lps  = mra_net_mklps(" ");

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_MODIFY_CONTACT, sizeof(user_id) + sizeof(flags) + sizeof(group_id) + LPSSIZE(email_lps) + LPSSIZE(name_lps) + LPSSIZE(zero_lps));
    mra_net_send(mmp, &head,  sizeof(head));
    mra_net_send(mmp, &user_id, sizeof(user_id));
    mra_net_send(mmp, &flags, sizeof(flags));
    mra_net_send(mmp, &group_id, sizeof(group_id));
    mra_net_send(mmp, email_lps, LPSSIZE(email_lps));
    mra_net_send(mmp, name_lps, LPSSIZE(name_lps));
    mra_net_send(mmp, zero_lps, LPSSIZE(zero_lps));
    ret = mra_net_send_flush(mmp);

    g_free(email_lps);
    g_free(name_lps);
    g_free(zero_lps);

    return ret;
}

/**************************************************************************************************
    Send 'set status' packet
**************************************************************************************************/
gboolean mra_net_send_status(mra_serv_conn *mmp, unsigned int status)
{
    purple_debug_info("mra", "== %s ==\n", __func__);                                   /* FIXME */

    mrim_packet_header_t head;

    mra_net_fill_cs_header(&head, mmp->seq++, MRIM_CS_CHANGE_STATUS, sizeof(status));
    mra_net_send(mmp, &head,    sizeof(head));
    mra_net_send(mmp, &status,  sizeof(status));
    return mra_net_send_flush(mmp);
}

/**************************************************************************************************
    Read data from socket
**************************************************************************************************/
void mra_net_read_cb(gpointer data, gint source, PurpleInputCondition cond)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(source);
    UNUSED(cond);
    
    mra_serv_conn *mmp = data;
    int len;
    char *buf;

    // increase buffer size
    mmp->rx_buf = g_realloc(mmp->rx_buf, mmp->rx_len + MRA_BUF_LEN + 1);
    
    // read data from socket
    buf = mmp->rx_buf + mmp->rx_len;
    len = read(mmp->fd, buf, MRA_BUF_LEN);
    mmp->rx_len = mmp->rx_len + len;
    
    purple_debug_info("mra", "[%s] bytes readed: %d\n", __func__, len);                 /* FIXME */
    purple_debug_info("mra", "read: %s\n", debug_data(mmp->rx_buf, len));               /* FIXME */

    if (len < 0 && errno == EAGAIN) {
        // read more
        return;
    } else if (len < 0) { 
        // connection was lost
        gchar *tmp = g_strdup_printf(_("Lost connection with server: %s"), g_strerror(errno));
        purple_connection_error_reason(mmp->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);
        return;
    } else if (len == 0) {
        // server closed the connection
        purple_connection_error_reason(mmp->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Server closed the connection"));
        return;
    }    

    // proceed received data while we can do it =)
    while (mra_net_read_proceed(mmp));
}

/**************************************************************************************************
    Proceed data from socket
**************************************************************************************************/
gboolean mra_net_read_proceed(gpointer data)
{
    purple_debug_info("mra", "== %s ==\n", __func__);
    
    mra_serv_conn *mmp = data;
    mrim_packet_header_t *head;
    unsigned int packet_len = 0;
    char *answer;
    char *next_packet;

    // return if no data
    if (mmp->rx_len == 0) {
        return FALSE;
    }
    
    // check if data length in input buffer is greater, than MRIM packet header size
    if (mmp->rx_len < sizeof(mrim_packet_header_t)) {
        purple_debug_info("mra", "[%s] need more data to procced\n", __func__);         /* FIXME */
        return FALSE;
    }
    
    // detach MRIM packet header from readed data
    head = (mrim_packet_header_t *) mmp->rx_buf;
        
    // check if we have correct magic
    if (head->magic != CS_MAGIC) {
        purple_debug_info("mra", "[%s] wrong magic: 0x%08x\n", 
                          __func__, (unsigned int) head->magic);                        /* FIXME */
        purple_debug_info("mra", "data: %s\n", debug_plain(mmp->rx_buf, mmp->rx_len));  /* FIXME */
        //TODO: we need to cut wrong data from input buffer here
        purple_connection_error_reason(mmp->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Received data is not MRIM packet"));
        return FALSE;
    }

    packet_len = sizeof(mrim_packet_header_t) + head->dlen;
        
    purple_debug_info("mra", "[%s] received packet is 0x%08x (length: %d, buf len: %d)\n", 
                  __func__, (unsigned int) head->msg, packet_len, mmp->rx_len);         /* FIXME */
    
    purple_debug_info("mra", "read: %s\n", debug_data(mmp->rx_buf, packet_len));        /* FIXME */

    // check if we received full packet
    if (mmp->rx_len < packet_len) {
        purple_debug_info("mra", "[%s] need more data to procced\n", __func__);         /* FIXME */
        return FALSE;
    }

    // get answer value
    answer = mmp->rx_buf + sizeof(mrim_packet_header_t);

    // proceed packet
    switch(head->msg) {
        case MRIM_CS_HELLO_ACK:
            // 'hello' packet
            mra_net_read_hello(mmp, answer, head->dlen);
            break;
        case MRIM_CS_LOGIN_ACK:
            // 'login successful' packet
            mra_net_read_login_successful(mmp, answer, head->dlen);
            break;
        case MRIM_CS_LOGIN_REJ:
            // 'login failed' packet
            mra_net_read_login_failed(mmp, answer, head->dlen);
            break;
        case MRIM_CS_LOGOUT:
            // 'logout' packet
            mra_net_read_logout(mmp, answer, head->dlen);
            break;
        case MRIM_CS_USER_INFO:
            // 'user info' packet
            mra_net_read_user_info(mmp, answer, head->dlen);
            break;
        case MRIM_CS_CONTACT_LIST2:
            // 'contact list' packet
            mra_net_read_contact_list(mmp, answer, head->dlen);
            break;
        case MRIM_CS_USER_STATUS:
            // 'user change status' packet
            mra_net_read_user_status(mmp, answer, head->dlen);
            break;
        case MRIM_CS_MESSAGE_ACK:
            // 'receive message' packet
            mra_net_read_message(mmp, answer, head->dlen);
            break;
        case MRIM_CS_OFFLINE_MESSAGE_ACK:
            // 'receive offline message' packet
            mra_net_read_message_offline(mmp, answer, head->dlen);
            break;
        case MRIM_CS_ADD_CONTACT_ACK:
            // 'add new contact ack' packet
            mra_net_read_add_contact_ack(mmp, answer, head->dlen);
            break;
        case MRIM_CS_AUTHORIZE_ACK:
            // 'add new user auth request ack' packet
            mra_net_read_auth_ack(mmp, answer, head->dlen);
            break;
        default:
            // unknown packet
            purple_debug_info("mra", "[%s] packet type is unknown\n", __func__);        /* FIXME */
    }

    // if we have more data in incoming buffer
    if (mmp->rx_len > packet_len) {
        // cut proceeded packet
        purple_debug_info("mra", "[%s] rx_len is %d\n", __func__, mmp->rx_len);         /* FIXME */
        purple_debug_info("mra", "[%s] packet_len is %d\n", __func__, packet_len);      /* FIXME */
        next_packet = mmp->rx_buf + packet_len;
        mmp->rx_len = mmp->rx_len - packet_len;
        purple_debug_info("mra", "[%s] rx_len is %d now\n", __func__, mmp->rx_len);     /* FIXME */
        memmove(mmp->rx_buf, next_packet, mmp->rx_len);
        mmp->rx_buf = g_realloc(mmp->rx_buf, mmp->rx_len);                              /*  XXX  */
        purple_debug_info("mra", "[%s] where are data in buffer left: %d\n", 
                          __func__, mmp->rx_len);                                       /* FIXME */
        return TRUE;
    } else {
        // else just empty buffer
        mmp->rx_len = 0;
        mmp->rx_buf = g_realloc(mmp->rx_buf, MRA_BUF_LEN + 1);                            /*  XXX  */
    }
    return FALSE;
}

/**************************************************************************************************
    Read 'hello' packet
**************************************************************************************************/
void mra_net_read_hello(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(len);

    mra_serv_conn *mmp = data;
    unsigned int ping_timeout;

    // get ping timeout value
    ping_timeout = *(unsigned int *) answer;
    
    // check if ping timeout value is correct
    if (ping_timeout <= 0 || ping_timeout > 3600) {
        purple_debug_info("mra", "[%s] wrong ping timeout value: %d\n",
                          __func__, ping_timeout);                                      /* FIXME */
        purple_connection_error_reason(mmp->gc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, _("Wrong ping interval value"));
        return;
    }

    purple_debug_info("mra", "[%s] %d\n", __func__, ping_timeout);                      /* FIXME */

    // start ping timer
    mmp->ping_timer = purple_timeout_add(ping_timeout * 1000, (GSourceFunc) mra_net_ping_timeout_cb, mmp);

    // 'hello' callback
    mmp->callback_hello(mmp);
}

/**************************************************************************************************
    Read 'login successful' packet
**************************************************************************************************/
void mra_net_read_login_successful(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(answer);
    UNUSED(len);

    mra_serv_conn *mmp = data;
    mmp->callback_login(mmp, MRA_LOGIN_SUCCESSFUL, NULL);
}

/**************************************************************************************************
    Read 'login failed' packet
**************************************************************************************************/
void mra_net_read_login_failed(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(len);

    mra_serv_conn *mmp = data;
    gchar *reason;
    
    reason = cp1251_to_utf8(mra_net_mksz(answer));

    mmp->callback_login(mmp, MRA_LOGIN_FAILED, reason);

    g_free(reason);
}

/**************************************************************************************************
    Read 'logout' packet
**************************************************************************************************/
void mra_net_read_logout(gpointer data, char *answer, int len)
{           
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(len);

    mra_serv_conn *mmp = data;
    gchar *reason;
    
    reason = cp1251_to_utf8(mra_net_mksz(answer));

    mmp->callback_logout(mmp, reason);

    g_free(reason);
}

/**************************************************************************************************
    Read 'user info' packet
**************************************************************************************************/
void mra_net_read_user_info(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);
    
    mra_serv_conn *mmp = data;
    mra_user_info *user_info = (mra_user_info *) malloc(sizeof(mra_user_info));
    char *key;
    char *val;

    while(len) {
        key     = mra_net_mksz(answer);
        len    -= LPSSIZE(answer);
        answer += LPSSIZE(answer);
        val   = mra_net_mksz(answer);
        len    -= LPSSIZE(answer);
        answer += LPSSIZE(answer);
        
        if (strcmp(key, "WEATHER.CITY") == 0) {
            user_info->weather_city = atol(val);
        } else if (strcmp(key, "MESSAGES.TOTAL") == 0) {
            user_info->messages_total = atol(val);
        } else if (strcmp(key, "MESSAGES.UNREAD") == 0) {
            user_info->messages_unread = atol(val);
        } else if (strcmp(key, "MRIM.NICKNAME") == 0) {
            user_info->mrim_nickname = g_strdup(val);
        } else if (strcmp(key, "client.endpoint") == 0) {
            user_info->client_endpoint = g_strdup(val);
        } else {
            purple_debug_info("mra", "[%s] WARNING! Unknown key. %s = %s\n",
                              __func__, key, val);                                      /* FIXME */
        }
    }

    mmp->callback_user_info(mmp, user_info);
}

/**************************************************************************************************
    Read 'contact list' packet
**************************************************************************************************/
void mra_net_read_contact_list(gpointer data, char *answer, int len)
{           
    purple_debug_info("mra", "== %s ==\n", __func__);
    
    mra_serv_conn *mmp = data;
    mra_group *groups = NULL;
    mra_contact *contacts = NULL;
    unsigned int i, j;
    char *p;
    unsigned int status;
    unsigned int groups_count;
    char *group_mask;
    char *contact_mask;
    const char *known_group_mask = "us";
    const char *known_contact_mask = "uussuu";
    u_int flags;
    u_int intflags;
    u_int user_status;
    char *name;
    char *email;
    int group_id;
    int group_cnt = 0;
    int contact_cnt = 0;

    p = answer;

    // get status of contact list loading
    status = LPSLENGTH(p);
    p += sizeof(u_int);
    purple_debug_info("mra", "[%s] contacts read status: %d\n", __func__, status);      /* FIXME */
    // return error to callback if something wrong
    if (status != GET_CONTACTS_OK) {
        mmp->callback_contact_list(mmp, status, 0, NULL, 0, NULL);
        return;
    }
    
    // get groups count
    check_p(mmp, p, answer, 'u');
    groups_count = LPSLENGTH(p);
    p += sizeof(u_int);
    purple_debug_info("mra", "[%s] groups count: %d\n", __func__, groups_count);        /* FIXME */
    
    // get group mask
    check_p(mmp, p, answer, 's');
    group_mask = mra_net_mksz(p);
    p += LPSLENGTH(p) + sizeof(u_int);
    purple_debug_info("mra", "[%s] group mask: %s\n", __func__, group_mask);            /* FIXME */

    // get contact mask
    check_p(mmp, p, answer, 's');
    contact_mask = mra_net_mksz(p);
    p += LPSLENGTH(p) + sizeof(u_int);
    purple_debug_info("mra", "[%s] contact mask: %s\n", __func__, contact_mask);        /* FIXME */

    // check if we know group and contact masks
    if (strncmp(contact_mask, known_contact_mask, strlen(known_contact_mask)) || strncmp(group_mask, known_group_mask, strlen(known_group_mask))) {        
        purple_debug_info("mra", "[%s] contact or group mask is unknown\n", __func__);  /* FIXME */
        mmp->callback_contact_list(mmp, GET_CONTACTS_INTERR, 0, NULL, 0, NULL);
        return;
    }

    // get all groups data
    for(i = 0; i < groups_count; i++) {
        // get group flags
        check_p(mmp, p, answer, 'u');
        flags = *(u_int *) p;
        p += sizeof(u_int);

        // get group name
        check_p(mmp, p, answer, 's');
        name = cp1251_to_utf8(mra_net_mksz(p));
        p += LPSLENGTH(p) + sizeof(u_int);

        // check all data
        j = strlen(known_group_mask);
        while (j < strlen(group_mask))
            p = check_p(mmp, p, answer, group_mask[j++]);

        purple_debug_info("mra", "[%s] group %s, flags: %08x\n", __func__, name, flags);/* FIXME */
        
        // push group into groups array if group is active
        flags &= 0x00FFFFFF;
        if(!(flags & CONTACT_FLAG_REMOVED)) {
            purple_debug_info("mra", "[%s] is enabled (id: %d)\n", __func__, i);        /* FIXME */
            groups = (mra_group *) g_realloc(groups, (group_cnt + 1) * sizeof(mra_group));
            groups[group_cnt].id = i;
            groups[group_cnt].name = g_strdup(name);
            groups[group_cnt].flags = flags;
            group_cnt++;
        }
    }

    // get all contacts data
    while (p < answer + len) {
        // get contact flags
        check_p(mmp, p, answer, 'u');
        flags = *(u_int *) p;
        p += sizeof(u_int);

        // get contact group
        check_p(mmp, p, answer, 'u');
        group_id = *(u_int *) p;
        p += sizeof(u_int);

        // get contact address
        check_p(mmp, p, answer, 's');
        email = mra_net_mksz(p);
        p += LPSLENGTH(p) + sizeof(u_int);

        // get contact nickname
        check_p(mmp, p, answer, 's');
        name = cp1251_to_utf8(mra_net_mksz(p));
        p += LPSLENGTH(p) + sizeof(u_int);

        // get contact internal flags
        check_p(mmp, p, answer, 'u');
        intflags = *(u_int *) p;
        p += sizeof(u_int);

        // get contact status
        check_p(mmp, p, answer, 'u');
        user_status = *(u_int *) p;
        p += sizeof(u_int);

        // check all data
        j = strlen(known_contact_mask);
        while (j < strlen(contact_mask))
            p = check_p(mmp, p, answer, contact_mask[j++]);
            
        purple_debug_info("mra", "[%s] contact %s (%s), flags: 0x%08x, group: %d, status: 0x%08x\n", 
                              __func__, name, email, flags, group_id, user_status);     /* FIXME */

        // push contact into contact array if contact is active
        if(!(flags & CONTACT_FLAG_REMOVED))
        {
            purple_debug_info("mra", "[%s] is enabled (id: %d)\n", 
                              __func__, contact_cnt + MAX_GROUP);                       /* FIXME */
            contacts = (mra_contact *) g_realloc(contacts, (contact_cnt + 1) * sizeof(mra_contact));
            contacts[contact_cnt].id = contact_cnt + MAX_GROUP;
            contacts[contact_cnt].email = g_strdup(email);
            contacts[contact_cnt].nickname = g_strdup(name);
            contacts[contact_cnt].flags = flags;
            contacts[contact_cnt].group_id = group_id;
            contacts[contact_cnt].intflags = intflags;
            contacts[contact_cnt].status = user_status;
            contact_cnt++;
        }   
        g_free(email);
        g_free(name);
    }   
    g_free(group_mask);
    g_free(contact_mask);

    mmp->callback_contact_list(mmp, status, group_cnt, groups, contact_cnt, contacts);
}

/**************************************************************************************************
    Read 'user status' packet
**************************************************************************************************/
void mra_net_read_user_status(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(len);
    
    mra_serv_conn *mmp = data;
    u_int status;
    char *email;

    // get status and email
    status = *(u_int *) answer;
    answer += sizeof(u_int);
    email = mra_net_mksz(answer);

    purple_debug_info("mra", "[%s] contact %s new status: 0x%08x\n", 
                      __func__, email, status);                                         /* FIXME */

    // callback for user status change
    mmp->callback_user_status(mmp, email, status);

    g_free(email);
}

/**************************************************************************************************
    Read 'message' packet
**************************************************************************************************/
void mra_net_read_message(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(len);
                
    mra_serv_conn *mmp = data;
    u_int msg_id;
    u_int flags;
    char *from;
    char *message;
    char *message_rtf;

    // parse data
    msg_id = *(u_int *) answer;
    answer += sizeof(u_int);
    flags = *(u_int *) answer;
    answer += sizeof(u_int);
    from = mra_net_mksz(answer);
    answer += LPSSIZE(answer);
    message = cp1251_to_utf8(mra_net_mksz(answer));
    message_rtf = mra_net_mksz(answer);

    purple_debug_info("mra", "[%s] message received from %s (flags: 0x%08x)\n", 
                      __func__, from, flags);                                           /* FIXME */
    purple_debug_info("mra", "[%s] message is: %s\n", __func__, message);               /* FIXME */

    // send receive ack if needed
    if (!(flags & MESSAGE_FLAG_NORECV)) {
        purple_debug_info("mra", "[%s] need to send receive ack\n", __func__);          /* FIXME */

        mra_net_send_receive_ack(mmp, from, msg_id);
    }

    // proceed message
    if (flags & MESSAGE_FLAG_AUTHORIZE) {
        // authorization request
        
        purple_debug_info("mra", "[%s] this is authorize request\n", __func__);         /* FIXME */
        
        mmp->callback_auth_request(mmp, from, message);
    } else if (flags & MESSAGE_FLAG_SYSTEM) {
        // system message

        purple_debug_info("mra", "[%s] this is system message\n", __func__);            /* FIXME */

        mmp->callback_message(mmp, from, message, message_rtf, time(NULL), MRA_MESSAGE_TYPE_SYSTEM);
    } else if (flags & MESSAGE_FLAG_CONTACT) {
        // contacts list
        
        purple_debug_info("mra", "[%s] this is contacts list\n", __func__);             /* FIXME */

        mmp->callback_message(mmp, from, message, message_rtf, time(NULL), MRA_MESSAGE_TYPE_CONTACTS);
    } else if (flags & MESSAGE_FLAG_NOTIFY) {
        // typing notify

        purple_debug_info("mra", "[%s] this is typing notify\n", __func__);             /* FIXME */

        mmp->callback_typing_notify(mmp, from);
    } else {
        // casual message
        
        purple_debug_info("mra", "[%s] this is just a message\n", __func__);            /* FIXME */

        mmp->callback_message(mmp, from, message, message_rtf, time(NULL), MRA_MESSAGE_TYPE_MESSAGE);
    }

    g_free(from);
    g_free(message);
    g_free(message_rtf);
}

/**************************************************************************************************
    Read 'message offline' packet
**************************************************************************************************/
void mra_net_read_message_offline(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(len);
                
    mra_serv_conn *mmp = data;
    char *text;
    char uidl[8];
    char *message;
    char message_rtf[1] = " ";
    char *p;
    char *from;
    char *date;
    char *sflags;
    char *boundary;
    u_int flags;
    struct tm tm;
    time_t time;
    char *oldlocale;

    from = (char *) g_malloc0(190);
    date = (char *) g_malloc0(190);
    sflags = (char *) g_malloc0(190);
    boundary = (char *) g_malloc0(190);

    memcpy(uidl, answer, 8);
    text = mra_net_mksz(answer + 8);
    p = text;

    while (*p) {
        if (strncmp(p, "From:", 5) == 0) {
            strncpy(from, p + 6, strchr(p, '\n') - p - 6);
            purple_debug_info("mra", "[%s] from: %s\n", __func__, from);
        }    
        if (strncmp(p, "Date:", 5) == 0) {
            strncpy(date, p + 6, strchr(p, '\n') - p - 6);
            purple_debug_info("mra", "[%s] date: %s\n", __func__, date);
        }    
        if (strncmp(p, "X-MRIM-Flags:", 13) == 0) {
            strncpy(sflags, p + 14, strchr(p, '\n') - p - 14); 
            purple_debug_info("mra", "[%s] flags: %s\n", __func__, sflags);
        }    
        if (strncmp(p, "Boundary:", 9) == 0) {
            strcpy(boundary, "\n--");
            strncpy(boundary + 3, p + 10, strchr(p, '\n') - p - 10); 
            strcat(boundary, "--");
            purple_debug_info("mra", "[%s] boundary: %s\n", __func__, boundary);
        }    
        if (strncmp(p, "\n", 1) == 0)
        {    
            p++; 
            break;
        }    
        p = strchr(p, '\n') + 1;
    }    

    if (sscanf(sflags, "%X", &flags) != 1) {
        flags = 0;
    }
    purple_debug_info("mra", "[%s] parsed flags: 0x%08x\n", __func__, flags);

    oldlocale = setlocale(LC_TIME, NULL);
    setlocale(LC_TIME, "C");
    strptime(date, "%a, %d %b %Y %H:%M:%S", &tm);
    setlocale(LC_TIME, oldlocale);
    time = mktime(&tm);
        
    purple_debug_info("mra", "[%s] time: %d\n", __func__, (u_int) time);

    if(!p) {
        purple_debug_info("mra", "[%s] invalid message!\n", __func__);
        return;
    }    

    message = p; 
    p = strstr(message, boundary);
    if (p) {
        *p = '\0';
    }
    message = cp1251_to_utf8(message);

    purple_debug_info("mra", "[%s] message received from %s (flags: 0x%08x)\n", 
                      __func__, from, flags);                                           /* FIXME */
    purple_debug_info("mra", "[%s] message is: %s\n", __func__, message);               /* FIXME */

    if (flags & MESSAGE_FLAG_AUTHORIZE) {
        // authorization request
        
        purple_debug_info("mra", "[%s] this is authorize request\n", __func__);         /* FIXME */
        
        mmp->callback_auth_request(mmp, from, message);
    } else {
        // message
        
        purple_debug_info("mra", "[%s] this is offline message\n", __func__);           /* FIXME */

        mmp->callback_message(mmp, from, message, message_rtf, time, MRA_MESSAGE_TYPE_MESSAGE);
    }

    g_free(text);
    g_free(message);
    g_free(from);
    g_free(date);
    g_free(sflags);
    g_free(boundary);

    mra_net_send_delete_offline(mmp, uidl);
}

/**************************************************************************************************
    Read 'add new contact ack' packet
**************************************************************************************************/
void mra_net_read_add_contact_ack(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(data);
    UNUSED(answer);
    UNUSED(len);
                
    purple_debug_info("mra", "[%s] contact add ack received\n", __func__);              /* FIXME */
}
            
/**************************************************************************************************
    Read 'add new contact ack' packet
**************************************************************************************************/
void mra_net_read_auth_ack(gpointer data, char *answer, int len)
{
    purple_debug_info("mra", "== %s ==\n", __func__);

    UNUSED(data);
    UNUSED(answer);
    UNUSED(len);
                
    purple_debug_info("mra", "[%s] add contact auth ack received\n", __func__);              /* FIXME */
}

