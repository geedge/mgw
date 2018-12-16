#include "mgw_utils.h"
#include "dnat.h"
#include "ip_mgr.h"

struct dnat_handle
{
    void *logger;
    struct ip_mgr_handle *_ip_mgr_handle;
    MESA_htable_handle dnat_rx_htable;
    MESA_htable_handle dnat_tx_htable;
};


struct dnat_tx_htable_value
{
    struct mgw_utils_sess sess;
    uint32_t mrl_ip;
};

static struct field_stat_handle *g_fs_handle = NULL;

static void dnat_rx_htable_data_free_cb(void *data)
{
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_rx, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    FREE(&data);
}

static void dnat_tx_htable_data_free_cb(void *data)
{
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_tx, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    FREE(&data);
}


struct dnat_handle * dnat_init(const char *profile, struct ip_mgr_handle *_ip_mgr_handle, struct field_stat_handle *fs_handle, void *logger)
{
    struct dnat_handle *handle = ALLOC(struct dnat_handle, 1);
    handle->logger = logger;
    handle->_ip_mgr_handle = _ip_mgr_handle;
    handle->dnat_rx_htable = mgw_utils_create_htable(profile, "dnat_rx_htable", (void *)dnat_rx_htable_data_free_cb, NULL, logger);
    handle->dnat_tx_htable = mgw_utils_create_htable(profile, "dnat_tx_htable", (void *)dnat_tx_htable_data_free_cb, NULL, logger);
    g_fs_handle = fs_handle;
    return handle;
}

void dnat_destroy(struct dnat_handle *handle)
{
    MESA_htable_destroy(handle->dnat_rx_htable, NULL);
    MESA_htable_destroy(handle->dnat_tx_htable, NULL);
    FREE(&handle);
}

static long dnat_rx_htable_query_cb(void *data, const uchar *key, uint size, void *user_arg)
{
    struct mgw_utils_sess *dup_value = (struct mgw_utils_sess *)user_arg;
    if(data != NULL)
    {
        struct mgw_utils_sess *_data = (struct mgw_utils_sess *)data;
        dup_value->proto = _data->proto;
        dup_value->sip = _data->sip;
        dup_value->sport = _data->sport;
        dup_value->dip = _data->dip;
        dup_value->dport = _data->dport;
        return MGW_HTABLE_KEY_EXISTED;
    }
    else
    {
        return MGW_HTABLE_KEY_NOT_EXISTED;
    }
}

static long dnat_tx_htable_query_cb(void *data, const uchar *key, uint size, void *user_arg)
{
    struct dnat_tx_htable_value *dup_value = (struct dnat_tx_htable_value *)user_arg;
    if(data != NULL)
    {
        struct dnat_tx_htable_value *_data = (struct dnat_tx_htable_value *)data;
        dup_value->sess.proto = _data->sess.proto;
        dup_value->sess.sip = _data->sess.sip;
        dup_value->sess.sport = _data->sess.sport;
        dup_value->sess.dip = _data->sess.dip;
        dup_value->sess.dport = _data->sess.dport;
        dup_value->mrl_ip = _data->mrl_ip;
        return MGW_HTABLE_KEY_EXISTED;
    }
    else
    {
        return MGW_HTABLE_KEY_NOT_EXISTED;
    }
}


int dnat_tx_convert(struct dnat_handle *handle, char *buff, int len, uint32_t *mrl_ip)
{
    printf("dnat_tx_convert!\n");
    void *logger = handle->logger;
    //get session
    struct mgw_utils_sess *dnat_tx_key = ALLOC(struct mgw_utils_sess, 1);
    int rtn = mgw_utils_pkt_sess_parse(buff, len, dnat_tx_key);
    if(rtn == -1)
    {
        FREE(&dnat_tx_key);
        MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
        return MGW_DROP;
    }
    char dnat_tx_key_str[MGW_SYMBOL_MAX];
    char dnat_tx_value_str[MGW_SYMBOL_MAX];
    mgw_utils_sess_to_str(dnat_tx_key, dnat_tx_key_str);
    //query dnat_tx_htable
    long cb_rtn = -1;
    struct dnat_tx_htable_value dnat_tx_dup_value;
    MESA_htable_search_cb(handle->dnat_tx_htable, (const unsigned char *)(dnat_tx_key), sizeof(struct mgw_utils_sess), dnat_tx_htable_query_cb,
                                         (void *)(&dnat_tx_dup_value), &cb_rtn);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_tx, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    FREE(&dnat_tx_key);
    if(cb_rtn == MGW_HTABLE_KEY_EXISTED)
    {
        //replace
        FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_tx, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        mgw_utils_pkt_sess_replace(buff, len, &(dnat_tx_dup_value.sess));
        *mrl_ip = dnat_tx_dup_value.mrl_ip;
        mgw_utils_sess_to_str(&(dnat_tx_dup_value.sess), dnat_tx_value_str);
        MGW_LOG_INFO(logger, "Succeed at dnat_tx_convert: %s ---> %s", dnat_tx_key_str, dnat_tx_value_str);
        return MGW_FORWORD;
    }
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_tx, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
    return MGW_BYPASS;
}

int dnat_rx_convert(struct dnat_handle *handle, char *buff, int len)
{
    void *logger = handle->logger;
    //get session
    struct mgw_utils_sess *dnat_rx_key = ALLOC(struct mgw_utils_sess, 1);
    int rtn = mgw_utils_pkt_sess_parse(buff, len, dnat_rx_key);
    if(rtn == -1)
    {
        FREE(&dnat_rx_key);
        MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
        return MGW_DROP;
    }
    char dnat_rx_key_str[MGW_SYMBOL_MAX];
    char dnat_rx_value_str[MGW_SYMBOL_MAX];
    char dnat_tx_key_str[MGW_SYMBOL_MAX];
    char dnat_tx_value_str[MGW_SYMBOL_MAX];
    mgw_utils_sess_to_str(dnat_rx_key, dnat_rx_key_str);
    //query dnat_rx_htable
    long cb_rtn = -1;
    struct mgw_utils_sess dnat_rx_dup_value;
    MESA_htable_search_cb(handle->dnat_rx_htable, (const unsigned char *)(dnat_rx_key), sizeof(struct mgw_utils_sess), dnat_rx_htable_query_cb,
                                         (void *)(&dnat_rx_dup_value), &cb_rtn);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_rx, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    if(cb_rtn == MGW_HTABLE_KEY_EXISTED)
    {
        //replace
        FREE(&dnat_rx_key);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_rx, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        mgw_utils_pkt_sess_replace(buff, len, &dnat_rx_dup_value);
        mgw_utils_sess_to_str(&dnat_rx_dup_value, dnat_rx_value_str);
        MGW_LOG_INFO(logger, "Succeed at dnat_rx_convert: %s ---> %s", dnat_rx_key_str, dnat_rx_value_str);
        return MGW_FORWORD;
    }
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_rx, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
    uint32_t trans_ip;
    uint16_t trans_port;
    char orig_ip_str[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(dnat_rx_key->dip, orig_ip_str);
    //query dnat_policy
    rtn = ip_mgr_dnat_policy_query(handle->_ip_mgr_handle, dnat_rx_key->dip, dnat_rx_key->dport, &trans_ip, &trans_port);
    if(rtn < 0)
    {
        MGW_LOG_ERROR(logger, "Failed at dnat_rx_convert: policy not found, original dest is <%s, %d>", orig_ip_str, ntohs(dnat_rx_key->dport));
        FREE(&dnat_rx_key);
        return MGW_DROP;
    }
    //query mrl_ip
    uint32_t mrl_ip;
    rtn = ip_mgr_mrl_ip_query(handle->_ip_mgr_handle, dnat_rx_key->dip, &mrl_ip);
    if(rtn < 0)
    {
        MGW_LOG_ERROR(logger, "Failed at dnat_rx_convert: mrl_ip not found, original dest is <%s, %d>", orig_ip_str, ntohs(dnat_rx_key->dport));
        FREE(&dnat_rx_key);
        return MGW_DROP;
    }
    //add to dnat_rx_table
    struct mgw_utils_sess *dnat_rx_value = ALLOC(struct mgw_utils_sess, 1);
    dnat_rx_value->sip = dnat_rx_key->sip;
    dnat_rx_value->sport = dnat_rx_key->sport;
    dnat_rx_value->proto = dnat_rx_key->proto;
    dnat_rx_value->dip = trans_ip;
    dnat_rx_value->dport = trans_port;
    mgw_utils_sess_to_str(dnat_rx_value, dnat_rx_value_str);
    rtn = MESA_htable_add(handle->dnat_rx_htable, (const unsigned char *)(dnat_rx_key), sizeof(struct mgw_utils_sess), (const void*)dnat_rx_value);
    if(rtn < 0)
    {
        FREE(&dnat_rx_value);
        FREE(&dnat_rx_key);
        MGW_LOG_ERROR(logger, "MESA_htable: Failed at add, table is %s, key is %s, value is %s, rtn is %d", 
                        "dnat_rx_htable", dnat_rx_key_str, dnat_rx_value_str, rtn);
        return MGW_DROP;
    }
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_rx, g_fs_handle->cloumn_element_num, FS_OP_ADD, 1);
    MGW_LOG_INFO(logger, "MESA_htable: Succeed at add, table is %s, key is %s, value is %s", 
                        "dnat_rx_htable", dnat_rx_key_str, dnat_rx_value_str);
    //add to dnat_tx_table
    struct mgw_utils_sess *dnat_tx_key = ALLOC(struct mgw_utils_sess, 1);
    dnat_tx_key->sip = dnat_rx_value->dip;
    dnat_tx_key->sport = dnat_rx_value->dport;
    dnat_tx_key->proto = dnat_rx_value->proto;
    dnat_tx_key->dip = dnat_rx_value->sip;
    dnat_tx_key->dport = dnat_rx_value->sport;
    struct dnat_tx_htable_value *dnat_tx_value = ALLOC(struct dnat_tx_htable_value, 1);
    dnat_tx_value->sess.sip = dnat_rx_key->dip;
    dnat_tx_value->sess.sport = dnat_rx_key->dport;
    dnat_tx_value->sess.proto = dnat_rx_key->proto;
    dnat_tx_value->sess.dip = dnat_rx_key->sip;
    dnat_tx_value->sess.dport = dnat_rx_key->sport;
    dnat_tx_value->mrl_ip = mrl_ip;
    mgw_utils_sess_to_str(dnat_tx_key, dnat_tx_key_str);
    mgw_utils_sess_to_str(&(dnat_tx_value->sess), dnat_tx_value_str);
    rtn = MESA_htable_add(handle->dnat_tx_htable, (const unsigned char *)(dnat_tx_key), sizeof(struct mgw_utils_sess), (const void*)dnat_tx_value);
    if(rtn < 0)
    {
        MGW_LOG_ERROR(logger, "MESA_htable: Failed at add, table is %s, key is %s, value is %s, rtn is %d", 
                        "dnat_tx_htable", dnat_tx_key_str, dnat_tx_value_str, rtn);
        //dnat_tx_table and dnat_rx_table are Transaction
        rtn = MESA_htable_del(handle->dnat_rx_htable, (const unsigned char *)dnat_rx_key, sizeof(struct mgw_utils_sess), NULL);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at del, table is %s, key is %s, value is %s, rtn is %s",
                            "dnat_rx_htable", dnat_rx_key_str, dnat_rx_value_str, rtn);
        }
        else
        {
            MGW_LOG_INFO(logger, "MESA_htable: Succeed at del, table is %s, key is %s, value is %s",
                            "dnat_rx_htable", dnat_rx_key_str, dnat_rx_value_str);
        }
        FREE(&dnat_rx_key);
        FREE(&dnat_tx_key);
        FREE(&dnat_tx_value);
        return MGW_DROP;
    }
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_tx, g_fs_handle->cloumn_element_num, FS_OP_ADD, 1);
    MGW_LOG_INFO(logger, "MESA_htable: Succeed at add, table is %s, key is %s, value is %s", 
                        "dnat_tx_htable", dnat_tx_key_str, dnat_tx_value_str);
    //replace
    FREE(&dnat_rx_key);
    FREE(&dnat_tx_key);
    mgw_utils_pkt_sess_replace(buff, len, dnat_rx_value);
    MGW_LOG_INFO(logger, "Succeed at dnat_rx_convert: %s ---> %s", dnat_rx_key_str, dnat_rx_value_str);
    return MGW_FORWORD;
}