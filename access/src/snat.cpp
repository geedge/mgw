#include "mgw_utils.h"
#include "snat.h"
#include "ip_mgr.h"

struct snat_handle
{
    void *logger;
    struct ip_mgr_handle *_ip_mgr_handle;
    MESA_htable_handle ip2user_htable;  // should be thread-safe
    MESA_htable_handle snat_tx_htable;
    MESA_htable_handle snat_rx_htable;
    int access_id;
};

struct snat_tx_htable_value
{
    struct mgw_utils_sess sess;
    uint32_t mrl_ip;
};

struct field_stat_handle *g_fs_handle;


static void snat_tx_htable_data_free_cb(void *data)
{
    FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_tx, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    FREE(&data);
}

static void dnat_rx_htable_data_free_cb(void *data)
{
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_rx, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    FREE(&data);
}


struct snat_handle * snat_init(const char *profile, MESA_htable_handle ip2user_htable, struct ip_mgr_handle *_ip_mgr_handle, 
                                    struct field_stat_handle *fs_handle, void *logger)
{
    struct snat_handle *handle = ALLOC(struct snat_handle, 1);
    handle->logger = logger;
    handle->_ip_mgr_handle = _ip_mgr_handle;
    handle->ip2user_htable = ip2user_htable;
    handle->snat_tx_htable = mgw_utils_create_htable(profile, "snat_tx_htable", (void *)snat_tx_htable_data_free_cb, NULL, logger);
    handle->snat_rx_htable = mgw_utils_create_htable(profile, "dnat_rx_htable", (void *)dnat_rx_htable_data_free_cb, NULL, logger);
    char *section = (char *)"global";
    MESA_load_profile_int_def(profile, section, "access_id", &handle->access_id, 0);
    g_fs_handle = fs_handle;
    return handle;
}

void snat_destroy(struct snat_handle *handle)
{
    MESA_htable_destroy(handle->snat_tx_htable, NULL);
    MESA_htable_destroy(handle->snat_rx_htable, NULL);
    FREE(&handle);
}

static long snat_tx_htable_query_cb(void *data, const uchar *key, uint size, void *user_arg)
{
    struct snat_tx_htable_value *dup_value = (struct snat_tx_htable_value *)user_arg;
    if(data != NULL)
    {
        struct snat_tx_htable_value *_data = (struct snat_tx_htable_value *)data;
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

static long snat_rx_htable_query_cb(void *data, const uchar *key, uint size, void *user_arg)
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

static long ip2user_htable_query_cb(void *data, const uchar *key, uint size, void *user_arg)
{
    char *dup_value = (char *)user_arg;
    if(data != NULL)
    {
        char *_data = (char *)data;
        strncpy(dup_value, _data, MGW_SYMBOL_MAX);
        return MGW_HTABLE_KEY_EXISTED;
    }
    else
    {
        return MGW_HTABLE_KEY_NOT_EXISTED;
    }
}

static uint16_t get_candidate_port(int access_id, struct mgw_utils_sess *sess, uint32_t cand_ip)
{   
    u_int16_t random  = mgw_utils_get_random(64);
    uint16_t hash = ntohl(sess->dip) ^ ntohl(cand_ip) ^ ntohs(sess->dport) ^ (sess->proto);
    hash &= 0xff;
    uint16_t port = (access_id << 14) + (random << 8) + hash;
    return htons(port);
}

//get snat_tx_value, if succeed, has already added to snat_rx_htable
static struct snat_tx_htable_value * snat_tx_value_get(struct snat_handle *handle, const char *user_name, struct mgw_utils_sess *snat_tx_key)
{
    struct ip_mgr_handle *_ip_mgr_handle = handle->_ip_mgr_handle;
    int retry_times = 10;
    void *logger = handle->logger;
    for(int i = 0; i < retry_times; i++)
    {
        //get candidate ip
        uint32_t cand_ip;
        int rtn = ip_mgr_snat_cand_ip_get(_ip_mgr_handle, user_name, &cand_ip);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(logger, "Failed at find snat candidate ip, user_name is %s", user_name);
            return NULL;
        }
        //query mrl_ip
        uint32_t mrl_ip;
        rtn = ip_mgr_mrl_ip_query(_ip_mgr_handle, cand_ip, &mrl_ip);
        if(rtn < 0)
        {
            char cand_ip_str[MGW_SYMBOL_MAX];
            mgw_utils_inet_ntoa(cand_ip, cand_ip_str);
            MGW_LOG_ERROR(logger, "mrl ip not found, snat candidate ip is %s", cand_ip_str);
            continue;
        }
        //get candidate port
        u_int16_t cand_port = get_candidate_port(handle->access_id, snat_tx_key, cand_ip);

        //try to add to snat_rx_htable
        struct mgw_utils_sess *snat_rx_key = ALLOC(struct mgw_utils_sess, 1);
        snat_rx_key->sip = snat_tx_key->dip;
        snat_rx_key->sport = snat_tx_key->dport;
        snat_rx_key->proto = snat_tx_key->proto;
        snat_rx_key->dip = cand_ip;
        snat_rx_key->dport = cand_port;
        struct mgw_utils_sess *snat_rx_value = ALLOC(struct mgw_utils_sess, 1);
        snat_rx_value->sip = snat_tx_key->dip;
        snat_rx_value->sport = snat_tx_key->dport;
        snat_rx_value->proto = snat_tx_key->proto;
        snat_rx_value->dip = snat_tx_key->sip;
        snat_rx_value->dport = snat_tx_key->sport;
        char snat_rx_key_str[MGW_SYMBOL_MAX];
        char snat_rx_value_str[MGW_SYMBOL_MAX];
        mgw_utils_sess_to_str(snat_rx_key, snat_rx_key_str);
        mgw_utils_sess_to_str(snat_rx_key, snat_rx_value_str);
        rtn = MESA_htable_add(handle->snat_rx_htable, (const unsigned char *)snat_rx_key, sizeof(struct mgw_utils_sess), (void *)snat_rx_value);
        FREE(&snat_rx_key);
        if(rtn < 0)
        {
            FREE(&snat_rx_value);
            if(rtn != MESA_HTABLE_RET_DUP_ITEM)
            {
                MGW_LOG_ERROR(logger, "MESA_htable: Failed at add, table is %s, key is %s, value is %s, rtn is %d", 
                            "snat_rx_htable", snat_rx_key_str, snat_rx_value_str, rtn);
            }
            continue;
        }
        else
        {
            MGW_LOG_INFO(logger, "MESA_htable: Succeed at add, table is %s, key is %s, value is %s", 
                            "snat_rx_htable", snat_rx_key_str, snat_rx_value_str);
            FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_rx, g_fs_handle->cloumn_element_num, FS_OP_ADD, 1);
            struct snat_tx_htable_value *snat_tx_value = ALLOC(struct snat_tx_htable_value, 1);
            snat_tx_value->sess.sip = snat_tx_key->sip;
            snat_tx_value->sess.sport = snat_tx_key->sport;
            snat_tx_value->sess.proto = snat_tx_key->proto;
            snat_tx_value->sess.dip = cand_ip;
            snat_tx_value->sess.dport = cand_port;
            snat_tx_value->mrl_ip = mrl_ip;
            return snat_tx_value;
        }
    }
    MGW_LOG_ERROR(logger, "snat candidate ip and port conflicts, retry times is %d", retry_times - 1);
    return NULL;
}

int snat_tx_convert(struct snat_handle *handle, char *buff, int len, uint32_t *mrl_ip)
{
    void *logger = handle->logger;
    //get session
    struct mgw_utils_sess *snat_tx_key = ALLOC(struct mgw_utils_sess, 1);
    int rtn = mgw_utils_pkt_sess_parse(buff, len, snat_tx_key);
    if(rtn == -1)
    {
        FREE(&snat_tx_key);
        MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
        return MGW_DROP;
    }
    char snat_tx_key_str[MGW_SYMBOL_MAX];
    char snat_tx_value_str[MGW_SYMBOL_MAX];
    mgw_utils_sess_to_str(snat_tx_key, snat_tx_key_str);
    //query snat_tx_htable
    long cb_rtn = -1;
    struct snat_tx_htable_value snat_tx_dup_value;
    MESA_htable_search_cb(handle->snat_tx_htable, (const unsigned char *)(snat_tx_key), sizeof(struct mgw_utils_sess), snat_tx_htable_query_cb,
                                         (void *)(&snat_tx_dup_value), &cb_rtn);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_tx, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    if(cb_rtn == MGW_HTABLE_KEY_EXISTED)
    {
        //replace
        FREE(&snat_tx_key);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_tx, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        mgw_utils_pkt_sess_replace(buff, len, &(snat_tx_dup_value.sess));
        *mrl_ip = snat_tx_dup_value.mrl_ip;
        mgw_utils_sess_to_str(&(snat_tx_dup_value.sess), snat_tx_value_str);
        MGW_LOG_INFO(logger, "Succeed at snat_tx_convert: %s ---> %s", snat_tx_key_str, snat_tx_value_str);
        return MGW_FORWORD;
    }
    FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_tx, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
    //query user_name. user_name not existed: bypass, user_name existed: drop or forward
    char dup_user_name[MGW_SYMBOL_MAX];
    cb_rtn = -1;
    uint32_t snat_tx_key_sip = snat_tx_key->sip;
    char snat_tx_key_sip_str[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(snat_tx_key_sip, snat_tx_key_sip_str);
    MESA_htable_search_cb(handle->ip2user_htable, (const unsigned char *)(&snat_tx_key_sip), sizeof(uint32_t), 
                ip2user_htable_query_cb, (void *)(&dup_user_name), &cb_rtn);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_ip2user, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    if(cb_rtn == MGW_HTABLE_KEY_NOT_EXISTED)
    {
        mgw_utils_inet_ntoa(snat_tx_key_sip, snat_tx_key_sip_str);
        MGW_LOG_INFO(logger, "MESA_htable: key not existed, table is %s, ip is %s", "ip2user", snat_tx_key_sip_str);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_ip2user, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        FREE(&snat_tx_key);
        return MGW_BYPASS;
    }
    MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, ip is %s", "ip2user", snat_tx_key_sip_str);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_ip2user, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
    //get snat_tx_value
    struct snat_tx_htable_value *snat_tx_value = NULL;
    snat_tx_value = snat_tx_value_get(handle, dup_user_name, snat_tx_key);
    if(snat_tx_value == NULL)
    {
        FREE(&snat_tx_key);
        MGW_LOG_ERROR(logger, "Failed at snat_tx_convert: session is %s", snat_tx_key_str);
        return MGW_DROP;
    }
    //add to snat_tx_htable
    rtn = MESA_htable_add(handle->snat_tx_htable, (const unsigned char *)snat_tx_key, sizeof(struct mgw_utils_sess), (void *)snat_tx_value);
    FREE(&snat_tx_key);
    if(rtn < 0)
    {
        if(rtn != MESA_HTABLE_RET_DUP_ITEM)
        {
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at add, table is %s, key is %s, value is %s, rtn is %d", 
                        "snat_tx_htable", snat_tx_key_str, snat_tx_value_str, rtn);
        }
        //snat_tx_table and snat_rx_table are Transaction
        struct mgw_utils_sess *snat_rx_key = ALLOC(struct mgw_utils_sess, 1);
        snat_rx_key->sip = snat_tx_value->sess.dip;
        snat_rx_key->sport = snat_tx_value->sess.dport;
        snat_rx_key->proto = snat_tx_value->sess.proto;
        snat_rx_key->dip = snat_tx_value->sess.sip;
        snat_rx_key->dport = snat_tx_value->sess.sport;
        char snat_rx_key_str[MGW_SYMBOL_MAX];
        mgw_utils_sess_to_str(snat_rx_key, snat_rx_key_str);
        rtn = MESA_htable_del(handle->snat_rx_htable, (const unsigned char *)snat_rx_key, sizeof(struct mgw_utils_sess), NULL);
        FREE(&snat_tx_value);
        FREE(&snat_rx_key);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at del, table is %s, key is %s, rtn is %s", "snat_rx_htable", snat_rx_key_str, rtn);
        }
        else
        {
            MGW_LOG_INFO(logger, "MESA_htable: Succeed at del, table is %s, key is %s", "snat_rx_htable", snat_rx_key_str);
        }
        return MGW_DROP;
    }
    else
    {
        MGW_LOG_INFO(logger, "MESA_htable: Succeed at add, table is %s, key is %s, value is %s", 
                    "snat_tx_htable", snat_tx_key_str, snat_tx_value_str);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_tx, g_fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        //replace 
        mgw_utils_pkt_sess_replace(buff, len, &(snat_tx_value->sess));
        *mrl_ip = snat_tx_value->mrl_ip;
        MGW_LOG_INFO(logger, "Succeed at snat_tx_convert: %s ---> %s", snat_tx_key_str, snat_tx_value_str);
        return MGW_FORWORD;
    }
}

int snat_rx_convert(struct snat_handle *handle, char *buff, int len)
{   
    void *logger = handle->logger;
    //get session
    struct mgw_utils_sess *snat_rx_key = ALLOC(struct mgw_utils_sess, 1);
    int rtn = mgw_utils_pkt_sess_parse(buff, len, snat_rx_key);
    if(rtn == -1)
    {
        FREE(&snat_rx_key);
        MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
        return MGW_DROP;
    }
    char snat_rx_key_str[MGW_SYMBOL_MAX];
    char snat_rx_value_str[MGW_SYMBOL_MAX];
    mgw_utils_sess_to_str(snat_rx_key, snat_rx_key_str);
    //query snat_rx_htable
    long cb_rtn = -1;
    struct mgw_utils_sess snat_rx_dup_value;
    MESA_htable_search_cb(handle->snat_rx_htable, (const unsigned char *)(snat_rx_key), sizeof(struct mgw_utils_sess), snat_rx_htable_query_cb,
                                         (void *)(&snat_rx_dup_value), &cb_rtn);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_rx, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    if(cb_rtn == MGW_HTABLE_KEY_EXISTED)
    {
        //replace
        FREE(&snat_rx_key);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_rx, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        mgw_utils_pkt_sess_replace(buff, len, &snat_rx_dup_value);
        mgw_utils_sess_to_str(&snat_rx_dup_value, snat_rx_value_str);
        MGW_LOG_INFO(logger, "Succeed at dnat_rx_convert: %s ---> %s", snat_rx_key_str, snat_rx_value_str);
        return MGW_FORWORD;
    }
    FREE(&snat_rx_key);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_rx, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
    return MGW_BYPASS;
}
