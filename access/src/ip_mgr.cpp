

#include "mgw_utils.h"
#include "ip_mgr.h"
#define SNAT_CAND_IP_GROUP_MAX 4096

static struct field_stat_handle *g_fs_handle = NULL;

struct ip_mgr_handle
{
    void *logger;
    Maat_feather_t Maat_feather_snat_policy;
    Maat_feather_t Maat_feather_dnat_policy;
    Maat_feather_t Maat_feather_snat_cand_ip;
    Maat_feather_t Maat_feather_mrl_ip;
    MESA_htable_handle snat_policy_htable;  //expire_time: 0
    MESA_htable_handle dnat_policy_htable;  //expire_time: 0
    MESA_htable_handle snat_cand_ip_htable; //expire_time: 0
    MESA_htable_handle mrl_ip_htable; //expire_time: 0
};

struct snat_policy_htable_value
{
    char user_name[MGW_SYMBOL_MAX];
    int group_id;
};

struct dnat_policy_htable_key
{
    uint32_t orig_ip;
    uint16_t orig_port;
};

struct dnat_policy_htable_value
{
    uint32_t trans_ip;
    uint16_t trans_port;
};

struct mrl_ip_htable_value
{
    uint32_t back_ip;
    uint32_t mrl_ip;
};

struct snat_cand_ip_detail
{
    uint32_t ip;
    int group_id;
    int addr_type;
    int location;
    int reference;
};

struct snat_cand_ip_group
{
    struct snat_cand_ip_detail *ip_list[SNAT_CAND_IP_GROUP_MAX];
    unsigned int num;
};

struct snat_cand_ip_query_cb_get_args
{
    struct ip_mgr_handle *handle;
    int group_id;
    uint32_t *ip;
    bool existed;
};

struct snat_cand_ip_query_cb_add_args
{
    struct ip_mgr_handle *handle;
    int group_id;
    struct snat_cand_ip_detail ip_detail;
};

struct snat_cand_ip_query_cb_del_args
{
    struct ip_mgr_handle *handle;
    int group_id;
    uint32_t ip;
};

static long snat_policy_query_cb(void *data, const uchar *key, uint size, void *user_args)
{
    struct snat_policy_htable_value *dup_value = (struct snat_policy_htable_value *)user_args;
    if(data != NULL)
    {
        struct snat_policy_htable_value *_data = (struct snat_policy_htable_value *)data;
        strncpy(dup_value->user_name, _data->user_name, MGW_SYMBOL_MAX);
        dup_value->group_id = _data->group_id;
        return MGW_HTABLE_KEY_EXISTED;
    }
    return MGW_HTABLE_KEY_NOT_EXISTED;
}

static long dnat_policy_query_cb(void *data, const uchar *key, uint size, void *user_args)
{
    struct dnat_policy_htable_value *dup_value = (struct dnat_policy_htable_value *)user_args;
    if(data != NULL)
    {
        struct dnat_policy_htable_value *_data = (struct dnat_policy_htable_value *)data;
        dup_value->trans_ip = _data->trans_ip;
        dup_value->trans_port = _data->trans_port;
        return MGW_HTABLE_KEY_EXISTED;
    }
    return MGW_HTABLE_KEY_NOT_EXISTED;
}

static long mrl_ip_query_cb(void *data, const uchar *key, uint size, void *user_args)
{
    struct mrl_ip_htable_value *dup_value = (struct mrl_ip_htable_value *)user_args;
    if(data != NULL)
    {
        struct mrl_ip_htable_value *_data = (struct mrl_ip_htable_value *)data;
        dup_value->back_ip = _data->back_ip;
        dup_value->mrl_ip = _data->mrl_ip;
        return MGW_HTABLE_KEY_EXISTED;
    }
    return MGW_HTABLE_KEY_NOT_EXISTED;
}

int ip_mgr_dnat_policy_query(struct ip_mgr_handle *handle, uint32_t orig_ip, uint16_t orig_port, uint32_t *trans_ip, uint16_t *trans_port)
{
    void *logger = handle->logger;
    long cb_rtn = -1;
    struct dnat_policy_htable_key *key = ALLOC(struct dnat_policy_htable_key, 1);
    key->orig_ip = orig_ip;
    key->orig_port = orig_port;
    char orig_ip_str[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(orig_ip, orig_ip_str);
    struct dnat_policy_htable_value dup_value;
    MESA_htable_search_cb(handle->dnat_policy_htable, (const unsigned char *)key, sizeof(struct dnat_policy_htable_key), 
                        dnat_policy_query_cb, &dup_value, &cb_rtn);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_policy, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    if(cb_rtn == MGW_HTABLE_KEY_NOT_EXISTED)
    {
        FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_policy, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        MGW_LOG_ERROR(logger, "MESA_htable: key not existed, table is %s, original dest is <%s:%d>", "dnat_policy_htable", orig_ip_str, ntohs(orig_port));
        //port=0
        key->orig_port = 0;
        MESA_htable_search_cb(handle->dnat_policy_htable, (const unsigned char *)key, sizeof(struct dnat_policy_htable_key), 
                        dnat_policy_query_cb, &dup_value, &cb_rtn);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_policy, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
        if(cb_rtn == MGW_HTABLE_KEY_NOT_EXISTED)
        {
            FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_policy, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
            MGW_LOG_ERROR(logger, "MESA_htable: key not existed, table is %s, original dest is <%s:%d>", "dnat_policy_htable", orig_ip_str, 0);
            FREE(&key);
            return -1;
        }
        FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_policy, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, original dest is <%s:%d>", "dnat_policy_htable", orig_ip_str, 0);
        *trans_port = orig_port;
    }
    else
    {
        *trans_port = dup_value.trans_port;
    }
    *trans_ip = dup_value.trans_ip;
    char trans_ip_str[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(*trans_ip, trans_ip_str);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_policy, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
    MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, original dest is <%s:%d>, translated dest is <%s:%d>", 
            "dnat_policy_htable", orig_ip_str, ntohs(orig_port), trans_ip_str, ntohs(*trans_port));
    FREE(&key);
    return 0; 
}

int ip_mgr_mrl_ip_query(struct ip_mgr_handle *handle, uint32_t back_ip, uint32_t *mrl_ip)
{
    void *logger = handle->logger;
    long cb_rtn = -1;
    char back_ip_str[MGW_SYMBOL_MAX];
    char mrl_ip_str[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(back_ip, back_ip_str);
    struct mrl_ip_htable_value dup_value;
    //printf("mrl_ip query: key is %d, size is %d\n", back_ip, sizeof(uint32_t));
    MESA_htable_search_cb(handle->mrl_ip_htable, (const unsigned char *)(&back_ip), sizeof(uint32_t), 
                        mrl_ip_query_cb, &dup_value, &cb_rtn);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_mrl_ip, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    if(cb_rtn == MGW_HTABLE_KEY_NOT_EXISTED)
    {
        FS_operate(g_fs_handle->handle, g_fs_handle->line_mrl_ip, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        MGW_LOG_ERROR(logger, "MESA_htable: key not existed, table is %s, back ip is %s", "mrl_ip_htable", back_ip_str);
        return -1;
    }
    mgw_utils_inet_ntoa(dup_value.mrl_ip, mrl_ip_str);
    *mrl_ip = dup_value.mrl_ip;
    FS_operate(g_fs_handle->handle, g_fs_handle->line_mrl_ip, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
    MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, back ip is %s, mrl ip is %s", "mrl_ip_htable", back_ip_str, mrl_ip_str);
    return 0; 
}

static long snat_cand_ip_query_cb_get(void *data, const uchar *key, uint size, void *user_args)
{
    //printf("call snat_cand_ip_query_cb_get\n");
    struct snat_cand_ip_query_cb_get_args *args = (struct snat_cand_ip_query_cb_get_args *)user_args;
    struct ip_mgr_handle *handle = args->handle;
    void *logger = handle->logger;
    int group_id = args->group_id;
    if(data == NULL)
    {
        MGW_LOG_INFO(logger, "MESA_htable: key not existed, table is %s, group_id is %d", "snat_cand_ip_htable", group_id);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        args->existed = false;
    }
    else
    {
        struct snat_cand_ip_group *ip_group = (struct snat_cand_ip_group *)data;
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, group_id is %d", "snat_cand_ip_htable", group_id);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        unsigned int num = ip_group->num;
        if(num <= 0)
        {
            MGW_LOG_ERROR(logger, "group_id is %d, num of snat candidate ip is %d", group_id, num);
            args->existed = false;
            return MGW_HTABLE_QUERY_CB_SUCCESS;
        }
        unsigned int index = mgw_utils_get_random(num);
        *(args->ip) = ip_group->ip_list[index]->ip;
        args->existed = true;
        return MGW_HTABLE_QUERY_CB_SUCCESS;
    }
    return MGW_HTABLE_QUERY_CB_SUCCESS;
}

int ip_mgr_snat_cand_ip_get(struct ip_mgr_handle *handle, const char *user_name, uint32_t *selected_ip)
{
    void *logger = handle->logger;
    long cb_rtn = 0;
    int key_size = strnlen(user_name, MGW_SYMBOL_MAX);
    //query snat_policy
    struct snat_policy_htable_value snat_policy_dup_value;
    MESA_htable_search_cb(handle->snat_policy_htable, (const unsigned char *)user_name, key_size, 
            snat_policy_query_cb, &snat_policy_dup_value, &cb_rtn);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_policy, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    if(cb_rtn == MGW_HTABLE_KEY_EXISTED)
    {
        int group_id = snat_policy_dup_value.group_id;
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_policy, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, user_name is %s, group id is %d", 
                    "snat_policy_htable", user_name, group_id);
        //query snat_cand_ip_htable
        long cb_rtn = -1;
        struct snat_cand_ip_query_cb_get_args args;
        args.handle = handle;
        args.ip = selected_ip;
        args.group_id = group_id;
        //printf("group id is %d\n", group_id);
        MESA_htable_search_cb(handle->snat_cand_ip_htable, (const unsigned char *)(&group_id), sizeof(group_id), 
            snat_cand_ip_query_cb_get, &args, &cb_rtn);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
        if(args.existed)
        {
            return 0;
        }
        else
        {
            MGW_LOG_ERROR(logger, "Failed at find available snat candidate ip, group id is %d", group_id);
            return -1;
        }
    }
    else
    {
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_policy, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        MGW_LOG_ERROR(logger, "MESA_htable: key not existed. table is %s, key is %s", "snat_policy_htable", user_name);
        return -1;
    }
}

static void snat_policy_htable_data_free_cb(void *data)
{
    FREE(&data);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_policy, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
}

static void dnat_policy_htable_data_free_cb(void *data)
{
    FREE(&data);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_policy, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
}

static void snat_cand_ip_htable_data_free_cb(void *data)
{
    struct snat_cand_ip_group *ip_group = (struct snat_cand_ip_group *)data;
    int num = ip_group->num;
    for(int i = 0; i < num; i++)
    {
        FREE(&(ip_group->ip_list[i]));
    }
    FREE(&data);
    FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
}

static void mrl_ip_htable_data_free_cb(void *data)
{
    FS_operate(g_fs_handle->handle, g_fs_handle->line_mrl_ip, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    FREE(&data);
}

static void Maat_snat_policy_start_cb(int update_type, void* args)
{
    printf("call Maat_snat_policy_start_cb, update_type is %d\n", update_type);
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: start callback, table is IP_SNAT_POLICY, update_type is %d\n", update_type);
	return;
}

static void Maat_snat_policy_update_cb(int table_id, const char* table_line, void* args)
{
    printf("call Maat_snat_policy_update_cb, table_line is %s\n", table_line);
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: update callback, table is IP_SNAT_POLICY, table line is %s", table_line);
    int config_id, group_id, is_valid;
    char user_type[MGW_SYMBOL_MAX];
    char user_name[MGW_SYMBOL_MAX];
    char translate_param[MGW_STRING_MAX];
    int do_log;
    int action;
    int service_id;
    //printf("table line is %s\n", table_line);
    sscanf(table_line, "%d %d %s %s %s %d %d %d %d", &config_id, &group_id, user_type, user_name, translate_param, &do_log, &action, &service_id, &is_valid);
    //printf("user name is %s\n", user_name);
    struct snat_policy_htable_value *value = ALLOC(struct snat_policy_htable_value, 1);
    strncpy(value->user_name, user_name, MGW_SYMBOL_MAX);
    value->group_id = group_id;
    int key_size = strnlen(user_name, MGW_SYMBOL_MAX);
    if(is_valid == 1)
    {
        //add snat_policy_htable
        int rtn = MESA_htable_add(handle->snat_policy_htable, (const unsigned char *)user_name, key_size, value);
        if(rtn < 0 && rtn != MESA_HTABLE_RET_DUP_ITEM)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at add, table is %s, user_name is %s, group_id is %d, rtn is %d", 
                        "snat_policy_htable", user_name, group_id, rtn);
            return;
        }
        if(rtn >= 0)
        {
            MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at add, table is %s, user_name is %s, group_id is %d", "snat_policy_htable", user_name, group_id);
            FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_policy, g_fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        }
    }
    else
    {
        //del snat_policy_htable
        int rtn = MESA_htable_del(handle->snat_policy_htable, (const unsigned char *)user_name, key_size, NULL);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at del, table is %s, user_name is %s, group_id is %d, rtn is %d", "snat_policy_htable", user_name, group_id, rtn);
            return;
        }
        MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at del, table is %s, user_name is %s, group_id is %d", "snat_policy_htable", user_name, group_id);
    }
	return;
}


static void Maat_snat_policy_finish_cb(void* args)
{
    printf("call Maat_snat_policy_finish_cb\n");
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: finish callback, table is SNAT_POLICY");
    //Maat_feather_t feather = handle->feather;
    /*
	long long version=0;
	int ret=0, is_last_updating_table = 0;
	ret = Maat_read_state(feather, MAAT_STATE_VERSION, &version, sizeof(version));
    printf("version is %d\n", version);
	assert(ret==0);
	ret=Maat_read_state(feather,MAAT_STATE_LAST_UPDATING_TABLE, &is_last_updating_table, sizeof(is_last_updating_table));
    printf("is_last_updating_table is %d\n", is_last_updating_table);
	assert(ret==0);
    */
	return;
}

static void Maat_snat_cand_ip_start_cb(int update_type,void* args)
{
    printf("call Maat_snat_cand_ip_start_cb, update_type is %d\n", update_type);
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: start callback, table is IR_CANDIDATE_IP, updata_type is %d\n", update_type);
	return;
}

static long snat_cand_ip_query_cb_add(void *data, const uchar *key, uint size, void *user_args)
{
    //printf("call snat_cand_ip_query_cb_add\n");
    struct snat_cand_ip_query_cb_add_args *args = (struct snat_cand_ip_query_cb_add_args *)user_args;
    struct ip_mgr_handle *handle = args->handle;
    int group_id = args->group_id;
    struct snat_cand_ip_detail ip_detail = args->ip_detail;
    void *logger = handle->logger;
    struct snat_cand_ip_group *ip_group = NULL;
    if(data == NULL)
    {
        MGW_LOG_INFO(logger, "MESA_htable: key not existed, table is %s, group_id is %d", "snat_cand_ip_htable", group_id);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        ip_group = ALLOC(struct snat_cand_ip_group, 1);
        ip_group->num = 0;
        int rtn = MESA_htable_add(handle->snat_cand_ip_htable, (const unsigned char *)&group_id, sizeof(group_id), (void *)ip_group);
        if(rtn < 0)
        {
            FREE(&ip_group);
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at add, table is %s, group_id is %d, rtn is %d", "snat_cand_ip_htable", group_id, rtn);
            MGW_LOG_ERROR(logger, "Failed at add ip to snat_cand_ip_group, group not existed, group_id is %d", group_id); 
            return MGW_HTABLE_QUERY_CB_SUCCESS;
        }
        MGW_LOG_INFO(logger, "MESA_htable: Succeed at add, table is %s, group_id is %d", "snat_cand_ip_htable", group_id);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_element_num, FS_OP_ADD, 1);
    }
    else
    {
        ip_group = (struct snat_cand_ip_group *)data;
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, group_id is %d", "snat_cand_ip_htable", group_id);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
    }
    struct snat_cand_ip_detail *cand_ip_detail = ALLOC(struct snat_cand_ip_detail, 1);
    cand_ip_detail->ip = ip_detail.ip;
    cand_ip_detail->group_id = ip_detail.group_id;
    cand_ip_detail->addr_type = ip_detail.addr_type;
    cand_ip_detail->location = ip_detail.location;
    int num = ip_group->num;
    char ip_str[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(ip_detail.ip, ip_str);
    if(num >= SNAT_CAND_IP_GROUP_MAX)
    {
        FREE(&cand_ip_detail);
        MGW_LOG_ERROR(logger, "Failed at add ip to snat_cand_ip_group, reach the max num %d of group, ip is %s, group_id is %d", 
                            SNAT_CAND_IP_GROUP_MAX, ip_str, group_id);
        return MGW_HTABLE_QUERY_CB_SUCCESS;
    }
    ip_group->ip_list[num] = cand_ip_detail;
    ip_group->num++;
    MGW_LOG_INFO(logger, "Succeed at add ip to snat_cand_ip_group, ip is %s, group_id is %d", ip_str, group_id);
    return MGW_HTABLE_QUERY_CB_SUCCESS;
}

static long snat_cand_ip_query_cb_del(void *data, const uchar *key, uint size, void *user_args)
{
    //printf("call snat_cand_ip_query_cb_del\n");
    struct snat_cand_ip_query_cb_del_args *args = (struct snat_cand_ip_query_cb_del_args *)user_args;
    struct ip_mgr_handle *handle = args->handle;
    uint32_t ip = args->ip;
    int group_id = args->group_id;
    void *logger = handle->logger;
    char ip_str[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(ip, ip_str);
    if(data == NULL)
    {
        MGW_LOG_ERROR(logger, "MESA_htable: key not existed, table is %s, group_id is %d", "snat_cand_ip_htable", group_id);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        MGW_LOG_ERROR(logger, "Failed at del ip from snat_cand_ip_group, group_id not existed, ip is %s, group_id is %d", ip_str, group_id);
        return MGW_HTABLE_QUERY_CB_SUCCESS;
    }
    else
    {
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, group_id is %d", "snat_cand_ip_htable", group_id);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        struct snat_cand_ip_group *ip_group = (struct snat_cand_ip_group *)data;
        int num = ip_group->num;
        int pos = -1;
        for(int i = 0; i < num; i++)
        {
            if(ip_group->ip_list[i]->ip == ip)
            {
                pos = i;
                break;
            }
        }
        if(pos == -1)
        {
            MGW_LOG_ERROR(logger, "Failed at del ip from snat_cand_ip_group, ip not in group, ip is %s, group_id is %d", ip_str, group_id);
        }
        else
        {
            FREE(&(ip_group->ip_list[pos]));
            ip_group->num --;
            for(int i = pos; i < num - 1; i++)
            {
                ip_group->ip_list[i] = ip_group->ip_list[i + 1];
            }
        }
        if(ip_group->num <= 0)
        {
            int rtn = MESA_htable_del(handle->snat_cand_ip_htable, (const unsigned char *)&group_id, sizeof(group_id), NULL);
            if(rtn < 0)
            {
                MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at del, table is %s, group_id is %d, rtn is %d", "snat_cand_ip_htable", group_id, rtn);
            }
            else
            {
                MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at del, table is %s, group_id is %d", "snat_cand_ip_htable", group_id);
            }
        }
        return MGW_HTABLE_QUERY_CB_SUCCESS;
    }
}

static void Maat_snat_cand_ip_update_cb(int table_id, const char* table_line, void* args)
{
    printf("call Maat_snat_cand_ip_update_cb, table line is %s\n", table_line);
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
	MGW_LOG_INFO(logger, "Maat_redis: update callback, table is IR_CANDIDATE_IP, table line is %s", table_line);
    int config_id, group_id, addr_type, location, is_valid;
    char ip_addr[MGW_SYMBOL_MAX];
    sscanf(table_line, "%d %d %d %s %d %d", &config_id, &group_id, &addr_type, ip_addr, &location, &is_valid);
    uint32_t ip = inet_addr(ip_addr);
    if(is_valid == 1)
    {
        //add cand ip to snat_cand_ip_htable
        struct snat_cand_ip_query_cb_add_args args;
        args.handle = handle;
        args.group_id = group_id;
        args.ip_detail.ip = ip;
        args.ip_detail.group_id = group_id;
        args.ip_detail.addr_type = addr_type;
        args.ip_detail.location = location;
        long cb_rtn = -1;
        MESA_htable_search_cb(handle->snat_cand_ip_htable, (const unsigned char *)(&group_id), 
                    sizeof(group_id), snat_cand_ip_query_cb_add, (void *)&args, &cb_rtn);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    }
    else
    {
        //delete cand ip from snat_cand_ip_htable
        struct snat_cand_ip_query_cb_del_args args;
        args.group_id = group_id;
        args.handle = handle;
        args.ip = ip;
        long cb_rtn = -1;
        MESA_htable_search_cb(handle->snat_cand_ip_htable, (const unsigned char *)(&group_id), sizeof(group_id), snat_cand_ip_query_cb_del, (void *)&args, &cb_rtn);
        FS_operate(g_fs_handle->handle, g_fs_handle->line_snat_cand_ip, g_fs_handle->cloumn_query_num, FS_OP_ADD, 1);
    }
	return;
}


static void Maat_snat_cand_ip_finish_cb(void* args)
{
    printf("call Maat_snat_cand_ip_finish_cb\n");
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: finish callback, table is CAND_IP_TABLE");
	return;
}


static void Maat_dnat_policy_start_cb(int update_type, void* args)
{
    printf("call Maat_dnat_policy_start_cb, update_type is %d\n", update_type);
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: start callback, update_type is %d, table is IP_DNAT_POLICY", update_type);
	return;
}

static void Maat_dnat_policy_update_cb(int table_id, const char* table_line, void* args)
{
    printf("call Maat_dnat_policy_update_cb, table line is %s\n", table_line);
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: update callback, table is IP_DNAT_POLICY, table line is %s", table_line);
    int config_id, addr_type, orig_proto, do_log, action, service_id, is_valid;
    char orig_ip[MGW_SYMBOL_MAX];
    char orig_port_str[MGW_SYMBOL_MAX];
    uint16_t orig_port;
    char trans_ip[MGW_SYMBOL_MAX];
    char trans_port_str[MGW_SYMBOL_MAX];
    uint16_t trans_port;
    //printf("table is dnat_policy, table line is %s\n", table_line);
    sscanf(table_line, "%d %d %s %s %d %s %s %d %d %d %d", &config_id, &addr_type, orig_ip, orig_port_str, 
            &orig_proto,trans_ip, trans_port_str, &do_log, &action, &service_id, &is_valid);
    orig_port = atoi(orig_port_str);
    trans_port = atoi(trans_port_str);
    struct dnat_policy_htable_key *key = ALLOC(struct dnat_policy_htable_key, 1);
    key->orig_ip = inet_addr(orig_ip);
    key->orig_port = htons(orig_port);
    //printf("service id is %d\n", service_id);
    //printf("is valid is %d\n", is_valid);
    if(is_valid == 1)
    {
        //add dnat_policy_htable
        struct dnat_policy_htable_value *value = ALLOC(struct dnat_policy_htable_value, 1);
        value->trans_ip = inet_addr(trans_ip);
        value->trans_port = htons(trans_port);
        int rtn = MESA_htable_add(handle->dnat_policy_htable, (const unsigned char *)key, sizeof(key), (void *)value);
        if(rtn < 0)
        {
            FREE(&value);
            if(rtn != MESA_HTABLE_RET_DUP_ITEM)
            {
                MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at add, table is %s, original pair is <%s:%d>, translated pair is <%s:%d>, rtn is %d", 
                        "dnat_policy_htable", orig_ip, orig_port, trans_ip, trans_port, rtn);
            }
        }
        else
        {
            MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at add, table is %s, original pair is <%s:%d>, translated pair is <%s:%d>", 
                        "dnat_policy_htable", orig_ip, orig_port, trans_ip, trans_port, rtn);
            FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat_policy, g_fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        }
    }
    else
    {
        //del dnat_policy_htable
        int rtn = MESA_htable_del(handle->dnat_policy_htable, (const unsigned char *)key, sizeof(key), NULL);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at del, table is %s, original pair is <%s:%d>, translated pair is <%s:%d>, rtn is %d", 
                        "dnat_policy_htable", orig_ip, orig_port, trans_ip, trans_port, rtn);
        }
        else
        {
            MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at del, table is %s, original pair is <%s:%d>, translated pair is <%s:%d>", 
                        "dnat_policy_htable", orig_ip, orig_port, trans_ip, trans_port);
        }
    }
    FREE(&key);
	return;
}


static void Maat_dnat_policy_finish_cb(void* args)
{
    printf("call Maat_dnat_policy_finish_cb\n");
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: finish callback, table is IP_DNAT_POLICY");
	return;
}

static void Maat_mrl_ip_start_cb(int update_type, void* args)
{
    printf("call Maat_mrl_ip_start_cb, update_type is %d\n", update_type);
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: start callback, table is IP_MRL_IP_INFO, update_type is %d", update_type);
	return;
}

static void Maat_mrl_ip_update_cb(int table_id, const char* table_line, void* args)
{
    printf("call Maat_mrl_ip_update_cb, table_line is %s\n", table_line);
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: update callback, table is IP_MRL_IP_INFO, table line is %s", table_line);
    int config_id, back_type, is_valid;
    char back_ip[MGW_SYMBOL_MAX];
    char mrl_ip[MGW_SYMBOL_MAX];
    //printf("table line is %s\n", table_line);
    sscanf(table_line, "%d %s %d %s %d", &config_id, back_ip, &back_type, mrl_ip, &is_valid);
    uint32_t key = inet_addr(back_ip);
    if(is_valid == 1)
    {
        struct mrl_ip_htable_value *value = ALLOC(struct mrl_ip_htable_value, 1);
        value->back_ip = key;
        value->mrl_ip = inet_addr(mrl_ip);
        //printf("mrl_ip add : key is %d, size is %d\n", key, sizeof(key));
        int rtn = MESA_htable_add(handle->mrl_ip_htable, (const unsigned char *)&key, sizeof(key), (void *)value);
        if(rtn < 0)
        {
            FREE(&value);
            if(rtn != MESA_HTABLE_RET_DUP_ITEM)
            {
                MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at add, table is %s, back_ip is %s, mrl_ip is %s, rtn is %d", 
                        "mrl_ip_htable", back_ip, mrl_ip, rtn);
            }
        }
        else
        {
            MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at add, table is %s, back_ip is %s, mrl_ip is %s", 
                        "mrl_ip_htable", back_ip, mrl_ip);
            FS_operate(g_fs_handle->handle, g_fs_handle->line_mrl_ip, g_fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        }
    }
    else
    {
        int rtn = MESA_htable_del(handle->mrl_ip_htable, (const unsigned char *)&key, sizeof(key), NULL);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at del, table is %s, back_ip is %s, mrl_ip is %s, rtn is %d", 
                        "mrl_ip_htable", back_ip, mrl_ip, rtn);
        }
        else
        {
            MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at del, table is %s, back_ip is %s, mrl_ip is %s", 
                        "mrl_ip_htable", back_ip, mrl_ip);
        }
    }
	return;
}


static void Maat_mrl_ip_finish_cb(void* args)
{
    printf("call Maat_mrl_ip_finish_cb\n");
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: finish callback, table is IP_MRL_IP_INFO");
	return;
}

static int Maat_plugin_register(Maat_feather_t feather, const char* table_name, Maat_start_callback_t *start, 
                Maat_update_callback_t *update, Maat_finish_callback_t *finish, struct ip_mgr_handle *handle)
{
	int table_id = 0, ret = 0;
    void *logger = handle->logger;
	table_id = Maat_table_register(feather, table_name);
	if(table_id == -1)
	{
        MGW_LOG_ERROR(logger, "Maat_redis: Failed at register table %s", table_name);
        return -1;
	}
	else
	{
		ret = Maat_table_callback_register(feather, table_id, start, update, finish, (void *)handle);
		if(ret < 0)
		{
            MGW_LOG_ERROR(logger, "Maat_redis: Failed to register callback of table %s", table_name);
            return -1;
		}
	}
	return 0;
}

static void wrapped_Maat_set_feather_opt(void *logger, Maat_feather_t feather, enum MAAT_INIT_OPT type, const void* value, int size)
{
    int rtn = Maat_set_feather_opt(feather, type, value, size);
    if(unlikely(rtn < 0))
    {
        MGW_LOG_ERROR(logger, "Failed at Maat_set_feather_opt, type is %d, rtn is %d", type, rtn);
        exit(EXIT_FAILURE);
    }
}

static Maat_feather_t  Maat_init(const char *profile, const char *section, void *logger)
{
    // load conf
    char table_info_path[MGW_PATH_MAX];
    int max_thread_num;
    char Maat_redis_ip[MGW_SYMBOL_MAX];
    int Maat_redis_port;
    int Maat_redis_index;
    char stat_file_path[MGW_PATH_MAX];
    MESA_load_profile_string_def(profile, section, "table_info_path", table_info_path, sizeof(table_info_path), "./conf/table_info.conf");
    MESA_load_profile_int_def(profile, section, "max_thread_num", &max_thread_num, 1);
    MESA_load_profile_string_def(profile, section, "Maat_redis_ip", Maat_redis_ip, sizeof(Maat_redis_ip), "127.0.0.1");
    MESA_load_profile_int_def(profile, section, "Maat_redis_port", &Maat_redis_port, 6379);
    MESA_load_profile_int_def(profile, section, "Maat_redis_index", &Maat_redis_index, 1);
    MESA_load_profile_string_def(profile, section, "stat_file_path", stat_file_path, sizeof(stat_file_path), "./log/Maat_stat.log");
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n table_info_path: %s\n max_thread_num: %d\n Maat_redis_ip: %s\n Maat_redis_port: %d\n Maat_redis_index: %d\n"
    "stat_file_path: %s", section, table_info_path, max_thread_num, Maat_redis_ip, Maat_redis_port, Maat_redis_index, stat_file_path);
    // init Maat
    Maat_feather_t feather = NULL;
    feather = Maat_feather(max_thread_num, table_info_path, logger);
    if(feather == NULL)
    {
        MGW_LOG_ERROR(logger, "Failed at Maat_feather");
        exit(EXIT_FAILURE);
    }
    wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_INSTANCE_NAME, "mgw", strlen("mgw")+1);
	wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_REDIS_IP, Maat_redis_ip, strlen(Maat_redis_ip)+1);
	wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_REDIS_PORT, &Maat_redis_port, sizeof(Maat_redis_port));
    wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_REDIS_INDEX, &Maat_redis_index, sizeof(Maat_redis_index));
    //wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_STAT_FILE_PATH, stat_file_path, strlen(stat_file_path)+1);
    //wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_STAT_ON, NULL, 0);
	//wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_PERF_ON, NULL, 0);
    //wrapped_Maat_set_feather_opt(feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
	//wrapped_Maat_set_feather_opt(feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effective_interval_ms, sizeof(effective_interval_ms));
	//wrapped_Maat_set_feather_opt(feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	//wrapped_Maat_set_feather_opt(feather, MAAT_OPT_ACCEPT_TAGS, accept_tags, strlen(accept_tags)+1);
	int rtn = Maat_initiate_feather(feather);
    if(unlikely(rtn < 0))
    {
        MGW_LOG_ERROR(logger, "Failed at Maat_initiate_feather");
		exit(EXIT_FAILURE);
    }
    return feather;
}

struct ip_mgr_handle *ip_mgr_init(const char *profile, struct field_stat_handle *fs_handle, void *logger)
{
    struct ip_mgr_handle *handle = ALLOC(struct ip_mgr_handle, 1); 
    handle->Maat_feather_snat_policy = Maat_init(profile, "Maat_snat_policy", logger);
    handle->Maat_feather_dnat_policy = Maat_init(profile, "Maat_dnat_policy", logger);
    handle->Maat_feather_snat_cand_ip = Maat_init(profile, "Maat_snat_cand_ip", logger);
    handle->Maat_feather_mrl_ip = Maat_init(profile, "Maat_mrl_ip", logger);
    handle->logger = logger;
    handle->snat_policy_htable = mgw_utils_create_htable(profile, "snat_policy_htable", (void *)snat_policy_htable_data_free_cb, NULL, logger);
    handle->dnat_policy_htable = mgw_utils_create_htable(profile, "dnat_policy_htable", (void *)dnat_policy_htable_data_free_cb, NULL, logger);
    handle->snat_cand_ip_htable = mgw_utils_create_htable(profile, "snat_cand_ip_htable", (void *)snat_cand_ip_htable_data_free_cb, NULL, logger);
    handle->mrl_ip_htable = mgw_utils_create_htable(profile, "mrl_ip_htable", (void *)mrl_ip_htable_data_free_cb, NULL, logger);
    g_fs_handle = fs_handle;
    int rtn = Maat_plugin_register(handle->Maat_feather_snat_policy, "IR_SNAT_POLICY", Maat_snat_policy_start_cb, Maat_snat_policy_update_cb, Maat_snat_policy_finish_cb, handle);
    if(rtn == -1)
    {
        return NULL;   
    }
    rtn = Maat_plugin_register(handle->Maat_feather_dnat_policy, "IR_DNAT_POLICY", Maat_dnat_policy_start_cb, Maat_dnat_policy_update_cb, Maat_dnat_policy_finish_cb, handle);
    if(rtn == -1)
    {
        return NULL;   
    }
    rtn = Maat_plugin_register(handle->Maat_feather_snat_cand_ip, "IR_CANDIDATE_IP", Maat_snat_cand_ip_start_cb, Maat_snat_cand_ip_update_cb, Maat_snat_cand_ip_finish_cb, handle);
    if(rtn == -1)
    {
        return NULL;
    }
    rtn = Maat_plugin_register(handle->Maat_feather_mrl_ip, "IR_MRL_IP_INFO", Maat_mrl_ip_start_cb, Maat_mrl_ip_update_cb, Maat_mrl_ip_finish_cb, handle);
    if(rtn == -1)
    {
        return NULL;
    }
    return handle;
}

void ip_mgr_destroy(struct ip_mgr_handle *handle)
{
    MESA_htable_destroy(handle->snat_policy_htable, NULL);
    MESA_htable_destroy(handle->dnat_policy_htable, NULL);
    MESA_htable_destroy(handle->snat_cand_ip_htable, NULL);
    MESA_htable_destroy(handle->mrl_ip_htable, NULL);
    Maat_burn_feather(handle->Maat_feather_snat_policy);
    Maat_burn_feather(handle->Maat_feather_dnat_policy);
    Maat_burn_feather(handle->Maat_feather_snat_cand_ip);
    Maat_burn_feather(handle->Maat_feather_mrl_ip);
    FREE(&handle);
}


