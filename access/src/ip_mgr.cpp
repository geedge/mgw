

#include "mgw_utils.h"
#include "ip_mgr.h"
#define GROUP_IP_MAX 4096

/*
{
	"plugin_table":[   
		{
	  	"table_name":"IR_CANDINATE_IP",
	  	"table_content":[
                "1\t101\t4\t202.104.1.123\t0\t192.168.10.180\t1\t0\t0\t4789\t50000\t192.168.14.1\t10.2.2.2\t24:6e:96:c9:77:d0\t00:1e:73:6c:fa:44\te8:61:1f:13:70:7a\t18:31:bf:e4:a5:a0\t1"	  		
				]
	 	},
	 	{
	  	"table_name":"IR_POLICY",
	  	"table_content":[
                "1\t101\t0\tuser\t1"
	  			]
	 	}
    ]
}
*/

struct ip_mgr_handle
{
    void *logger;
    Maat_feather_t feather;
    MESA_htable_handle user_policy_htable;  //expire_time: 0
    MESA_htable_handle cand_ip_htable; //expire_time: 0
    MESA_htable_handle ip_verify_htable; //expire_time: 0
};

struct user_policy_htable_value
{
    char user_name[MGW_SYMBOL_MAX];
    int group_id;
};

struct ip_verify_htable_value
{
    uint32_t ip;
    bool is_valid;
};
struct cand_ip_htable_value
{
    struct cand_ip *ip_group[GROUP_IP_MAX];
    unsigned int num;
};


static long ip_verify_htable_query_cb(void *data, const uchar *key, uint size, void *user_args)
{
    bool *is_valid = (bool *)user_args;
    if(data != NULL)
    {
        struct ip_verify_htable_value *_data = (struct ip_verify_htable_value*)data;
        *is_valid = _data->is_valid;
        return HTABLE_KEY_EXISTED; 
    }
    return HTABLE_KEY_NOT_EXISTED;
}

bool ip_mgr_candidate_ip_verify(struct ip_mgr_handle *handle, uint32_t ip)
{
    long ip_verify_cb_rtn = 0;
    bool is_valid;
    MESA_htable_search_cb(handle->ip_verify_htable, (const unsigned char *)(&ip), sizeof(ip), ip_verify_htable_query_cb, &is_valid, &ip_verify_cb_rtn);
    if(ip_verify_cb_rtn == HTABLE_KEY_EXISTED)
    {
        if(is_valid == true)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}


static long user_policy_htable_query_cb(void *data, const uchar *key, uint size, void *user_args)
{
    struct user_policy_htable_value *value = (struct user_policy_htable_value *)data;
    int *group_id = (int *)user_args;
    if(data != NULL)
    {
        *group_id = value->group_id;
        return HTABLE_KEY_EXISTED;
    }
    return HTABLE_KEY_NOT_EXISTED;
}


struct cand_ip* ip_mgr_candidata_ip_get(struct ip_mgr_handle *handle, const char *user_name)
{
    void *logger = handle->logger;
    long user_policy_cb_rtn = 0;
    int group_id;
    int key_size = strnlen(user_name, MGW_SYMBOL_MAX);
    MESA_htable_search_cb(handle->user_policy_htable, (const unsigned char *)user_name, key_size, user_policy_htable_query_cb, &group_id, &user_policy_cb_rtn);
    if(user_policy_cb_rtn == HTABLE_KEY_EXISTED)
    {
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, key is %s, group id is %d", "user_policy", user_name, group_id);
        struct cand_ip_htable_value *ip_group = NULL;
        ip_group = (struct cand_ip_htable_value *)MESA_htable_search(handle->cand_ip_htable, (const unsigned char *)(&group_id), sizeof(group_id));
        if(ip_group != NULL)
        {
            unsigned int num = ip_group->num;
            if(num <= 0)
            {
                MGW_LOG_ERROR(logger, "The cand_ip is empty, group_id is %d", group_id);
                return NULL;
            }
            unsigned int index = mgw_utils_get_random(num);
            return ip_group->ip_group[index];
        }
        else
        {
            MGW_LOG_ERROR(logger, "MESA_htable: key not existed. table is %s, key is %d", "cand_ip_htable", group_id);
            return NULL;
        }
    }
    else
    {
        MGW_LOG_ERROR(logger, "MESA_htable: key not existed. table is %s, key is %s", "user_policy_htable", user_name);
        return NULL;
    }
}

static void user_info_htable_data_free_cb(void *data)
{
    FREE(&data);
}

static void cand_ip_htable_data_free_cb(void *data)
{
    FREE(&data);
}

static void ip_verify_htable_data_free_cb(void *data)
{
    FREE(&data);
}

static int delete_ip_from_group(uint32_t ip, struct cand_ip_htable_value *ip_group)
{
    int num = ip_group->num;
    int pos = -1;
    for(int i = 0; i < num; i++)
    {
        if(ip_group->ip_group[i]->ip == ip)
        {
            pos = i;
            break;
        }
    }
    if(pos == -1)
    {
        return -1;
    }
    for(int i = pos; i < num - 1; i++)
    {
        ip_group->ip_group[i] = ip_group->ip_group[i + 1];
    }
    ip_group->num --;
    return 0;
}


static void Maat_user_policy_start_cb(int update_type,void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: start callback, table is USER_POLICY_TABLE");
	return;
}

static void Maat_user_policy_update_cb(int table_id, const char* table_line, void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: update callback, table is USER_POLICY_TABLE");
    int config_id, group_id, user_type, is_valid;
    char user_name[MGW_SYMBOL_MAX];
    sscanf(table_line, "%d %d %d %s %d", &config_id, &group_id, &user_type, user_name, &is_valid);
    struct user_policy_htable_value *value = ALLOC(struct user_policy_htable_value, 1);
    strncpy(value->user_name, user_name, MGW_SYMBOL_MAX);
    value->group_id = group_id;
    int key_size = strnlen(user_name, MGW_SYMBOL_MAX);
    if(is_valid == 1)
    {
        //add user_policy_htable
        int rtn = MESA_htable_add(handle->user_policy_htable, (const unsigned char *)user_name, key_size, value);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: failed at add, table is %s, user_name is %s, group_id is %d", "user_policy_htable", user_name, group_id);
        }
    }
    else
    {
        //del user_policy_htable
        int rtn = MESA_htable_del(handle->user_policy_htable, (const unsigned char *)user_name, key_size, NULL);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: failed at del, table is %s, user_name is %s, group_id is %d", "user_policy_htable", user_name, group_id);
        }
    }
	return;
}


static void Maat_user_policy_finish_cb(void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    Maat_feather_t feather = handle->feather;
    MGW_LOG_INFO(logger, "Maat_redis: finish callback, table is USER_POLICY_TABLE");
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

static void Maat_cand_ip_start_cb(int update_type,void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: start callback, table is CAND_IP_TABLE");
	return;
}

static void Maat_cand_ip_update_cb(int table_id, const char* table_line, void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
	MGW_LOG_INFO(logger, "Maat_redis: update callback, table is CAND_IP_TABLE");
    int config_id, group_id, addr_type, location, link_id, encap_type, direction, is_valid;
    char ip_addr[MGW_SYMBOL_MAX];
    char mrl_ip[MGW_SYMBOL_MAX];
    char outer_sport[MGW_SYMBOL_MAX];
    char outer_dport[MGW_SYMBOL_MAX];
    char outer_sip[MGW_SYMBOL_MAX];
    char outer_dip[MGW_SYMBOL_MAX];
    char outer_smac[MGW_SYMBOL_MAX];
    char outer_dmac[MGW_SYMBOL_MAX];
    char inner_smac[MGW_SYMBOL_MAX];
    char inner_dmac[MGW_SYMBOL_MAX];
    sscanf(table_line, "%d %d %d %s %d %s %d %d %d %s %s %s %s %s %s %s %s %d", &config_id, &group_id, &addr_type, ip_addr, &location, mrl_ip, &link_id, &encap_type, &direction, outer_sport, outer_dport, 
        outer_sip, outer_dip, outer_smac, outer_dmac, inner_smac, inner_dmac, &is_valid);
    uint32_t ip = inet_addr(ip_addr);
    if(is_valid == 1)
    {
        //add cand_ip_htable
        struct cand_ip_htable_value *ip_group = NULL;
        ip_group = (struct cand_ip_htable_value *)MESA_htable_search(handle->cand_ip_htable, (const unsigned char *)(&group_id), sizeof(group_id));
        if(ip_group == NULL)
        {
            ip_group = ALLOC(struct cand_ip_htable_value, 1);
            ip_group->num = 0;
            int rtn = MESA_htable_add(handle->cand_ip_htable, (const unsigned char *)&group_id, sizeof(group_id), (void *)ip_group);
            if(rtn < 0)
            {
                MGW_LOG_ERROR(logger, "MESA_htable: failed at add, table is %s, group_id is %d", "cand_ip_htable", group_id);
                return;
            }
        }
        struct cand_ip *_cand_ip = ALLOC(struct cand_ip, 1);
        _cand_ip->ip = ip;
        _cand_ip->reference = 0;
        int num = ip_group->num;
        ip_group->ip_group[num] = _cand_ip;
        ip_group->num ++;
    }
    else
    {
        struct cand_ip_htable_value *ip_group = NULL;
        ip_group = (struct cand_ip_htable_value *)MESA_htable_search(handle->cand_ip_htable, (const unsigned char *)(&group_id), sizeof(group_id));
        if(ip_group == NULL)
        {
            MGW_LOG_ERROR(logger, "Failed at del ip from ip_group, group_id %d not existed in cand_ip_htable", group_id);
            return;
        }
        int rtn = delete_ip_from_group(ip, ip_group);
        if(rtn == -1)
        {
            MGW_LOG_ERROR(logger, "Failed at del ip from ip_group, ip %s not in group %d", ip_addr, group_id);
            return;
        }
    }
	return;
}


static void Maat_cand_ip_finish_cb(void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    Maat_feather_t feather = handle->feather;
    MGW_LOG_INFO(logger, "Maat_redis: finish callback, table is CAND_IP_TABLE");
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

static int Maat_plugin_register(Maat_feather_t feather, const char* table_name, Maat_start_callback_t *start, 
                Maat_update_callback_t *update, Maat_finish_callback_t *finish, struct ip_mgr_handle *handle)
{
	int table_id = 0, ret = 0;
    void *logger = handle->logger;
	table_id = Maat_table_register(feather, table_name);
	if(table_id == -1)
	{
        MGW_LOG_ERROR(logger, "Maat_redis: database table %s register failed", table_name);
        return -1;
	}
	else
	{
		ret = Maat_table_callback_register(feather, table_id, start, update, finish, (void *)handle);
		if(ret < 0)
		{
            MGW_LOG_ERROR(logger, "Maat_redis: callback register table %s error", table_name);
            return -1;
		}
	}
	return 0;
}


struct ip_mgr_handle *ip_mgr_init(void *logger, Maat_feather_t feather, struct htable_opts* opts)
{
    struct ip_mgr_handle *handle = ALLOC(struct ip_mgr_handle, 1); 
    handle->logger = logger;
    handle->feather = feather;
    handle->user_policy_htable = mgw_utils_create_htable("user_info_htable", opts, (void *)user_info_htable_data_free_cb, NULL);
    handle->cand_ip_htable = mgw_utils_create_htable("cand_ip_htable", opts, (void *)cand_ip_htable_data_free_cb, NULL);
    handle->ip_verify_htable = mgw_utils_create_htable("ip_verify_htable", opts, (void *)ip_verify_htable_data_free_cb, NULL);
    Maat_plugin_register(feather, "USER_POLICY_TABLE", Maat_user_policy_start_cb, Maat_user_policy_update_cb, Maat_user_policy_finish_cb, handle);
    Maat_plugin_register(feather, "CAND_IP_TABLE", Maat_cand_ip_start_cb, Maat_cand_ip_update_cb, Maat_cand_ip_finish_cb, handle);
    return handle;
}

void ip_mgr_destroy(struct ip_mgr_handle *handle)
{
    MESA_htable_destroy(handle->user_policy_htable, user_info_htable_data_free_cb);
    MESA_htable_destroy(handle->cand_ip_htable, cand_ip_htable_data_free_cb);
    MESA_htable_destroy(handle->ip_verify_htable, ip_verify_htable_data_free_cb);
    FREE(&handle);
}




