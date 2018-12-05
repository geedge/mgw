

#include "mgw_utils.h"
#include "ip_mgr.h"
#define GROUP_IP_MAX 4096

struct ip_mgr_handle
{
    void *logger;
    Maat_feather_t Maat_feather_cand;
    Maat_feather_t Maat_feather_policy;
    MESA_htable_handle user_policy_htable;  //expire_time: 0
    MESA_htable_handle cand_ip_group_htable; //expire_time: 0
    MESA_htable_handle cand_ip_detail_htable; //expire_time: 0
    struct field_stat_handle *fs_handle;
};

struct user_policy_htable_value
{
    char user_name[MGW_SYMBOL_MAX];
    int group_id;
};

struct cand_ip_group_htable_value
{
    uint32_t ip_list[GROUP_IP_MAX];
    unsigned int num;
};

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


int ip_mgr_candidata_ip_get(struct ip_mgr_handle *handle, const char *user_name, uint32_t *selected_ip)
{
    struct field_stat_handle *fs_handle = handle->fs_handle;
    void *logger = handle->logger;
    long user_policy_cb_rtn = 0;
    int group_id;
    int key_size = strnlen(user_name, MGW_SYMBOL_MAX);
    MESA_htable_search_cb(handle->user_policy_htable, (const unsigned char *)user_name, key_size, user_policy_htable_query_cb, &group_id, &user_policy_cb_rtn);
    FS_operate(fs_handle->handle, fs_handle->line_user_policy, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
    if(user_policy_cb_rtn == HTABLE_KEY_EXISTED)
    {
        FS_operate(fs_handle->handle, fs_handle->line_user_policy, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, key is %s, group id is %d", "user_policy", user_name, group_id);
        struct cand_ip_group_htable_value *ip_group = NULL;
        ip_group = (struct cand_ip_group_htable_value *)MESA_htable_search(handle->cand_ip_group_htable, (const unsigned char *)(&group_id), sizeof(group_id));
        FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
        if(ip_group != NULL)
        {
            MGW_LOG_INFO(logger, "MESA_htable: key existed. table is %s, key is %d", "cand_ip_group_htable", group_id);
            FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
            unsigned int num = ip_group->num;
            if(num <= 0)
            {
                MGW_LOG_ERROR(logger, "The cand_ip is empty, group_id is %d", group_id);
                return -1;
            }
            unsigned int index = mgw_utils_get_random(num);
            *selected_ip = ip_group->ip_list[index];
            return 0;
        }
        else
        {
            FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
            MGW_LOG_ERROR(logger, "MESA_htable: key not existed. table is %s, key is %d", "cand_ip_group_htable", group_id);
            return -1;
        }
    }
    else
    {
        FS_operate(fs_handle->handle, fs_handle->line_user_policy, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        MGW_LOG_ERROR(logger, "MESA_htable: key not existed. table is %s, key is %s", "user_policy_htable", user_name);
        return -1;
    }
}

static void user_policy_htable_data_free_cb(void *data)
{
    FREE(&data);
}

static void cand_ip_group_htable_data_free_cb(void *data)
{
    FREE(&data);
}


static int delete_ip_from_group(uint32_t ip, struct cand_ip_group_htable_value *ip_group)
{
    int num = ip_group->num;
    int pos = -1;
    for(int i = 0; i < num; i++)
    {
        if(ip_group->ip_list[i] == ip)
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
        ip_group->ip_list[i] = ip_group->ip_list[i + 1];
    }
    ip_group->num --;
    return 0;
}


static void Maat_user_policy_start_cb(int update_type, void* args)
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
    struct field_stat_handle *fs_handle = handle->fs_handle;
    MGW_LOG_INFO(logger, "Maat_redis: update callback, table is USER_POLICY_TABLE");
    int config_id, group_id, is_valid;
    char user_type[MGW_SYMBOL_MAX];
    char user_name[MGW_SYMBOL_MAX];
    char translate_param[MGW_STRING_MAX];
    int do_log;
    int action;
    int service_id;
    printf("table line is %s\n", table_line);
    sscanf(table_line, "%d %d %s %s %s %d %d %d %d", &config_id, &group_id, user_type, user_name, translate_param, &do_log, &action, &service_id, &is_valid);
    printf("user name is %s\n", user_name);
    struct user_policy_htable_value *value = ALLOC(struct user_policy_htable_value, 1);
    strncpy(value->user_name, user_name, MGW_SYMBOL_MAX);
    value->group_id = group_id;
    int key_size = strnlen(user_name, MGW_SYMBOL_MAX);
    if(is_valid == 1)
    {
        //add user_policy_htable
        int rtn = MESA_htable_add(handle->user_policy_htable, (const unsigned char *)user_name, key_size, value);
        if(rtn < 0 && rtn != MESA_HTABLE_RET_DUP_ITEM)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at add, table is %s, user_name is %s, group_id is %d, rtn is %d", "user_policy_htable", user_name, group_id, rtn);
            return;
        }
        if(rtn >= 0)
        {
            MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at add, table is %s, user_name is %s, group_id is %d", "user_policy_htable", user_name, group_id);
            FS_operate(fs_handle->handle, fs_handle->line_user_policy, fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        }
    }
    else
    {
        //del user_policy_htable
        int rtn = MESA_htable_del(handle->user_policy_htable, (const unsigned char *)user_name, key_size, NULL);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at del, table is %s, user_name is %s, group_id is %d, rtn is %d", "user_policy_htable", user_name, group_id, rtn);
            return;
        }
        MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at del, table is %s, user_name is %s, group_id is %d", "user_policy_htable", user_name, group_id);
        FS_operate(fs_handle->handle, fs_handle->line_user_policy, fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    }
	return;
}


static void Maat_user_policy_finish_cb(void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: finish callback, table is USER_POLICY_TABLE");
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

static void Maat_cand_ip_start_cb(int update_type,void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: start callback, table is CAND_IP_TABLE, updata_type is %d\n", update_type);
	return;
}

static void Maat_cand_ip_update_cb(int table_id, const char* table_line, void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    struct field_stat_handle *fs_handle = handle->fs_handle;
    void *logger = handle->logger;
	MGW_LOG_INFO(logger, "Maat_redis: update callback, table is CAND_IP_TABLE");
    //MGW_LOG_INFO(logger, "Maat_redis: update callback, table_line is %s", table_line);
    int config_id, group_id, addr_type, location, link_id, encap_type, direction, is_valid, vpn_id;
    char ip_addr[IP_MGR_IP_LEN];
    char mrl_ip[IP_MGR_IP_LEN];
    char outer_sport[IP_MGR_PORT_LEN];
    char outer_dport[IP_MGR_PORT_LEN];
    char outer_sip[IP_MGR_IP_LEN];
    char outer_dip[IP_MGR_IP_LEN];
    char outer_smac[IP_MGR_MAC_LEN];
    char outer_dmac[IP_MGR_MAC_LEN];
    char inner_smac[IP_MGR_MAC_LEN];
    char inner_dmac[IP_MGR_MAC_LEN];
    sscanf(table_line, "%d %d %d %s %d %s %d %d %d %d %s %s %s %s %s %s %s %s %d", 
     &config_id, &group_id, &addr_type, ip_addr, &location, mrl_ip, &link_id, &encap_type, &direction, &vpn_id, outer_sport, 
        outer_dport, outer_sip, outer_dip, outer_smac, outer_dmac, inner_smac, inner_dmac, &is_valid);
    uint32_t ip = inet_addr(ip_addr);
    if(is_valid == 1)
    {
        //add cand_ip_group_htable
        struct cand_ip_group_htable_value *ip_group = NULL;
        ip_group = (struct cand_ip_group_htable_value *)MESA_htable_search(handle->cand_ip_group_htable, (const unsigned char *)(&group_id), sizeof(group_id));
        FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
        if(ip_group == NULL)
        {
            MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s, group_id is %d", "cand_ip_group_htable", group_id);
            FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
            ip_group = ALLOC(struct cand_ip_group_htable_value, 1);
            ip_group->num = 0;
            int rtn = MESA_htable_add(handle->cand_ip_group_htable, (const unsigned char *)&group_id, sizeof(group_id), (void *)ip_group);
            if(rtn < 0)
            {
                MGW_LOG_ERROR(logger, "MESA_htable: Failed at add, table is %s, group_id is %d, rtn is %d", "cand_ip_group_htable", group_id, rtn);
                return;
            }
            MGW_LOG_INFO(logger, "MESA_htable: Succeed at add, table is %s, group_id is %d", "cand_ip_group_htable", group_id);
            FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        }
        else
        {
            MGW_LOG_INFO(logger, "MESA_htable: key not existed, table is %s, group_id is %d", "cand_ip_group_htable", group_id);
            FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        }
        struct ip_mgr_cand_ip_detail *_cand_ip = ALLOC(struct ip_mgr_cand_ip_detail, 1);
        _cand_ip->ip = ip;
         _cand_ip->reference = 0;
        struct ip_mgr_vxlan_info *vxlan_info = ALLOC(struct ip_mgr_vxlan_info, 1);

        strncpy(vxlan_info->vxlan_outer_local_port, outer_sport, IP_MGR_PORT_LEN);
        strncpy(vxlan_info->vxlan_outer_gdev_port, outer_dport, IP_MGR_PORT_LEN);
        strncpy(vxlan_info->vxlan_outer_local_ip, outer_sip, IP_MGR_IP_LEN);
        strncpy(vxlan_info->vxlan_outer_gdev_ip, outer_dip, IP_MGR_IP_LEN);
        strncpy(vxlan_info->vxlan_outer_local_mac, outer_smac, IP_MGR_MAC_LEN);
        strncpy(vxlan_info->vxlan_outer_gdev_mac, outer_dmac, IP_MGR_MAC_LEN);
        strncpy(vxlan_info->vxlan_inner_smac, inner_smac, IP_MGR_MAC_LEN);
        strncpy(vxlan_info->vxlan_inner_dmac, inner_dmac, IP_MGR_MAC_LEN);
        vxlan_info->vxlan_link_id = link_id;
        vxlan_info->vxlan_link_dir = direction;
        vxlan_info->vxlan_encap_type = encap_type;
        vxlan_info->vxlan_vpn_id = vpn_id;

        _cand_ip->vxlan_info = vxlan_info;
        _cand_ip->mrl_ip = inet_addr(mrl_ip);
        int num = ip_group->num;
        ip_group->ip_list[num] = ip;
        ip_group->num ++;
        
        //add to cand_ip_detail_htable
        int rtn = MESA_htable_add(handle->cand_ip_detail_htable, (const unsigned char *)&ip, sizeof(ip), (void *)_cand_ip);
        if(rtn < 0 && rtn != MESA_HTABLE_RET_DUP_ITEM)
        {
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at add, table is %s, ip is %s, rtn is %d", "cand_ip_detail_htable", rtn);
            return;
        }
        if(rtn >= 0)
        {
            MGW_LOG_INFO(logger, "MESA_htable: Succeed at add, table is %s, ip is %s", "cand_ip_detail_htable", ip_addr);
            FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        }
    }
    else
    {
        //delete from cand_ip_group_htable
        struct cand_ip_group_htable_value *ip_group = NULL;
        ip_group = (struct cand_ip_group_htable_value *)MESA_htable_search(handle->cand_ip_group_htable, (const unsigned char *)(&group_id), sizeof(group_id));
        FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
        if(ip_group == NULL)
        {
            FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at del ip from ip_group, group_id %d not existed in cand_ip_group_htable", group_id);
            return;
        }
        FS_operate(fs_handle->handle, fs_handle->line_ip_group, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        int rtn = delete_ip_from_group(ip, ip_group);
        if(rtn == -1)
        {
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at del ip from ip_group, ip %s not in group %d", ip_addr, group_id);
            return;
        }

        //delete from cand_ip_detail_htable
        struct ip_mgr_cand_ip_detail *cand_ip = NULL;
        cand_ip = (struct ip_mgr_cand_ip_detail *)MESA_htable_search(handle->cand_ip_detail_htable, (const unsigned char *)(&ip), sizeof(ip));
        FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
        if(cand_ip == NULL)
        {
            FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at del ip from cand_ip_detail_htable, key %s not existed", ip_addr);
            return;
        }
        FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        rtn = MESA_htable_del(handle->cand_ip_detail_htable, (const unsigned char *)(&ip), sizeof(ip), NULL);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at del, table is %s, ip is %s, rtn is %d", "cand_ip_detail_htable", ip_addr, rtn);
            return;
        }
        MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at del, table is %s, ip is %s", "cand_ip_detail_htable", ip_addr);
        FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    }
	return;
}


static void Maat_cand_ip_finish_cb(void* args)
{
    struct ip_mgr_handle *handle = (struct ip_mgr_handle *)args;
    void *logger = handle->logger;
    MGW_LOG_INFO(logger, "Maat_redis: finish callback, table is CAND_IP_TABLE");
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


struct ip_mgr_handle *ip_mgr_init(const char *profile, MESA_htable_handle cand_ip_detail_htable, struct field_stat_handle *fs_handle, 
                Maat_feather_t Maat_feather_cand, Maat_feather_t Maat_feather_policy, void *logger)
{
    struct ip_mgr_handle *handle = ALLOC(struct ip_mgr_handle, 1); 
    handle->logger = logger;
    handle->Maat_feather_cand = Maat_feather_cand;
    handle->Maat_feather_policy = Maat_feather_policy;
    handle->fs_handle = fs_handle;
    handle->cand_ip_detail_htable = cand_ip_detail_htable;
    handle->user_policy_htable = mgw_utils_create_htable(profile, "user_policy_htable", (void *)user_policy_htable_data_free_cb, NULL, logger);
    handle->cand_ip_group_htable = mgw_utils_create_htable(profile, "cand_ip_group_htable", (void *)cand_ip_group_htable_data_free_cb, NULL, logger);
    int rtn = Maat_plugin_register(Maat_feather_policy, "IR_SNAT_POLICY", Maat_user_policy_start_cb, Maat_user_policy_update_cb, Maat_user_policy_finish_cb, handle);
    if(rtn == -1)
    {
        return NULL;   
    }
    rtn = Maat_plugin_register(Maat_feather_cand, "IR_CANDIDATE_IP", Maat_cand_ip_start_cb, Maat_cand_ip_update_cb, Maat_cand_ip_finish_cb, handle);
    if(rtn == -1)
    {
        return NULL;
    }
    return handle;
}

void ip_mgr_destroy(struct ip_mgr_handle *handle)
{
    MESA_htable_destroy(handle->user_policy_htable, NULL);
    MESA_htable_destroy(handle->cand_ip_group_htable, NULL);
    FREE(&handle);
}




