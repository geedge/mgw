#include "mgw_utils.h"
#include "vpn_monitor.h"

struct hub_info
{
    char name[MGW_SYMBOL_MAX];
    char passwd[MGW_SYMBOL_MAX];
    unsigned int dhcp_begin_ip;
    unsigned int dhcp_end_ip;
}hub_info_t;
#define MAX_HUB_NUM 20

struct vpn_monitor_handle
{ 
    void *logger;
    char server_ip[MGW_SYMBOL_MAX];
    int server_port;
    char server_passwd[MGW_SYMBOL_MAX];
    struct hub_info hubs[MAX_HUB_NUM];
    int hub_num;
    MESA_htable_handle ip2user_htable;  // should be thread-safe
    struct field_stat_handle *fs_handle;
};

static long ip2user_cb_to_del_key(void *data, const uchar *key, uint size, void *user_arg)
{
    unsigned char _key[MGW_SYMBOL_MAX];
    memcpy((char *)_key, key, size);
    _key[size] = '\0';
    struct vpn_monitor_handle *handle = (struct vpn_monitor_handle *)user_arg;
    struct field_stat_handle *fs_handle = handle->fs_handle;
    if(data != NULL)
    {
        FS_operate(fs_handle->handle, fs_handle->line_ip2user, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        MGW_LOG_INFO(handle->logger, "MESA_htable: key existed, table is %s, key is %s", "ip2user_htable", _key);
        int rtn = MESA_htable_del(handle->ip2user_htable, key, size, NULL);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at del, errno is %d, table is %s, key is %s", rtn, "ip2user_htable", _key);
            return HTABLE_QUERY_CB_FAILURE;
        }
        FS_operate(fs_handle->handle, fs_handle->line_ip2user, fs_handle->cloumn_element_num, FS_OP_ADD, -1);
        MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at del, table is %s, key is %s", "ip2user_htable", _key);
    }
    FS_operate(fs_handle->handle, fs_handle->line_ip2user, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
    return HTABLE_QUERY_CB_SUCCESS;
}


static struct vpn_monitor_handle * vpn_monitor_init(void *args)
{
    struct vpn_monitor_args *_args = (struct vpn_monitor_args *)args;
    struct vpn_monitor_handle *handle = ALLOC(struct vpn_monitor_handle, 1);
    handle->logger = _args->logger;
    handle->ip2user_htable = _args->ip2user_htable;
    handle->fs_handle = _args->fs_handle;
    const char *profile = _args->profile;
    const char *section = "vpn_server";
    char hub_list_str[MGW_STRING_MAX];
    MESA_load_profile_string_def(profile, section, "server_ip", handle->server_ip, sizeof(handle->server_ip), "localhost");
    MESA_load_profile_int_def(profile, section, "server_port", &(handle->server_port), 443);
    MESA_load_profile_string_def(profile, section, "server_passwd", handle->server_passwd, sizeof(handle->server_passwd), "111111");
    MESA_load_profile_string_def(profile, section, "hub_list", hub_list_str, sizeof(hub_list_str), "{NewHub0|111111}");
    MGW_LOG_INFO(handle->logger, "MESA_prof_load, [%s]:\n server_ip: %s\n server_port: %d\n server_passwd: %s\n hub_list: %s",
                 "vpn_server", handle->server_ip, handle->server_port, handle->server_passwd, hub_list_str);
    char *token;
    char *rest = hub_list_str;
    handle->hub_num = 0;
    while((token = strtok_r(rest, ",", &rest)))
    {
        //printf("token is %s\n", token);
        char hub_name[MGW_SYMBOL_MAX];
        char hub_passwd[MGW_SYMBOL_MAX];
        char dhcp_begin_ip[MGW_SYMBOL_MAX];
        char dhcp_end_ip[MGW_SYMBOL_MAX];
        sscanf(token, "{%s %s %s %[^}]", hub_name, hub_passwd, dhcp_begin_ip, dhcp_end_ip);
        strncpy(handle->hubs[handle->hub_num].name, hub_name, MGW_SYMBOL_MAX);
        strncpy(handle->hubs[handle->hub_num].passwd, hub_passwd, MGW_SYMBOL_MAX);
        unsigned int _dhcp_begin_ip = inet_network(dhcp_begin_ip);
        if(_dhcp_begin_ip == INADDR_NONE)
        {
            MGW_LOG_ERROR(handle->logger, "Invalid dhcp_begin_ip: %s", dhcp_begin_ip);
            continue;
        }
        handle->hubs[handle->hub_num].dhcp_begin_ip = _dhcp_begin_ip;
        unsigned int _dhcp_end_ip = inet_network(dhcp_end_ip);
        //printf("_dhcp_end_ip is %d\n", _dhcp_end_ip);
        if(_dhcp_end_ip == INADDR_NONE)
        {
            MGW_LOG_ERROR(handle->logger, "Invalid dhcp_end_ip: %s", dhcp_end_ip);
            continue;
        }
        handle->hubs[handle->hub_num].dhcp_end_ip = _dhcp_end_ip;
        handle->hub_num ++;
    }
    FREE(&args);
    return handle;
}

/*
static void * vpn_monitor_destroy(struct vpn_monitor_handle *handle)
{
    FREE(&handle);
}
*/

static void get_ip2user_by_vpncmd(struct vpn_monitor_handle *handle)
{
    const char *server_ip = handle->server_ip;
    int server_port = handle->server_port;
    struct field_stat_handle *fs_handle = handle->fs_handle;
    const char *server_passwd = handle->server_passwd;
    char get_sessions_cmd[MGW_STRING_MAX];
    char get_iptables_cmd[MGW_STRING_MAX];
    char buff[MGW_STRING_MAX];
    int i;
    for(i = 0; i < handle->hub_num; i++)
    {
        const char *hub_name = handle->hubs[i].name;
        const char *hub_passwd = handle->hubs[i].passwd;
        unsigned int dhcp_begin_ip = handle->hubs[i].dhcp_begin_ip;
        unsigned int dhcp_end_ip = handle->hubs[i].dhcp_end_ip;
        snprintf(get_sessions_cmd, MGW_STRING_MAX, "vpncmd %s:%d /SERVER /PASSWORD:%s /HUB:%s /PASSWORD:%s /CSV /CMD SessionList", 
                    server_ip, server_port, server_passwd, hub_name, hub_passwd);
        snprintf(get_iptables_cmd, MGW_STRING_MAX, "vpncmd %s:%d /SERVER /PASSWORD:%s /HUB:%s /PASSWORD:%s /CSV /CMD IPTable",
                    server_ip, server_port, server_passwd, hub_name, hub_passwd);

        //get_iptables_cmd
        //printf("get_iptables_cmd: %s\n", get_iptables_cmd);
        FILE *get_iptables_fp = popen(get_iptables_cmd, "r");
        if(get_iptables_fp == NULL)
        {
            MGW_LOG_ERROR(handle->logger, "Failed at popen, cmd is %s", get_iptables_cmd);
            fclose(get_iptables_fp);
            return;
        }
        fgets(buff, MGW_STRING_MAX, get_iptables_fp);
        if(buff == NULL)
        {
            MGW_LOG_ERROR(handle->logger, "Failed at get_iptables_cmd: %s", "result is null");
            fclose(get_iptables_fp);
            return;
        }
        if(strstr(buff, "Error occurred") != NULL)
        {
            fgets(buff, MGW_STRING_MAX, get_iptables_fp);
            MGW_LOG_ERROR(handle->logger, "Failed at get_iptables_cmd: %s", buff);
            fclose(get_iptables_fp);
            return;
        }
        //ID,Session Name,IP Address,Created at,Updated at,Location
        //1549233234,SID-TESTING10-182,192.168.11.167,2018-11-05 15:02:30,2018-11-05 15:29:02,On 'localhost.localdomain'
        //user_name不区分大小写，不能包含-，数据库中一律存小写
        while(fgets(buff, MGW_STRING_MAX, get_iptables_fp))
        {
            char id[MGW_SYMBOL_MAX];
            char sess_name[MGW_SYMBOL_MAX];
            char dhcp_ip[MGW_SYMBOL_MAX];
            sscanf(buff, "%[^,],%[^,],%[^,]", id, sess_name, dhcp_ip);

            //get ip and user_name
            char *user_name = ALLOC(char, MGW_SYMBOL_MAX);
            sscanf(sess_name, "SID-%[^-]", user_name);
            //change to lower case
            for(size_t i = 0; i < strnlen(user_name, MGW_SYMBOL_MAX); i ++)
            {
                if(user_name[i] >= 'A' && user_name[i] <= 'Z')
                {
                    user_name[i] = user_name[i] - 'A' + 'a';
                }
            }

            char ip[MGW_SYMBOL_MAX];
            sscanf(dhcp_ip, "%s", ip);

            //find ip in dhcp range
            uint32_t _ip = inet_network(ip);
            if(_ip == INADDR_NONE)
            {
                MGW_LOG_ERROR(handle->logger, "Invalid dhcp_ip: %s", ip);
                FREE(&user_name);
                continue;
            }
            if(_ip > dhcp_end_ip || _ip < dhcp_begin_ip)
            {
                MGW_LOG_INFO(handle->logger, "Not in dhcp range, ip is %s", ip);
                FREE(&user_name);
                continue;
            }
            //set ip2user
            long cb_rtn = -1;
            uint32_t key = inet_addr(ip);
            MESA_htable_search_cb(handle->ip2user_htable, (const unsigned char *)(&key), sizeof(key), ip2user_cb_to_del_key, (void *)handle, &cb_rtn);
            FS_operate(fs_handle->handle, fs_handle->line_ip2user, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
            int rtn = MESA_htable_add(handle->ip2user_htable, (const unsigned char *)(&key), sizeof(key), user_name);
            if(rtn < 0)
            {
                MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at add, table is %s, key is %s, value is %s", "ip2user_htable", ip, user_name);
                FREE(&user_name);
                continue;
            }
            FS_operate(fs_handle->handle, fs_handle->line_ip2user, fs_handle->cloumn_element_num, FS_OP_ADD, 1);
            MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at add, table is %s, key is %s, value is %s", "ip2user_htable", ip, user_name);
        }
        fclose(get_iptables_fp);
    }
}


void * thread_vpn_monitor(void* args)
{
    struct vpn_monitor_handle *handle = vpn_monitor_init(args);
    while(1)
    {
        //printf("vpn monitor--------------\n");
        get_ip2user_by_vpncmd(handle);
        sleep(60);
    }
    return NULL;
}