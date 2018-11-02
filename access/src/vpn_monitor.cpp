#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include "MESA/MESA_prof_load.h"
#include "MESA/MESA_handle_logger.h"
#include "MESA/MESA_htable.h"
#include "mgw_utils.h"

struct hub_info
{
    char name[MGW_SYMBOL_MAX];
    char passwd[MGW_SYMBOL_MAX];
};
#define MAX_HUB_NUM 20

struct vpn_monitor_ctx
{ 
    char vpn_server_ip[MGW_SYMBOL_MAX];
    int vpn_server_port;
    char vpn_server_passwd[MGW_SYMBOL_MAX];
    struct hub_info hubs[MAX_HUB_NUM];
    int hub_num;
    MESA_htable_handle ip2user_htable;  // should be thread-safe
};

static int __wrapper_MESA_htable_set_opt(MESA_htable_handle table, enum MESA_htable_opt opt_type, unsigned value)
{
	int ret = MESA_htable_set_opt(table, opt_type, &value, (int)(sizeof(value)));
	assert(ret == 0);
	return ret;
}

static int __wrapper_MESA_htable_set_opt(MESA_htable_handle table, enum MESA_htable_opt opt_type, void * val, size_t len)
{
	int ret = MESA_htable_set_opt(table, opt_type, val, (int)len);
	if(unlikely(ret != 0))
    {
        MGW_LOG_ERROR("Failed at MESA_htable_set_opt, opt_type is %d", opt_type);
    }
	return ret;
}

static MESA_htable_handle create_ip2user_table()
{
	int ret = 0;
	unsigned max_num = slot_size * 4;
	MESA_htable_handle ip2user_htable = MESA_htable_born();
	__wrapper_MESA_htable_set_opt_int(htable, MHO_SCREEN_PRINT_CTRL, g_mgw_ctx._htable_opt->mho_screen_print_ctrl);
	__wrapper_MESA_htable_set_opt_int(htable, MHO_THREAD_SAFE, g_mgw_ctx._htable_opt->mho_thread_safe);
	__wrapper_MESA_htable_set_opt_int(htable, MHO_MUTEX_NUM, g_mgw_ctx._htable_opt->mho_mutex_num);
	__wrapper_MESA_htable_set_opt_int(htable, MHO_HASH_SLOT_SIZE, g_mgw_ctx._htable_opt->mho_hash_slot_size);
	__wrapper_MESA_htable_set_opt_int(htable, MHO_HASH_MAX_ELEMENT_NUM, g_mgw_ctx._htable_opt->mho_hash_slot_size * 4);
	__wrapper_MESA_htable_set_opt_int(htable, MHO_EXPIRE_TIME, g_mgw_ctx._htable_opt->mho_expire_time);
	__wrapper_MESA_htable_set_opt_int(htable, MHO_ELIMIMINATE_TYPE, HASH_ELIMINATE_ALGO_FIFO);
	ret = __wrapper_MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,
	    (void *)ip2user_htable_free_data, sizeof(&ip2user_htable_free_data));
	//ret = __wrapper_MESA_htable_set_opt(htable, MHO_CBFUN_DATA_EXPIRE_NOTIFY,
	//	(void *)key_keeper_verify_cb);
	ret = MESA_htable_mature(ip2user_htable);
	if(ret != 0)
    {
        MGW_LOG_ERROR("Failed at create ip2user_htable");
        exit(EXIT_FAILURE);
    }
	return ip2user_htable;
}

struct vpn_monitor_ctx * vpn_monitor_init()
{
    struct vpn_monitor_ctx *ctx = ALLOC(struct vpn_monitor_ctx, 1);
    ctx->ip2user_htable = create_ip2user_table();
    const char *section = "vpn_server";
    char hub_list_str[MGW_STRING_MAX];
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "vpn_server_ip", ctx->vpn_server_ip, sizeof(vpn_server_ip), "localhost");
    MESA_load_profile_int_def(g_mgw_ctx.profile, section, "vpn_server_port", &(ctx->vpn_server_port), 443);
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "vpn_server_passwd", ctx->vpn_server_passwd, sizeof(vpn_server_passwd), "111111");
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "hub_list", hub_list_str, sizeof(hub_list_str), "{NewHub0|111111}");
    char *token;
    char *rest = hub_list_str;
    ctx->hub_num = 0;
    while((token = strtok_r(rest, ",", &rest)))
    {
        //printf("token is %s\n", token);
        int len = strnlen(token, MGW_STRING_MAX);
        char *pos = strchr(token, '|');
        if(pos == NULL)
        {
            MGW_LOG_ERROR(g_mgw_ctx.logger, "Invalid hub conf, hub is %s", token);
            continue;
        }
        strncpy(ctx->hubs[i].name, token + 1, pos - token - 1);
        strncpy(ctx->hubs[i].passwd, pos + 1, len - 2 - (pos - token));
        ctx->hubs.num ++;
    }
    int i = 0;
    for(i = 0; i < ctx->hub_num; i++)
    {
        printf("Hub: name is %s, passwd is %s\n", ctx->hubs[i].name, ctx->hubs[i].passwd);
    }
    return ctx;
}

void * vpn_monitor_destroy(struct vpn_monitor_ctx *ctx)
{

}

static void get_ip2user_by_vpncmd(const char *vpn_server_ip, int vpn_server_port, const char *vpn_server_passwd, const char *hub_name, const char *hub_passwd)
{
    char vpncmd_get_sessions[MGW_STRING_MAX];
    char vpncmd_get_iptables[MGW_STRING_MAX];
    snprintf(vpncmd_get_sessions, MGW_STRING_MAX, "vpncmd %s:%d /SERVER /PASSWORD:%s /HUB:%s /PASSWORD:%s /CSV /CMD SessionList", 
                vpn_server_ip, vpn_server_port, vpn_server_passwd, hub_name, hub_passwd);
    snprintf(vpncmd_get_iptables, MGW_STRING_MAX, "vpncmd %s:%d /SERVER /PASSWORD:%s /HUB:%s /PASSWORD:%s /CSV /CMD IPTable",
                vpn_server_ip, vpn_server_port, vpn_server_passwd, hub_name, hub_passwd);
}

void * thread_vpn_monitor(void* arg)
{
    struct vpn_monitor_ctx ctx = vpn_monitor_init();
    g_mgw_ctx._vpn_monitor_ctx = ctx;
    sleep(10);
    for(i = 0; i < ctx.hub_num; i++)
    {
        get_ip2user_by_vpncmd(ctx->vpn_server_ip, ctx->vpn_server_port, ctx->vpn_server_passwd, ctx->hubs[i].name, ctx->hubs.passwd);
     }
}