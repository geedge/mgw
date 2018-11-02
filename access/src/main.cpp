
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include "MESA/MESA_prof_load.h"
#include "MESA/MESA_handle_logger.h"
#include "mgw_utils.h"
#include "Maat_rule.h"
#include "Maat_command.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct htable_opt
{
    int mho_screen_print_ctrl;
    int mho_thread_safe;
    int mho_mutex_num;
    int mho_hash_slot_size;
    int mho_expire_time;
}

struct mgw_ctx
{
    void* logger;
    const char *profile;
    Maat_feather_t Maat_feather;
    struct htable_opt *_htable_opt;
    struct vpn_monitor_ctx *_vpn_monitor_ctx;
};

struct mgw_ctx g_mgw_ctx;

static void wrapped_Maat_set_feather_opt(Maat_feather_t feather, enum MAAT_INIT_OPT type, const void* value, int size)
{
    int rtn = Maat_set_feather_opt(feather, type, value, size);
    if(unlikely(rtn < 0))
    {
        MGW_LOG_ERROR(g_mgw_ctx.logger, "Failed at Maat_set_feather_opt, type is %d", type);
        exit(EXIT_FAILURE);
    }
}

static void Maat_init()
{
    // load conf
    const char *section = "Maat";
    char table_info_path[MGW_PATH_MAX];
    int max_thread_num;
    char Maat_redis_ip[MGW_SYMBOL_MAX];
    int Maat_redis_port;
    char stat_file_path[MGW_PATH_MAX];
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "table_info_path", table_info_path, sizeof(table_info_path), "./conf/table_info.conf");
    MESA_load_profile_int_def(g_mgw_ctx.profile, section, "max_thread_num", &max_thread_num, 1);
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "Maat_redis_ip", Maat_redis_ip, sizeof(Maat_redis_ip), "127.0.0.1");
    MESA_load_profile_int_def(g_mgw_ctx.profile, section, "Maat_redis_port", &Maat_redis_port, 6379);
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "stat_file_path", stat_file_path, sizeof(stat_file_path), "./log/Maat_stat.log");

    // init Maat
    Maat_feather_t feather = NULL;
    feather = Maat_feather(max_thread_num, table_info_path, g_mgw_ctx.logger);
    if(feather == NULL)
    {
        exit(EXIT_FAILURE);
    }
    wrapped_Maat_set_feather_opt(feather, MAAT_OPT_INSTANCE_NAME, "mgw", strlen("mgw")+1);
	wrapped_Maat_set_feather_opt(feather, MAAT_OPT_REDIS_IP, Maat_redis_ip, strlen(Maat_redis_ip)+1);
	wrapped_Maat_set_feather_opt(feather, MAAT_OPT_REDIS_PORT, &Maat_redis_port, sizeof(Maat_redis_port));
    wrapped_Maat_set_feather_opt(feather, MAAT_OPT_STAT_FILE_PATH, stat_file_path, strlen(stat_file_path)+1);
    wrapped_Maat_set_feather_opt(feather, MAAT_OPT_STAT_ON, NULL, 0);
	wrapped_Maat_set_feather_opt(feather, MAAT_OPT_PERF_ON, NULL, 0);
    //wrapped_Maat_set_feather_opt(feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
	//wrapped_Maat_set_feather_opt(feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effective_interval_ms, sizeof(effective_interval_ms));
	//wrapped_Maat_set_feather_opt(feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	//wrapped_Maat_set_feather_opt(feather, MAAT_OPT_ACCEPT_TAGS, accept_tags, strlen(accept_tags)+1);
	int rtn = Maat_initiate_feather(feather);
    if(unlikely(rtn < 0))
    {
        MGW_LOG_ERROR(g_mgw_ctx.logger, "Failed at Maat_initiate_feather");
		exit(EXIT_FAILURE);
    }
    g_mgw_ctx.Maat_feather = feather;
}

static void htable_opt_init()
{
    struct htable_opt* _htable_opt = ALLOC(struct htable_opt, 1);
    const char *section = "htable_opt";
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "mho_screen_print_ctrl", _htable_opt->mho_screen_print_ctrl, sizeof(int), 0);
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "mho_thread_safe", _htable_opt->_htable_opt.mho_thread_safe, sizeof(int), 1);
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "mho_mutex_num", _htable_opt->_htable_opt.mho_mutex_num, sizeof(int), 16);
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "mho_hash_slot_size", _htable_opt->_htable_opt.mho_hash_slot_size, sizeof(int), 16);
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "mho_expire_time", _htable_opt->_htable_opt.mho_expire_time, sizeof(int), -1);
    g_mgw_ctx._htable_opt = _htable_opt;
}

static void mgw_init()
{
    g_mgw_ctx.profile = "./conf/mgw.conf";
	const char *section = "global";
    char log_path[MGW_PATH_MAX];
    MESA_load_profile_string_def(g_mgw_ctx.profile, section, "log_path", log_path, sizeof(log_path), "./log/mgw.log");
    void *logger = MESA_create_runtime_log_handle(log_path, RLOG_LV_DEBUG);
    if (unlikely(logger == NULL))
	{
		MGW_LOG_ERROR(g_mgw_ctx.logger, "Failed at creating logger: %s", log_path);
		exit(EXIT_FAILURE);
	}
    g_mgw_ctx.logger = logger;
    htable_opt_init();
    Maat_init();
    pthread_t thread_id;
    int rtn = pthread_create(&thread_id, NULL, thread_vpn_monitor, NULL);
    if(unlikely(rtn != 0))
    {
        MGW_LOG_ERROR(g_mgw_ctx.logger, "Failed at creating thread_vpn_monitor");
        exit(EXIT_FAILURE);
    }
}

static void mgw_destroy()
{
    MESA_destroy_runtime_log_handle(g_mgw_ctx.logger);
    Maat_burn_feather(g_mgw_ctx.Maat_feather);
}

static void mgw_run()
{
    while(1)
    {
        
    }
}

int main(int argc, char* argv[])
{
    mgw_init();
    mgw_run();
}

#ifdef __cplusplus
}
#endif

