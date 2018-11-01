
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "MESA/MESA_prof_load.h"
#include "MESA/MESA_handle_logger.h"
#include "MESA/Maat_rule.h"
#include "MESA/Maat_command.h"
#include "mgw_utils.h"


#ifdef __cplusplus
extern "C"
{
#endif

struct mgw_ctx
{
    void* logger;
    const char *profile;
    Maat_feather_t Maat_feather;
};
struct mgw_ctx g_mgw_ctx;

void wrapped_Maat_set_feather_opt(Maat_feather_t feather, enum MAAT_INIT_OPT type, const void* value, int size)
{
    int rtn = Maat_set_feather_opt(feather, type, value, size);
    if(unlikely(rtn < 0))
    {
        MGW_LOG_ERROR(g_mgw_ctx.logger, "Failed at Maat_set_feather_opt, type is %d", type);
        exit(EXIT_FAILURE);
    }
}

void Maat_init()
{
    // load conf
    const char *section = "Maat";
    char table_info_path[MGW_PATH_MAX];
    int max_thread_num;
    char Maat_redis_ip[MGW_STRING_MAX];
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
void mgw_init()
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
    Maat_init();
}

void mgw_destroy()
{
    MESA_destroy_runtime_log_handle(g_mgw_ctx.logger);
    Maat_burn_feather(g_mgw_ctx.Maat_feather);
}

#define	TEST_CMD_LINE_NUM	4
void Maat_test_set_cmd_line(Maat_feather_t feather)
{
	const struct Maat_line_t *p_line[TEST_CMD_LINE_NUM];
	struct Maat_line_t line_rule[TEST_CMD_LINE_NUM];
	char table_line[TEST_CMD_LINE_NUM][128];
	int ret=0,i=0;
	memset(&line_rule,0,sizeof(line_rule));
	for(i=0;i<TEST_CMD_LINE_NUM;i++)
	{
		line_rule[i].label_id=0;
		//line_rule[i].rule_id=(int)Maat_cmd_incrby(feather,"TEST_PLUG_SEQ", 1);
        line_rule[i].rule_id = i + 1;
		line_rule[i].table_name="QD_ENTRY_INFO";
		snprintf(table_line[i],sizeof(table_line[i]),"1\t192.168.0.1\t%d\t1",100+i);
		line_rule[i].table_line=table_line[i];
		line_rule[i].expire_after=0;
		p_line[i]=line_rule+i;
	}
	

	//ret=Maat_cmd_set_lines(feather, p_line, TEST_CMD_LINE_NUM, MAAT_OP_ADD);
	//assert(ret>0);
	for(i=0;i<TEST_CMD_LINE_NUM;i++)
	{
		line_rule[i].table_line=NULL;
	}
	ret=Maat_cmd_set_lines(feather, p_line,TEST_CMD_LINE_NUM, MAAT_OP_DEL);
	assert(ret>0);
	return;
}

void Maat_redis_start_cb(int update_type,void* u_para)
{
    MGW_LOG_INFO(g_mgw_ctx.logger, "call Maat_redis_start_cb");
	return;
}
void Maat_redis_update_cb(int table_id,const char* table_line,void* u_para)
{
    printf("table_line is %s\n", table_line);
	MGW_LOG_INFO(g_mgw_ctx.logger, "call Maat_redis_update_cb");
	return;
}


void Maat_redis_finish_cb(void* u_para)
{
    MGW_LOG_INFO(g_mgw_ctx.logger, "call Maat_redis_finish_cb");
	Maat_feather_t feather=u_para;
	long long version=0;
	int ret=0,is_last_updating_table=0;
	ret=Maat_read_state(feather,MAAT_STATE_VERSION, &version, sizeof(version));
    printf("version is %d\n", version);
	assert(ret==0);

	ret=Maat_read_state(feather,MAAT_STATE_LAST_UPDATING_TABLE, &is_last_updating_table, sizeof(is_last_updating_table));
    printf("is_last_updating_table is %d\n", is_last_updating_table);
	assert(ret==0);
	return;
}

int Maat_test_plugin_table(Maat_feather_t feather,const char* table_name,
							Maat_start_callback_t *start,Maat_update_callback_t *update,Maat_finish_callback_t *finish,
							void *u_para,
							void* logger)
{
	int table_id=0,ret=0;
	table_id=Maat_table_register(feather,table_name);
	if(table_id==-1)
	{
		printf("Database table %s register failed.\n",table_name);
	}
	else
	{
		ret=Maat_table_callback_register(feather, table_id,
								start,
								update, 
								finish,
								u_para);
		if(ret<0)
		{
			printf("Maat callback register table %s error.\n",table_name);
		}
	}
	return ret;
}


int main(int argc, char* argv[])
{
    mgw_init();
    Maat_test_plugin_table(g_mgw_ctx.Maat_feather, "QD_ENTRY_INFO",	
								Maat_redis_start_cb,
								Maat_redis_update_cb, 
								Maat_redis_finish_cb,
								g_mgw_ctx.Maat_feather,
								g_mgw_ctx.logger);
    sleep(10);
    Maat_test_set_cmd_line(g_mgw_ctx.Maat_feather);
    sleep(3600);
}

#ifdef __cplusplus
}
#endif

