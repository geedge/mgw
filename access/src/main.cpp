#include "mgw_utils.h"
#include "vpn_monitor.h"
#include "mgw_tun.h"
#include "nat.h"
#include "ip_mgr.h"
#include "mgw_socket.h"
#include "udp_server.h"

struct udp_client_handle
{
    int socket_fd;
    char dip[MGW_SYMBOL_MAX];  //not used
    uint16_t dport; 
    void *logger;
};

struct mgw_handle
{
    void* logger;
    char *profile;
    Maat_feather_t Maat_feather_cand;
    Maat_feather_t Maat_feather_policy;
	struct mgw_tun_handle *mgw_tun_handle_s;
	struct nat_handle *nat_handle_s;
    struct ip_mgr_handle *ip_mgr_handle_s;
    struct udp_client_handle *udp_client_handle_s;
    MESA_htable_handle cand_ip_detail_htable;
    MESA_htable_handle ip2user_htable;
    struct field_stat_handle *fs_handle;
};

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

static void ip2user_htable_data_free_cb(void *data)
{
    FREE(&data);
}

static void cand_ip_detail_htable_data_free_cb(void *data)
{
    struct ip_mgr_cand_ip_detail *cand_ip_detail = (struct ip_mgr_cand_ip_detail *)data;
    FREE(&cand_ip_detail->vxlan_info);
    FREE(&data);
}

static struct udp_client_handle * udp_client_init(const char *profile, void *logger)
{
    const char *section = "mrl";
    char ip[MGW_SYMBOL_MAX] = "";
    uint16_t port;
    MESA_load_profile_string_def(profile, section, "ip", ip, MGW_SYMBOL_MAX, "192.168.10.242");
    MESA_load_profile_int_def(profile, section, "port", (int *)&port, 23456);
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n ip: %s\n port: %d", "mrl", ip, port);
    int socket_fd = mgw_socket_init();
    if(socket_fd < 0)
    {
        MGW_LOG_ERROR(logger, "mgw_socket: Failed at create socket, errno is %d, %s", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
    struct udp_client_handle *handle = ALLOC(struct udp_client_handle, 1);
    handle->logger = logger;
    handle->dport = port;
    handle->socket_fd = socket_fd;
    strncpy(handle->dip, ip, MGW_SYMBOL_MAX);
    return handle;
}

static struct field_stat_handle * fs_init(const char *profile, void *logger)
{
    const char *section = "field_stat";
    char stat_path[MGW_SYMBOL_MAX] = "";
    char FP_HISTOGRAM_BINS[MGW_SYMBOL_MAX] = "";
    MESA_load_profile_string_def(profile, section, "stat_path", stat_path, MGW_SYMBOL_MAX, "./fs2_mgw.status");
    MESA_load_profile_string_def(profile, section, "histogram_bins", FP_HISTOGRAM_BINS, MGW_SYMBOL_MAX, "0.5,0.8,0.9,0.95");
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n stat_path: %s\n histogram_bins: %s", "field_stat", stat_path, FP_HISTOGRAM_BINS);
    screen_stat_handle_t handle = NULL;
	const char* app_name = "fs2_mgw";
	char buff[128];
	int value=0;
	handle = FS_create_handle();
    FS_set_para(handle, HISTOGRAM_GLOBAL_BINS, FP_HISTOGRAM_BINS, strlen(FP_HISTOGRAM_BINS)+1);

	FS_set_para(handle, APP_NAME, app_name, strlen(app_name)+1);
	value=0;
	FS_set_para(handle, FLUSH_BY_DATE, &value, sizeof(value));
	FS_set_para(handle, OUTPUT_DEVICE, stat_path, strlen(stat_path)+1);
	value=1;
	FS_set_para(handle, PRINT_MODE, &value, sizeof(value));
	value=1;
	FS_set_para(handle, CREATE_THREAD, &value, sizeof(value));
	value=5;
	FS_set_para(handle, STAT_CYCLE, &value, sizeof(value));
	value=4096;
	FS_set_para(handle, MAX_STAT_FIELD_NUM, &value, sizeof(value));

    //field: packet handle status
    snprintf(buff, sizeof(buff),"read_from_tun");
    int field_read_from_tun = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);

    snprintf(buff, sizeof(buff),"write_to_tun");
    int field_write_to_tun = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);
    
    snprintf(buff, sizeof(buff),"recv_from_mrl");
    int field_recv_from_mrl = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);

    snprintf(buff, sizeof(buff),"send_to_mrl");
    int field_send_to_mrl = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"snat_succ_rate");
	FS_register_ratio(handle,
				field_send_to_mrl,
				field_read_from_tun,
				1,
				FS_STYLE_FIELD,
				FS_CALC_CURRENT,
				buff);
    
    snprintf(buff,sizeof(buff),"dnat_succ_rate");
	FS_register_ratio(handle,
                field_write_to_tun, 
				field_recv_from_mrl,
				1,
				FS_STYLE_FIELD,
				FS_CALC_CURRENT,
				buff);

    //column: cache hit/miss, line htable
    snprintf(buff,sizeof(buff),"snat");
	int line_snat = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"dnat");
	int line_dnat = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"ip2user");
	int line_ip2user = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"user_policy");
	int line_user_policy = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"ip_group");
	int line_ip_group = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"ip_detail");
	int line_ip_detail = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"query_num");
    int cloumn_queyr_num = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"element_num");
    int cloumn_element_num = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"cache_miss");
    int cloumn_cache_miss = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"cache_hit");
    int cloumn_cache_hit = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"cache_hit_rate");
	FS_register_ratio(handle,
				cloumn_cache_hit,
				cloumn_queyr_num,
				1,
				FS_STYLE_COLUMN,
				FS_CALC_CURRENT,
				buff);

    //snat/dnat latency
    snprintf(buff,sizeof(buff), "snat(us)");
    int snat_latency = FS_register_histogram(handle, FS_CALC_CURRENT, buff, 1, 30*1000, 3);

    snprintf(buff,sizeof(buff), "dnat(us)");
    int dnat_latency = FS_register_histogram(handle, FS_CALC_CURRENT, buff, 1, 30*1000, 3);

	FS_start(handle);
    struct field_stat_handle *fs_handle= ALLOC(struct field_stat_handle, 1);
    fs_handle->handle = handle;
    //field
    fs_handle->field_read_from_tun = field_read_from_tun;
    fs_handle->field_write_to_tun = field_write_to_tun;
    fs_handle->field_recv_from_mrl = field_recv_from_mrl;
    fs_handle->field_send_to_mrl = field_send_to_mrl;
    //cloumn and line
    fs_handle->cloumn_cache_hit = cloumn_cache_hit;
    fs_handle->cloumn_cache_miss = cloumn_cache_miss;
    fs_handle->cloumn_element_num = cloumn_element_num;
    fs_handle->cloumn_queyr_num = cloumn_queyr_num;
    fs_handle->line_snat = line_snat;
    fs_handle->line_dnat = line_dnat;
    fs_handle->line_ip2user = line_ip2user;
    fs_handle->line_user_policy = line_user_policy;
    fs_handle->line_ip_group = line_ip_group;
    fs_handle->line_ip_detail = line_ip_detail;
    //snat/dnat latency
    fs_handle->snat_latency = snat_latency;
    fs_handle->dnat_latency = dnat_latency;
    return fs_handle;
}


static struct mgw_handle * mgw_init(char *conf_path)
{
    struct mgw_handle *_mgw_handle = ALLOC(struct mgw_handle, 1);
    char *profile = ALLOC(char, MGW_SYMBOL_MAX);
    strncpy(profile, conf_path, MGW_SYMBOL_MAX);
    printf("profile is %s\n", profile);
	const char *section = "global";

    //init srand
    srand((unsigned)time(NULL)); 

    //init logger 
    char log_path[MGW_PATH_MAX];
    int log_level;
    MESA_load_profile_string_def(profile, section, "log_path", log_path, sizeof(log_path), "./log/mgw.log");
    MESA_load_profile_int_def(profile, section, "log_level", &log_level, 30);
    void *logger = MESA_create_runtime_log_handle(log_path, log_level);
    if (unlikely(logger == NULL))
	{
		MGW_LOG_ERROR(logger, "Failed at creating logger: %s", log_path);
		exit(EXIT_FAILURE);
	}
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n log_path: %s", "global", log_path);
    _mgw_handle->logger = logger;
    _mgw_handle->profile = (char *)profile;

    //init feild_stat
    struct field_stat_handle *fs_handle = fs_init(profile, logger);
    _mgw_handle->fs_handle = fs_handle;

    //init Maat
    Maat_feather_t Maat_feather_cand = Maat_init((const char *)profile, "Maat_cand", logger);
    Maat_feather_t Maat_feather_policy = Maat_init((const char *)profile, "Maat_policy", logger);
    _mgw_handle->Maat_feather_cand = Maat_feather_cand;
    _mgw_handle->Maat_feather_policy = Maat_feather_policy;

    //init tun
    _mgw_handle->mgw_tun_handle_s = mgw_tun_init("tun_mgw", logger);

    //init ip_mgr
    MESA_htable_handle cand_ip_detail_htable = mgw_utils_create_htable(profile, "cand_ip_detail_htable", (void *)cand_ip_detail_htable_data_free_cb, NULL, logger);
    if(cand_ip_detail_htable == NULL)
    {
        MGW_LOG_ERROR(logger, "Failed at create cand_ip_detail_htable");
        exit(EXIT_FAILURE);
    }
    _mgw_handle->cand_ip_detail_htable = cand_ip_detail_htable;
    struct ip_mgr_handle * _ip_mgr_handle = ip_mgr_init(profile, cand_ip_detail_htable, fs_handle, Maat_feather_cand, Maat_feather_policy, logger);
    if(unlikely(_ip_mgr_handle == NULL))
    {
        MGW_LOG_ERROR(logger, "Failed at init_ip_mgr");
        exit(EXIT_FAILURE);
    }
    _mgw_handle->ip_mgr_handle_s = _ip_mgr_handle;


    //init nat
    MESA_htable_handle ip2user_htable = mgw_utils_create_htable(profile, "ip2user_htable", (void *)ip2user_htable_data_free_cb, NULL, logger);
    if(ip2user_htable == NULL)
    {
        MGW_LOG_ERROR(logger, "Failed at create ip2user_htable");
        exit(EXIT_FAILURE);
    }
    _mgw_handle->ip2user_htable = ip2user_htable;
    _mgw_handle->nat_handle_s = nat_init(profile, ip2user_htable, cand_ip_detail_htable, fs_handle, logger);


    //create thread_vpn_monitor
    pthread_t thread_id;
    struct vpn_monitor_args *args = ALLOC(struct vpn_monitor_args, 1);
    args->ip2user_htable = ip2user_htable;
    args->logger = logger;
    args->profile = (const char *)profile;
    args->fs_handle = fs_handle;
    int rtn = pthread_create(&thread_id, NULL, thread_vpn_monitor, (void *)args);
    if(unlikely(rtn != 0))
    {
        MGW_LOG_ERROR(logger, "Failed at creating thread_vpn_monitor");
        exit(EXIT_FAILURE);
    }

    //create thread_udp_server
    struct udp_server_args *_udp_server_args = ALLOC(struct udp_server_args, 1);
    _udp_server_args->logger = logger;
    _udp_server_args->profile = profile;
    _udp_server_args->_nat_handle = _mgw_handle->nat_handle_s;
    _udp_server_args->tun_handle = _mgw_handle->mgw_tun_handle_s;
    _udp_server_args->fs_handle = fs_handle;
    rtn = pthread_create(&thread_id, NULL, thread_udp_server, (void *)_udp_server_args);
    if(unlikely(rtn != 0))
    {
        MGW_LOG_ERROR(logger, "Failed at creating thread_udp_server");
        exit(EXIT_FAILURE);
    }

    //init udp client socket
    struct udp_client_handle *_udp_client_handle = udp_client_init(profile, logger);
    _mgw_handle->udp_client_handle_s = _udp_client_handle;
    return _mgw_handle;
}


static void mgw_destroy(struct mgw_handle *handle)
{
    MESA_destroy_runtime_log_handle(handle->logger);
    FREE(&handle->profile);
    Maat_burn_feather(handle->Maat_feather_cand);
    Maat_burn_feather(handle->Maat_feather_policy);
    MESA_htable_destroy(handle->cand_ip_detail_htable, NULL);
    MESA_htable_destroy(handle->ip2user_htable, NULL);
    mgw_tun_destroy(handle->mgw_tun_handle_s);
    nat_destroy(handle->nat_handle_s);
    ip_mgr_destroy(handle->ip_mgr_handle_s);
    FREE(&handle->udp_client_handle_s);
    FS_stop(&handle->fs_handle->handle);
    FREE(&handle->fs_handle);
    FREE(&handle);
}

static int send_data_to_mrl(struct udp_client_handle *handle, char *buff, int len,  MESA_htable_handle cand_ip_detail_htable, 
        struct ip_mgr_vxlan_info *vxlan_info, uint32_t mrl_ip)
{
    void *logger = handle->logger;
    int socket_fd = handle->socket_fd;
    char _buff[MGW_PACKET_MAX];
    memcpy(_buff, vxlan_info, sizeof(struct ip_mgr_vxlan_info));
    memcpy(_buff + sizeof(struct ip_mgr_vxlan_info), buff, len);
    len += sizeof(struct ip_mgr_vxlan_info);
    uint16_t dport = htons(handle->dport);
    int rtn = mgw_socket_udp_send(socket_fd, _buff, len, mrl_ip, dport);
    if (rtn < 0)
    {
       MGW_LOG_ERROR(logger, "mgw_socket: Failed at send udp data, errno is %d, %s", errno, strerror(errno));
    }
    return rtn;
}

static void mgw_run(struct mgw_handle *handle)
{
    void *logger = handle->logger;
    sleep(10);
    struct timespec start_time, end_time;
    struct field_stat_handle *fs_handle = handle->fs_handle;
    //for test
    //struct timespec _start_time;
    //clock_gettime(CLOCK_MONOTONIC, &_start_time);


    while(1)
    {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        char buff[MGW_PACKET_MAX];
        int len = mgw_tun_read(handle->mgw_tun_handle_s, buff, MGW_PACKET_MAX);
        FS_operate(fs_handle->handle, fs_handle->field_read_from_tun, 0, FS_OP_ADD, 1);
        struct ip_mgr_vxlan_info *vxlan_info = NULL;
        uint32_t mrl_ip;
        int rtn = nat_src_convert(handle->nat_handle_s, handle->ip_mgr_handle_s, buff, len, &vxlan_info, &mrl_ip);
        if(rtn == NAT_COVERT_FAILURE)
        {
            MGW_LOG_ERROR(logger, "Failed at nat_src_convert");
            continue;
        }
        int send_len = send_data_to_mrl(handle->udp_client_handle_s, buff, len, handle->cand_ip_detail_htable, vxlan_info, mrl_ip);
        if(send_len > 0)
        {
            FS_operate(fs_handle->handle, fs_handle->field_send_to_mrl, 0, FS_OP_ADD, 1);
        }
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        long long cost_time;
        cost_time = (end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_nsec - start_time.tv_nsec) / 1000;
        FS_operate(fs_handle->handle, fs_handle->snat_latency, 0, FS_OP_SET, cost_time);

        //for test
        //if(end_time.tv_sec - _start_time.tv_sec > 60)
            //break;
    }
}

int main(int argc, char* argv[])
{
    char *conf_path = (char *)"./conf/mgw.conf";
    if(argc > 1)
    {
        conf_path = argv[1];
    }
    struct mgw_handle *handle = mgw_init(conf_path);
    mgw_run(handle);
    mgw_destroy(handle);
}

