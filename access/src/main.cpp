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
    const char *profile;
    Maat_feather_t Maat_feather;
    struct htable_opts *htable_opts_s;
	struct mgw_tun_handle *mgw_tun_handle_s;
	struct nat_handle *nat_handle_s;
    struct ip_mgr_handle *ip_mgr_handle_s;
    struct udp_client_handle *udp_client_handle_s;
};

static void wrapped_Maat_set_feather_opt(void *logger, Maat_feather_t feather, enum MAAT_INIT_OPT type, const void* value, int size)
{
    int rtn = Maat_set_feather_opt(feather, type, value, size);
    if(unlikely(rtn < 0))
    {
        MGW_LOG_ERROR(logger, "Failed at Maat_set_feather_opt, type is %d", type);
        exit(EXIT_FAILURE);
    }
}

static Maat_feather_t  Maat_init(const char *profile, void *logger)
{
    // load conf
    const char *section = "Maat";
    char table_info_path[MGW_PATH_MAX];
    int max_thread_num;
    char Maat_redis_ip[MGW_SYMBOL_MAX];
    int Maat_redis_port;
    char stat_file_path[MGW_PATH_MAX];
    MESA_load_profile_string_def(profile, section, "table_info_path", table_info_path, sizeof(table_info_path), "./conf/table_info.conf");
    MESA_load_profile_int_def(profile, section, "max_thread_num", &max_thread_num, 1);
    MESA_load_profile_string_def(profile, section, "Maat_redis_ip", Maat_redis_ip, sizeof(Maat_redis_ip), "127.0.0.1");
    MESA_load_profile_int_def(profile, section, "Maat_redis_port", &Maat_redis_port, 6379);
    MESA_load_profile_string_def(profile, section, "stat_file_path", stat_file_path, sizeof(stat_file_path), "./log/Maat_stat.log");
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n table_info_path: %s\n max_thread_num: %d\n Maat_redis_ip: %s\n Maat_redis_port: %d\n stat_file_path: %s", "Maat", table_info_path, max_thread_num, Maat_redis_ip, Maat_redis_port, stat_file_path);
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
    wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_STAT_FILE_PATH, stat_file_path, strlen(stat_file_path)+1);
    wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_STAT_ON, NULL, 0);
	wrapped_Maat_set_feather_opt(logger, feather, MAAT_OPT_PERF_ON, NULL, 0);
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

static struct htable_opts * htable_opt_init(const char* profile, void *logger)
{
    struct htable_opts* _htable_opts = ALLOC(struct htable_opts, 1);
    const char *section = "htable_opt";
    MESA_load_profile_int_def(profile, section, "mho_screen_print_ctrl", &(_htable_opts->mho_screen_print_ctrl), 0);
    MESA_load_profile_int_def(profile, section, "mho_thread_safe", &(_htable_opts->mho_thread_safe), 1);
    MESA_load_profile_int_def(profile, section, "mho_mutex_num", &(_htable_opts->mho_mutex_num), 16);
    MESA_load_profile_int_def(profile, section, "mho_hash_slot_size", &(_htable_opts->mho_hash_slot_size), 16000);
    MESA_load_profile_int_def(profile, section, "mho_expire_time", &(_htable_opts->mho_expire_time), 0);
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n mho_screen_print_ctrl: %d\n mho_thread_safe: %d\n mho_mutex_num: %d\n mho_hash_slot_size: %d\n mho_expire_time: %d", 
        "htable_opt", _htable_opts->mho_screen_print_ctrl, _htable_opts->mho_thread_safe, _htable_opts->mho_mutex_num, _htable_opts->mho_hash_slot_size, _htable_opts->mho_expire_time);
    return _htable_opts;
}

void ip2user_htable_free_data_cb(void *data)
{
    FREE(&data);
}

struct udp_client_handle * udp_client_init(const char *profile, void *logger)
{
    const char *section = "mrl";
    char ip[MGW_SYMBOL_MAX];
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

static struct mgw_handle * mgw_init()
{
    struct mgw_handle *_mgw_handle = ALLOC(struct mgw_handle, 1);
    char *profile = ALLOC(char, MGW_SYMBOL_MAX);
    strncpy(profile, "./conf/mgw.conf", MGW_SYMBOL_MAX);
	const char *section = "global";

    //init srand
    srand((unsigned)time(NULL)); 

    //init logger 
    char log_path[MGW_PATH_MAX];
    MESA_load_profile_string_def(profile, section, "log_path", log_path, sizeof(log_path), "./log/mgw.log");
    void *logger = MESA_create_runtime_log_handle(log_path, RLOG_LV_DEBUG);
    if (unlikely(logger == NULL))
	{
		MGW_LOG_ERROR(logger, "Failed at creating logger: %s", log_path);
		exit(EXIT_FAILURE);
	}
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n log_path: %s", "global", log_path);
    _mgw_handle->logger = logger;
    _mgw_handle->profile = (const char *)profile;

    //init htable_opt
    struct htable_opts * _htable_opts = htable_opt_init(profile, logger);
    _mgw_handle->htable_opts_s = _htable_opts;

    //init Maat
    Maat_feather_t Maat_feather = Maat_init((const char *)profile, logger);
    _mgw_handle->Maat_feather = Maat_feather;

    //init tun
    _mgw_handle->mgw_tun_handle_s = mgw_tun_init("tun_mgw", logger);

    //init nat
    MESA_htable_handle ip2user_htable = mgw_utils_create_htable("ip2user_htable", _mgw_handle->htable_opts_s, (void *)ip2user_htable_free_data_cb, NULL);
    if(ip2user_htable == NULL)
    {
        MGW_LOG_ERROR(logger, "Failed at create ip2user_htable");
        exit(EXIT_FAILURE);
    }
    _mgw_handle->nat_handle_s = nat_init(ip2user_htable, logger, _htable_opts);

    //init ip_mgr
    struct ip_mgr_handle * _ip_mgr_handle = ip_mgr_init(logger, Maat_feather, _htable_opts);
    if(unlikely(_ip_mgr_handle == NULL))
    {
        MGW_LOG_ERROR(logger, "Failed at init_ip_mgr");
        exit(EXIT_FAILURE);
    }
    _mgw_handle->ip_mgr_handle_s = _ip_mgr_handle;

    //create thread_vpn_monitor
    pthread_t thread_id;
    struct vpn_monitor_args *args = ALLOC(struct vpn_monitor_args, 1);
    args->ip2user_htable = ip2user_htable;
    args->logger = logger;
    args->profile = (const char *)profile;
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

static void mgw_destroy(struct mgw_handle *_mgw_handle)
{
    MESA_destroy_runtime_log_handle(_mgw_handle->logger);
    Maat_burn_feather(_mgw_handle->Maat_feather);
}

static void send_data_to_mrl(struct udp_client_handle *handle, char *buff, int len, struct ip_mgr_vxlan_info *vxlan_info)
{
    void *logger = handle->logger;
    int socket_fd = handle->socket_fd;
    memcpy(buff + len, vxlan_info, sizeof(struct ip_mgr_vxlan_info));
    len += sizeof(struct ip_mgr_vxlan_info);
    uint32_t dip = inet_addr(vxlan_info->vxlan_outer_local_ip);
    uint16_t dport = htons(handle->dport);
    int rtn = mgw_socket_udp_send(socket_fd, buff, len, dip, dport);
    if (rtn < 0)
    {
       MGW_LOG_ERROR(logger, "mgw_socket: Failed at send udp data, errno is %d, %s", errno, strerror(errno));
       return;
    }
    MGW_LOG_INFO(logger, "mgw_socket: Succeed to send udp data, len is %d", len);
}

static void mgw_run(struct mgw_handle *handle)
{
    void *logger = handle->logger;
    while(1)
    {
        char buff[MGW_PACKET_MAX];
        int len = mgw_tun_read(handle->mgw_tun_handle_s, buff, MGW_PACKET_MAX);
        printf("tun: len is %d\n", len);
        struct ip_mgr_vxlan_info *vxlan_info = NULL;
        int rtn = nat_src_convert(handle->nat_handle_s, handle->ip_mgr_handle_s, buff, len, &vxlan_info);
        if(rtn == NAT_COVERT_FAILURE)
        {
            MGW_LOG_ERROR(logger, "Failed at nat_src_convert");
            continue;
        }
        send_data_to_mrl(handle->udp_client_handle_s, buff, len, vxlan_info);
    }
}

int main(int argc, char* argv[])
{
    struct mgw_handle *handle = mgw_init();
    mgw_run(handle);
}

