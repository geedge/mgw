#include "mgw_utils.h"
#include "vpn_monitor.h"
#include "mgw_tun.h"
#include "snat.h"
#include "dnat.h"
#include "ip_mgr.h"
#include "mgw_socket.h"
#include "udp_server.h"


//rx :  receive from mrl
//tx:   transmit to mrl
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
	struct mgw_tun_handle *tun_handle;
	struct snat_handle *_snat_handle;
    struct dnat_handle *_dnat_handle;
    struct ip_mgr_handle *_ip_mgr_handle;
    struct udp_client_handle *_udp_client_handle;
    MESA_htable_handle ip2user_htable;
};

struct field_stat_handle *g_fs_handle = NULL;

void ip2user_htable_data_free_cb(void *data)
{
    FS_operate(g_fs_handle->handle, g_fs_handle->line_ip2user, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    FREE(&data);
}

static void user2ips_htable_data_free_cb(void *data)
{
    FREE(&data);
}

static struct udp_client_handle * udp_client_init(const char *profile, void *logger)
{
    const char *section = "mrl";
    char ip[MGW_SYMBOL_MAX] = "";
    uint16_t port;
    MESA_load_profile_int_def(profile, section, "port", (int *)&port, 23456);
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n port: %d", "mrl", port);
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
    struct field_stat_handle *fs_handle= ALLOC(struct field_stat_handle, 1);
    fs_handle->handle = handle;

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
    snprintf(buff, sizeof(buff),"tun_read");
    fs_handle->field_tun_read = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);

    snprintf(buff, sizeof(buff),"tun_bypass");
    fs_handle->field_tun_bypass = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);

    snprintf(buff, sizeof(buff),"tun_write");
    fs_handle->field_tun_write = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);
    
    snprintf(buff, sizeof(buff),"rx_from_mrl");
    fs_handle->field_rx_from_mrl = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);

    snprintf(buff, sizeof(buff),"tx_to_mrl");
    fs_handle->field_tx_to_mrl = FS_register(handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"rx_succ_rate");
	FS_register_ratio(handle,
				fs_handle->field_tun_write,
                fs_handle->field_rx_from_mrl,
				1,
				FS_STYLE_FIELD,
				FS_CALC_CURRENT,
				buff);

    snprintf(buff,sizeof(buff),"tx_succ_rate");
	FS_register_ratio(handle,
				fs_handle->field_tx_to_mrl,
				fs_handle->field_tun_read,
				1,
				FS_STYLE_FIELD,
				FS_CALC_CURRENT,
				buff);
    

    //column: cache hit/miss, line htable
    snprintf(buff,sizeof(buff),"snat");
	fs_handle->line_snat = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"dnat");
	fs_handle->line_dnat = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"ip2user");
	fs_handle->line_ip2user = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"user2ips");
	fs_handle->line_user2ips = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"snat_policy");
	fs_handle->line_snat_policy = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"dnat_policy"); 
	fs_handle->line_dnat_policy = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"snat_cand_ip");
	fs_handle->line_snat_cand_ip = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"mrl_ip");
	fs_handle->line_mrl_ip = FS_register(handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff); 

    snprintf(buff,sizeof(buff),"query_num");
    fs_handle->cloumn_query_num = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"element_num");
    fs_handle->cloumn_element_num = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"cache_miss");
    fs_handle->cloumn_cache_miss = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"cache_hit");
    fs_handle->cloumn_cache_hit = FS_register(handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"cache_hit_rate");
	FS_register_ratio(handle,
				fs_handle->cloumn_cache_hit,
				fs_handle->cloumn_query_num,
				1,
				FS_STYLE_COLUMN,
				FS_CALC_CURRENT,
				buff);

    //snat/dnat latency
    snprintf(buff,sizeof(buff), "snat_rx(us)");
    fs_handle->snat_rx_latency = FS_register_histogram(handle, FS_CALC_CURRENT, buff, 1, 30*1000, 3);

    snprintf(buff,sizeof(buff), "snat_tx(us)");
    fs_handle->snat_tx_latency = FS_register_histogram(handle, FS_CALC_CURRENT, buff, 1, 30*1000, 3);

    snprintf(buff,sizeof(buff), "dnat_rx(us)");
    fs_handle->dnat_rx_latency = FS_register_histogram(handle, FS_CALC_CURRENT, buff, 1, 30*1000, 3);

    snprintf(buff,sizeof(buff), "dnat_tx(us)");
    fs_handle->dnat_tx_latency = FS_register_histogram(handle, FS_CALC_CURRENT, buff, 1, 30*1000, 3);

	FS_start(handle);
    return fs_handle;
}


static struct mgw_handle * mgw_init(char *conf_path)
{
    struct mgw_handle *_mgw_handle = ALLOC(struct mgw_handle, 1);
    char *profile = ALLOC(char, MGW_SYMBOL_MAX);
    strncpy(profile, conf_path, MGW_SYMBOL_MAX);
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
    g_fs_handle = fs_handle;

    //init tun
    _mgw_handle->tun_handle = mgw_tun_init("tun_mgw", logger);

    //init ip_mgr
    MESA_htable_handle user2ips_htable = mgw_utils_create_htable(profile, "user2ips_htable", (void *)user2ips_htable_data_free_cb, NULL, logger);
    struct ip_mgr_handle * _ip_mgr_handle = ip_mgr_init(profile, &user2ips_htable, logger);
    if(unlikely(_ip_mgr_handle == NULL))
    {
        MGW_LOG_ERROR(logger, "Failed at init_ip_mgr");
        exit(EXIT_FAILURE);
    }
    _mgw_handle->_ip_mgr_handle = _ip_mgr_handle;

    //init snat
    MESA_htable_handle ip2user_htable = mgw_utils_create_htable(profile, "ip2user_htable", (void *)ip2user_htable_data_free_cb, NULL, logger);
    if(ip2user_htable == NULL)
    {
        MGW_LOG_ERROR(logger, "Failed at create ip2user_htable");
        exit(EXIT_FAILURE);
    }
    _mgw_handle->ip2user_htable = ip2user_htable;
    _mgw_handle->_snat_handle = snat_init(profile, ip2user_htable, _ip_mgr_handle, logger);

    //init_dnat
    _mgw_handle->_dnat_handle = dnat_init(profile, _ip_mgr_handle, logger);

    //create thread_vpn_monitor
    pthread_t thread_id;
    struct vpn_monitor_args *args = ALLOC(struct vpn_monitor_args, 1);
    args->ip2user_htable = ip2user_htable;
    args->user2ips_htable_ptr = &user2ips_htable;
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
    _udp_server_args->_snat_handle = _mgw_handle->_snat_handle;
    _udp_server_args->_dnat_handle = _mgw_handle->_dnat_handle;
    _udp_server_args->tun_handle = _mgw_handle->tun_handle;
    rtn = pthread_create(&thread_id, NULL, thread_udp_server, (void *)_udp_server_args);
    if(unlikely(rtn != 0))
    {
        MGW_LOG_ERROR(logger, "Failed at creating thread_udp_server");
        exit(EXIT_FAILURE);
    }

    //init udp client socket
    struct udp_client_handle *_udp_client_handle = udp_client_init(profile, logger);
    _mgw_handle->_udp_client_handle = _udp_client_handle;
    return _mgw_handle;
}


static void mgw_destroy(struct mgw_handle *handle)
{
    MESA_destroy_runtime_log_handle(handle->logger);
    FREE(&handle->profile);
    MESA_htable_destroy(handle->ip2user_htable, NULL);
    mgw_tun_destroy(handle->tun_handle);
    snat_destroy(handle->_snat_handle);
    dnat_destroy(handle->_dnat_handle);
    ip_mgr_destroy(handle->_ip_mgr_handle);
    FREE(&handle->_udp_client_handle);
    FS_stop(&(g_fs_handle->handle));
    FREE(&g_fs_handle);
    FREE(&handle);
}

static int send_data_to_mrl(struct udp_client_handle *handle, char *buff, int len, uint32_t mrl_ip)
{
    void *logger = handle->logger;
    int socket_fd = handle->socket_fd;
    uint16_t dport = htons(handle->dport);
    int rtn = mgw_socket_udp_send(socket_fd, buff, len, mrl_ip, dport);
    if (rtn < 0 || rtn != len)
    {
       MGW_LOG_ERROR(logger, "mgw_socket: Failed at send udp data, errno is %d, %s", errno, strerror(errno));
       return rtn;
    }
    MGW_LOG_INFO(logger, "mgw_socket: Succeed at send udp data, send len is %d", rtn);
    return rtn;
}

static void mgw_run(struct mgw_handle *handle)
{
    struct timespec start_time;
    while(1)
    {
        char buff[MGW_PACKET_MAX];
        int len = mgw_tun_read(handle->tun_handle, buff, MGW_PACKET_MAX);
        if(len < 0)
        {
            continue;
        }
        FS_operate(g_fs_handle->handle, g_fs_handle->field_tun_read, 0, FS_OP_ADD, 1);
        uint32_t mrl_ip;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        int rtn = dnat_tx_convert(handle->_dnat_handle, buff, len, &mrl_ip);
        mgw_utils_fs_latency_cala(g_fs_handle->handle, start_time, g_fs_handle->dnat_tx_latency);
        if(rtn == MGW_DROP)
        {
            continue;
        }
        if(rtn == MGW_FORWORD)
        {
            int rtn = send_data_to_mrl(handle->_udp_client_handle, buff, len, mrl_ip);
            if(rtn > 0 && rtn == len)
            {
                FS_operate(g_fs_handle->handle, g_fs_handle->field_tx_to_mrl, 0, FS_OP_ADD, 1);
            }
            continue;
        }
        // rtn=MGW_BYPASS, do sant_src_convert
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        rtn = snat_tx_convert(handle->_snat_handle, buff, len, &mrl_ip);
        mgw_utils_fs_latency_cala(g_fs_handle->handle, start_time, g_fs_handle->snat_tx_latency);
        if(rtn == MGW_DROP)
        {
            continue;
        }
        if(rtn == MGW_FORWORD)
        {
            int rtn = send_data_to_mrl(handle->_udp_client_handle, buff, len, mrl_ip);
            if(rtn > 0 && rtn == len)
            {
                FS_operate(g_fs_handle->handle, g_fs_handle->field_tx_to_mrl, 0, FS_OP_ADD, 1);
            }
            continue;
        }
        // rtn=MGW_BYPASS, write to tun
        rtn = mgw_tun_write(handle->tun_handle, buff, len);
        if(rtn < 0 || rtn != len)
        {
            continue;
        }
        FS_operate(g_fs_handle->handle, g_fs_handle->field_tun_bypass, 0, FS_OP_ADD, 1);
        //FS_operate(g_fs_handle->handle, g_fs_handle->field_tun_read, 0, FS_OP_ADD, -1);
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

