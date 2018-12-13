#include "mgw_utils.h"
#include "mgw_socket.h"
#include "udp_server.h"
#include "snat.h"
#include "dnat.h"
#include "mgw_tun.h"

void * thread_udp_server(void *args)
{
    struct udp_server_args *_args = (struct udp_server_args *)args;
    void *logger = _args->logger;
    const char *profile = _args->profile;
    struct snat_handle *_snat_handle = _args->_snat_handle;
    struct dnat_handle *_dnat_handle = _args->_dnat_handle;
    struct mgw_tun_handle *tun_handle = _args->tun_handle;
    struct field_stat_handle *fs_handle = _args->fs_handle;
    FREE(&args);
    const char *section = "udp_server";
    char ip[MGW_SYMBOL_MAX];
    u_int16_t port;
    MESA_load_profile_string_def(profile, section, "ip", ip, MGW_SYMBOL_MAX, "192.168.11.137");
    MESA_load_profile_int_def(profile, section, "port", (int *)&port, 33456);
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n ip: %s\n port: %d", "udp_server", ip, port);
    int socket_fd = mgw_socket_init();
    if(socket_fd < 0)
    {
       MGW_LOG_ERROR(logger, "mgw_socket: Failed at create socket, errno is %d, %s", errno, strerror(errno));
       exit(EXIT_FAILURE);
    }
    int rtn = mgw_socket_bind(socket_fd, ip, port);
    if(rtn < 0)
    {
        MGW_LOG_ERROR(logger, "mgw_socket: Failed at bind, ip is %s, port is %d, errno is %d, %s", ip, port, errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
    char buff[MGW_PACKET_MAX];
    struct timespec start_time;
    while(1)
    {
        //EAGAIN if socket is no-blocking, eg. fcntl()
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        int len = mgw_socket_udp_recv(socket_fd, buff, MGW_PACKET_MAX);
        if (len < 0)
        {
            MGW_LOG_ERROR(logger, "mgw_socket: Failed at recv udp data, errno is %d, %s", errno, strerror(errno));
            continue;
        }
        FS_operate(fs_handle->handle, fs_handle->field_rx_from_mrl, 0, FS_OP_ADD, 1);
        MGW_LOG_INFO(logger, "mgw_socket: Succeed to recv udp data, len is %d", len);
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        int rtn = snat_rx_convert(_snat_handle, buff, len);
        mgw_utils_fs_latency_cala(fs_handle->handle, start_time, fs_handle->snat_rx_latency);
        if(rtn == MGW_DROP)
        {
            continue;
        }
        if(rtn == MGW_FORWORD)
        {
            int rtn = mgw_tun_write(tun_handle, buff, len);
            if(rtn >0 && rtn == len)
            {
                FS_operate(fs_handle->handle, fs_handle->field_tun_write, 0, FS_OP_ADD, 1);
            }
            continue;
        }
        //MGW_BYPASS, dnat_rx_convert
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        rtn = dnat_rx_convert(_dnat_handle, buff, len);
        mgw_utils_fs_latency_cala(fs_handle->handle, start_time, fs_handle->dnat_rx_latency);
        if(rtn == MGW_DROP)
        {
            continue;
        }
        if(rtn == MGW_FORWORD)
        {
            int rtn = mgw_tun_write(tun_handle, buff, len);
            if(rtn >0 && rtn == len)
            {
                FS_operate(fs_handle->handle, fs_handle->field_tun_write, 0, FS_OP_ADD, 1);
            }
            continue;
        }
    }
}