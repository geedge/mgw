#include "mgw_utils.h"
#include "mgw_socket.h"
#include "udp_server.h"
#include "nat.h"
#include "mgw_tun.h"

void * thread_udp_server(void *args)
{
    struct udp_server_args *_args = (struct udp_server_args *)args;
    void *logger = _args->logger;
    const char *profile = _args->profile;
    struct nat_handle *_nat_handle = _args->_nat_handle;
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
    struct timespec start_time, end_time;
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
        FS_operate(fs_handle->handle, fs_handle->field_recv_from_mrl, 0, FS_OP_ADD, 1);
        MGW_LOG_INFO(logger, "mgw_socket: Succeed to recv udp data, len is %d", len);
        int rtn = nat_dest_convert(_nat_handle, buff, len);
        if(rtn == NAT_COVERT_FAILURE)
        {
            //MGW_LOG_INFO(logger, "Failed to nat_dest_convert");
            continue;
        }
        //write to tun
        mgw_tun_write(tun_handle, buff, len);
        FS_operate(fs_handle->handle, fs_handle->field_write_to_tun, 0, FS_OP_ADD, 1);
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        long long cost_time = (end_time.tv_sec - start_time.tv_sec) * 1000000 + (end_time.tv_nsec - start_time.tv_nsec) / 1000;
        FS_operate(fs_handle->handle, fs_handle->dnat_latency, 0, FS_OP_SET, cost_time);
    }
}