#ifndef TUN_H_INCLUDED
#define TUN_H_INCLUDED
#endif

#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <stddef.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "mgw_utils.h"
#include "mgw_tun.h"

struct mgw_tun_handle
{
    void* logger;
    int fd;
};


struct mgw_tun_handle * mgw_tun_init(const char *dev, void *logger)
{
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        MGW_LOG_ERROR(logger, "mgw_tun: Failed at open /dev/net/tun: errno is %d, %s", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;//不包含tun包信息
    if (*dev)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
        MGW_LOG_ERROR(logger, "mgw_tun: Failed at ioctl: errno is %d, %s", errno,strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }
    struct mgw_tun_handle *handle = ALLOC(struct mgw_tun_handle, 1);
    handle->fd = fd;
    handle->logger = logger;
    return handle;
}

void mgw_tun_destroy(struct mgw_tun_handle *handle)
{
    close(handle->fd);
    FREE(&handle);
}


int mgw_tun_read(struct mgw_tun_handle *handle, char *buff, size_t len)
 {
    void *logger = handle->logger;
    int recv_len = 0;
    recv_len = read(handle->fd, buff, len);
    if(recv_len < 0)
    {
        close(handle->fd);
        MGW_LOG_ERROR(logger, "mgw_tun: Failed at read from tun, errno is %d, %s\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return recv_len;
 }

int mgw_tun_write(struct mgw_tun_handle *handle, char *buff, size_t len)
 {
    void *logger = handle->logger;
    int send_len = 0 ;
    send_len = write(handle->fd, buff, len);
    if(send_len < 0)
    {
        MGW_LOG_ERROR(logger, "mgw_tun: Failed at write to tun, errno is %d, %s", errno, strerror(errno));
    }
    else
    {
        if((size_t)send_len < len)
        {
            close(handle->fd);
            MGW_LOG_ERROR(logger, "mgw_tun: Failed at write to tun completely, need send %d but only send %d", (int)len, send_len);
            exit(EXIT_FAILURE);
        }
    }
    MGW_LOG_INFO(logger, "mgw_tun: Succeed at write to tun, len is %d", send_len);
    return send_len;
 }
