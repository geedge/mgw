#pragma once

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


struct mgw_tun_handle * mgw_tun_init(char *dev, void *logger)
{
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        MGW_LOG_ERROR(logger, "Failed at open /dev/net/tun: errno %d is %s", errno, strerror(errno));
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
        MGW_LOG_ERROR(logger, "Failed at ioctl: errno %d is %s", errno,strerror(errno));
        close(fd);
        exit(EXIT_FAILURE);
    }
    strcpy(dev, ifr.ifr_name);
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


int mgw_tun_read(struct mgw_tun_handle *handle, char *recv_ip_pkts, size_t ip_pkt_len)
 {
    int recv_ip_len = 0;
    recv_ip_len = read(handle->fd, recv_ip_pkts, ip_pkt_len);
    if(recv_ip_len < 0)
    {
        close(handle->fd);
        MGW_LOG_ERROR(handle->logger, "Failed at tun_read errno %d is %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
    }
    else
    {
        return recv_ip_len;
    }
 }


 /**************************************************************************
 * write_to_tun: write data to tun                                         *
 * return:write bytes                                                      *
 **************************************************************************/
int mgw_tun_write(int tun_fd, char *send_ip_pkts, int send_ip_len)
 {
    assert(send_ip_pkts !=NULL);
    assert(send_ip_len > 0);
    int cur_snd_ip_len = 0 ;
    cur_snd_ip_len = write(tun_fd, send_ip_pkts, send_ip_len);
    if(cur_snd_ip_len < 0)
    {
        printf(" send ip pkts errno = %d, content is %s\n",errno, strerror(errno));
		assert(0);
    }
    else
    {
        if(cur_snd_ip_len < send_ip_len)
        {
            close(tun_fd);
            printf("the ip data can not send completely!\n");
            assert(0);
        }
        else
        {
            return cur_snd_ip_len;
        }
    }
 }
