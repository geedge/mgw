
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

/**************************************************************************
 * tun_alloc:  create a tun fd,and set tun param .                        *
 * return : a tun fd                                                      *
 **************************************************************************/
int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        printf("open function errno %d is %s\n",errno,strerror(errno));
        assert(0);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;//不包含tun包信息
    if (*dev)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
        printf("ioctl function err is %d,errno %d is %s\n",err,errno,strerror(errno));
        close(fd);
        assert(0);
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

/**************************************************************************
 * read_from_tun:  read data from tun , and puts them into buffer.        *
 * return : read bytes                                                    *
 **************************************************************************/
int read_from_tun(int tun_fd, char *recv_ip_pkts,size_t ip_pkt_len)
 {
    int recv_ip_len = 0;
    recv_ip_len = read(tun_fd, recv_ip_pkts, ip_pkt_len);
    if(recv_ip_len < 0)
    {
        close(tun_fd);
        printf("read function errno %d is %s\n",errno, strerror(errno));
		assert(0);
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
int write_to_tun(int tun_fd, char *send_ip_pkts, int send_ip_len)
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

int main(int argc, char* argv[])
{
    char dev[MGW_SYMBOL_MAX] = "tun_mgw";
    int fd = tun_alloc(dev);
    char buff[1500];
    int ret;
    while((ret = read_from_tun(fd, buff, sizeof(buff))) > 0)
    {
        printf("ret is %d\n", ret);
        printf("buff is %s\n", buff);
    }
}