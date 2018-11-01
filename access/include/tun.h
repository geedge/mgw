#ifndef TUN_H_INCLUDED
#define TUN_H_INCLUDED

#include <arpa/inet.h>
#include <errno.h>
#include<assert.h>
#include <sys/ioctl.h>
#include<linux/if_ether.h>
#include<stddef.h>
#include<net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <unistd.h>


int tun_alloc(char *dev);
int write_to_tun(int tun_fd, char *send_ip_pkts, int send_ip_len);
int read_from_tun(int tun_fd, char *recv_ip_pkts,size_t ip_pkt_len);
#endif // TUN_H_INCLUDED
