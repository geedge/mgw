#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include "MESA/MESA_handle_logger.h"
#include "MESA/MESA_htable.h"
#include "MESA/MESA_prof_load.h"
#include "field_stat2.h"
#include "Maat_rule.h"
#include "Maat_command.h"

#define MGW_STRING_MAX			2048
#define	MGW_PATH_MAX			256
#define MGW_SYMBOL_MAX			64
#define MGW_THREAD_MAX			128
#define MGW_PACKET_MAX 3000
#define MGW_HTABLE_KEY_EXISTED 0
#define MGW_HTABLE_KEY_NOT_EXISTED -1
#define MGW_DROP 0    // something error, drop the packet
#define MGW_BYPASS 1  // give others to handle
#define MGW_FORWORD 2 // for snat: send to mrl,  for dnat: send to real server
#define likely(expr)    __builtin_expect((expr), 1)
#define unlikely(expr)  __builtin_expect((expr), 0)

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#define	FREE(p)	{free(*p);*p=NULL;}

#define MGW_LOG_ERROR(handler, fmt, ...)															\
do { 													\
	 MESA_handle_runtime_log(handler, RLOG_LV_FATAL, "mgw", fmt, ##__VA_ARGS__); } while(0)			

#define MGW_LOG_INFO(handler, fmt, ...)																\
do { 												\
	 MESA_handle_runtime_log(handler, RLOG_LV_INFO, "mgw", fmt, ##__VA_ARGS__); } while(0)			

#define MGW_LOG_DEBUG(handler, fmt, ...)															\
do { MESA_handle_runtime_log(handler, RLOG_LV_DEBUG, "mgw", fmt, ##__VA_ARGS__); } while(0)			


//fprintf(stderr, fmt "\n", ##__VA_ARGS__);
MESA_htable_handle mgw_utils_create_htable(const char *profile, const char *section, void *free_data_cb, void *expire_notify_cb, void *logger);


struct field_stat_handle
{
    screen_stat_handle_t handle;
    int field_tun_read;
    int field_tun_bypass;
    int field_tun_write;
    int field_rx_from_mrl;
    int field_tx_to_mrl;
    int cloumn_query_num;
    int cloumn_element_num;
    int cloumn_cache_hit;
    int cloumn_cache_miss;
    int line_snat;
    int line_dnat;
    int line_ip2user;
    int line_user2ips;
    int line_snat_policy;
    int line_dnat_policy;
    int line_snat_cand_ip;
    int line_mrl_ip;
    int snat_rx_latency;
    int snat_tx_latency;
    int dnat_rx_latency;
    int dnat_tx_latency;
};

struct mgw_utils_sess
{
     uint32_t sip;
     uint16_t sport;
     uint32_t dip;
     uint16_t dport;
     uint8_t proto;
};

unsigned int mgw_utils_get_random(unsigned int num);

int mgw_utils_inet_ntoa(unsigned int ip, char *dest);

uint16_t mgw_utils_ip_checksum(const void *buff, size_t hdr_len);

uint16_t mgw_utils_tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr);

uint16_t mgw_utils_udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr);

int mgw_utils_pkt_sess_parse(const char *buff, int len, struct mgw_utils_sess *sess);

int mgw_utils_pkt_sess_replace(const char *buff, int len, mgw_utils_sess *sess);

void mgw_utils_fs_latency_cala(screen_stat_handle_t handle, struct timespec start_time, int field);

int mgw_utils_sess_to_str(struct mgw_utils_sess *sess, char *sess_str);
