#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "MESA/MESA_handle_logger.h"
#include "MESA/MESA_htable.h"
#include "MESA/MESA_prof_load.h"
#include "Maat_rule.h"
#include "Maat_command.h"

#define MGW_STRING_MAX			2048
#define	MGW_PATH_MAX			256
#define MGW_SYMBOL_MAX			64
#define MGW_THREAD_MAX			128
#define MGW_PACKET_MAX 3000
#define HTABLE_QUERY_CB_SUCCESS 0
#define HTABLE_QUERY_CB_FAILURE -1
#define HTABLE_KEY_EXISTED 0
#define HTABLE_KEY_NOT_EXISTED -1
#define PROTO_TCP 0x06
#define PROTO_UDP 0x11
#define PROTO_ICMP 0x01
#define likely(expr)    __builtin_expect((expr), 1)
#define unlikely(expr)  __builtin_expect((expr), 0)

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#define	FREE(p)	{free(*p);*p=NULL;}

#define MGW_LOG_ERROR(handler, fmt, ...)															\
do { fprintf(stderr, fmt "\n" , ##__VA_ARGS__);														\
	 MESA_handle_runtime_log(handler, RLOG_LV_FATAL, "mgw", fmt, ##__VA_ARGS__); } while(0)			

#define MGW_LOG_INFO(handler, fmt, ...)																\
do { fprintf(stderr, fmt "\n", ##__VA_ARGS__);														\
	 MESA_handle_runtime_log(handler, RLOG_LV_INFO, "mgw", fmt, ##__VA_ARGS__); } while(0)			

#define MGW_LOG_DEBUG(handler, fmt, ...)															\
do { MESA_handle_runtime_log(handler, RLOG_LV_DEBUG, "mgw", fmt, ##__VA_ARGS__); } while(0)			

struct htable_opts
{
    int mho_screen_print_ctrl;
    int mho_thread_safe;
    int mho_mutex_num;
    int mho_hash_slot_size;
    int mho_expire_time;
	void *logger;
};

MESA_htable_handle mgw_utils_create_htable(const char *symbol, struct htable_opts *_htable_opts, void *free_data_cb, void *expire_notify_cb);


unsigned int mgw_utils_get_random(unsigned int num);

const char * mgw_utils_inet_ntoa(unsigned int ip);