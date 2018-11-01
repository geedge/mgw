#pragma once
#include <MESA/MESA_handle_logger.h>

#define MGW_STRING_MAX			2048
#define	MGW_PATH_MAX			256
#define MGW_SYMBOL_MAX			64
#define MGW_THREAD_MAX			128


#define likely(expr)    __builtin_expect((expr), 1)
#define unlikely(expr)  __builtin_expect((expr), 0)

#define MGW_LOG_ERROR(handler, fmt, ...)															\
do { fprintf(stderr, fmt "\n" , ##__VA_ARGS__);														\
	 MESA_handle_runtime_log(handler, RLOG_LV_FATAL, "mgw", fmt, ##__VA_ARGS__); } while(0)			

#define MGW_LOG_INFO(handler, fmt, ...)																\
do { fprintf(stderr, fmt "\n", ##__VA_ARGS__);														\
	 MESA_handle_runtime_log(handler, RLOG_LV_INFO, "mgw", fmt, ##__VA_ARGS__); } while(0)			

#define MGW_LOG_DEBUG(handler, fmt, ...)															\
do { MESA_handle_runtime_log(handler, RLOG_LV_DEBUG, "mgw", fmt, ##__VA_ARGS__); } while(0)			

