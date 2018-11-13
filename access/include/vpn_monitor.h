#pragma once 

struct vpn_monitor_args
{
    MESA_htable_handle ip2user_htable;
    void *logger;
    const char *profile;
};

void * thread_vpn_monitor(void* arg);