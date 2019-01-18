#pragma once 

struct vpn_monitor_args
{
    MESA_htable_handle ip2user_htable;
    MESA_htable_handle *user2ips_htable_ptr;
    void *logger;
    const char *profile;
};

#define MAX_LOGIN_PER_USER 10
#define MAX_HUB_NUM 20

struct user2ips_value{
    uint32_t ip_list[MAX_LOGIN_PER_USER];
    int num;
};

void * thread_vpn_monitor(void* arg);