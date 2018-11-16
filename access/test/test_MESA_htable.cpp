
#include "mgw_utils.h"

static struct htable_opts * htable_opt_init(const char* profile, void *logger)
{
    struct htable_opts* _htable_opts = ALLOC(struct htable_opts, 1);
    const char *section = "htable_opt";
    MESA_load_profile_int_def(profile, section, "mho_screen_print_ctrl", &(_htable_opts->mho_screen_print_ctrl), 0);
    MESA_load_profile_int_def(profile, section, "mho_thread_safe", &(_htable_opts->mho_thread_safe), 1);
    MESA_load_profile_int_def(profile, section, "mho_mutex_num", &(_htable_opts->mho_mutex_num), 16);
    MESA_load_profile_int_def(profile, section, "mho_hash_slot_size", &(_htable_opts->mho_hash_slot_size), 16);
    MESA_load_profile_int_def(profile, section, "mho_expire_time", &(_htable_opts->mho_expire_time), 0);
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n mho_screen_print_ctrl: %d\n mho_thread_safe: %d\n mho_mutex_num: %d\n mho_hash_slot_size: %d\n mho_expire_time: %d", 
        "htable_opt", _htable_opts->mho_screen_print_ctrl, _htable_opts->mho_thread_safe, _htable_opts->mho_mutex_num, _htable_opts->mho_hash_slot_size, _htable_opts->mho_expire_time);
    return _htable_opts;
}

void test_htable_data_free_cb(void *data)
{
    free(data);
    //FREE(&data);
}


struct candidate_port
{
    unsigned char access_id : 2;
    unsigned char  random : 6;
    unsigned char  hash : 8;
};

int main()
{
    struct candidate_port port;
    printf("size of port is %d\n", sizeof(candidate_port));
    port.access_id = 0x3;
    port.random = 0x39;
    port.hash = 0xff;
    printf("port is %0x\n", port);
    /*
    const char *profile = "./conf/mgw.conf";
    void *logger = MESA_create_runtime_log_handle("./log/mgw.log", RLOG_LV_DEBUG);
    struct htable_opts * opts = htable_opt_init(profile, logger);
    MESA_htable_handle test_htable = create_htable("test", opts, (void *)test_htable_data_free_cb, NULL);
    const char ip[MGW_SYMBOL_MAX] = "192.168.1.1";
    int key_size = strnlen(ip, MGW_SYMBOL_MAX);
    char *user_name = ALLOC(char, MGW_SYMBOL_MAX);
    strncpy(user_name, "leo", MGW_SYMBOL_MAX); 
    //int rtn = MESA_htable_add(test_htable, (const unsigned char *)ip, key_size, user_name);
    //printf("MESA_htable_add: ret is %d\n", rtn);
    int rtn = MESA_htable_del(test_htable, (const unsigned char *)ip, key_size, NULL);
    printf("MESA_htable_del: ret is %d\n", rtn);
    */
    //char ip[MGW_SYMBOL_MAX] = "1.0.0.0";
    //uint32_t _ip = inet_addr(ip);
}

