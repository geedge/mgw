struct udp_server_args
{
    void *logger;
    const char *profile;
    struct nat_handle *_nat_handle;
    struct mgw_tun_handle *tun_handle;
    struct field_stat_handle *fs_handle;
};
void * thread_udp_server(void *args);
