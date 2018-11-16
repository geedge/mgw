struct udp_server_args
{
    void *logger;
    const char *profile;
    struct nat_handle *_nat_handle;
    struct mgw_tun_handle *tun_handle;
};
void * thread_udp_server(void *args);
