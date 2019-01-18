struct udp_server_args
{
    void *logger;
    const char *profile;
    struct snat_handle *_snat_handle;
    struct dnat_handle *_dnat_handle;
    struct mgw_tun_handle *tun_handle;
};
void * thread_udp_server(void *args);
