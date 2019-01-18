struct snat_handle;

struct snat_handle * snat_init(const char *profile, MESA_htable_handle ip2user_htable, 
            struct ip_mgr_handle *_ip_mgr_handle, void *logger);

void snat_destroy(struct snat_handle *handle);

int snat_tx_convert(struct snat_handle *handle, char *buff, int len, uint32_t *mrl_ip);

int snat_rx_convert(struct snat_handle *handle, char *buff, int len);