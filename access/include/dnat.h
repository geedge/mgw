struct dnat_handle;

struct dnat_handle * dnat_init(const char *profile, struct ip_mgr_handle *_ip_mgr_handle, void *logger);

void dnat_destroy(struct dnat_handle *handle);

int dnat_tx_convert(struct dnat_handle *handle, char *buff, int len, uint32_t *mrl_ip);

int dnat_rx_convert(struct dnat_handle *handle, char *buff, int len);