#pragma once 

struct mgw_tun_handle;

struct mgw_tun_handle * mgw_tun_init(const char *dev, void *logger);

int mgw_tun_read(struct mgw_tun_handle *handle, char *recv_ip_pkts, size_t ip_pkt_len);

int mgw_tun_write(struct mgw_tun_handle *handle, char *buff, size_t len);

void mgw_tun_destroy(struct mgw_tun_handle *handle);