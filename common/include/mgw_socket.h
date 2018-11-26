int mgw_socket_init();
void mgw_socket_close(int socket_fd);
int mgw_socket_bind(int socket_fd, const char *ip, u_int16_t port);
int mgw_socket_udp_recv(int socket_fd, char *buff, int len);
int mgw_socket_udp_send(int socket_fd, char *buff, int len, uint32_t dip, uint16_t dport);