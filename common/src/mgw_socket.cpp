
#include "mgw_utils.h"

int mgw_socket_udp_send(int socket_fd, char *buff, int len, uint32_t dip, uint16_t dport)
{
   struct sockaddr_in server;
   server.sin_family      = AF_INET;            /* Internet Domain    */
   server.sin_port        = dport;               /* Server Port        */
   server.sin_addr.s_addr = dip;                 /* Server's Address   */
   int rtn = sendto(socket_fd, buff, len, 0, (struct sockaddr *)&server, sizeof(server));
   return rtn;
}


int mgw_socket_init()
{
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    return socket_fd;
}

int mgw_socket_close(int socket_fd)
{
    close(socket_fd);
}


int mgw_socket_bind(int socket_fd, const char *ip, u_int16_t port)
{
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);
    int rtn = bind(socket_fd, (struct sockaddr *)&server, sizeof(server));
    return 0;
}
   

int mgw_socket_udp_recv(int socket_fd, char *buff)
{
    struct sockaddr_in client;
    unsigned int client_len = sizeof(client);
    int len = recvfrom(socket_fd, buff, sizeof(buff), 0, (struct sockaddr *) &client, &client_len);
    return len;
}