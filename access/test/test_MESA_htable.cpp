
#include "mgw_utils.h"
#include "ip_locator.h"
int main()
{
    void *logger = MESA_create_runtime_log_handle("./log/test.log", 10);
    struct ip_locator_handle *handle = ip_locator_init("/root/IPReuse/mgw/conf/mgw.conf", logger);
    bool is_inside = false;
    const char *ip_str = "193.193.255.87";
    uint32_t ip = inet_addr(ip_str);
    int rtn = ip_locator_is_inside(handle, ip, &is_inside);
    printf("rtn is %d, ip %s is %s\n", rtn, ip_str, is_inside == true ? "inside" : "outside");
    ip_locator_destroy(handle);
}
