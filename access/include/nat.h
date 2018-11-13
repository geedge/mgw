#define NAT_COVERT_SUCCESS -1
#define NAT_COVERT_FAILURE 0

struct nat_handle;
struct nat_handle * nat_init(MESA_htable_handle htable, void *logger, struct htable_opts* opts);
void nat_destroy(struct nat_handle *handle);
int nat_src_convert(struct nat_handle *handle, struct ip_mgr_handle *_ip_mgr_handle, char *buff, int len);
int nat_dest_convert(struct nat_handle *handle, char *buff, int len);