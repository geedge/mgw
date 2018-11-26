#define NAT_COVERT_SUCCESS -1
#define NAT_COVERT_FAILURE 0

struct nat_handle;
struct nat_handle * nat_init(MESA_htable_handle ip2user_htable, MESA_htable_handle cand_ip_detail_htable, 
                        struct field_stat_handle *fs_handle, struct htable_opts* opts, void *logger);
void nat_destroy(struct nat_handle *handle);
int nat_src_convert(struct nat_handle *handle, struct ip_mgr_handle *_ip_mgr_handle, char *buff, int len, struct ip_mgr_vxlan_info **vxlan_info, uint32_t *mrl_ip);
int nat_dest_convert(struct nat_handle *handle, char *buff, int len);