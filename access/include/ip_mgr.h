
struct ip_mgr_handle;

struct ip_mgr_handle *ip_mgr_init(const char *profile, MESA_htable_handle *user2ips_htable_ptr, void *logger);

void ip_mgr_destroy(struct ip_mgr_handle *handle);

int ip_mgr_dnat_policy_query(struct ip_mgr_handle *handle, uint32_t orig_ip, uint16_t orig_port, uint8_t orig_proto,
        uint32_t *trans_ip_ptr, uint16_t *trans_port_ptr);

int ip_mgr_mrl_ip_query(struct ip_mgr_handle *handle, uint32_t back_ip, uint32_t *mrl_ip);

int ip_mgr_snat_cand_ip_get(struct ip_mgr_handle *handle, const char *user_name, uint32_t *selected_ip, uint32_t dest_ip);