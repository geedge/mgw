struct cand_ip
{
    uint32_t ip;
    int reference;
};

struct ip_mgr_handle;
struct ip_mgr_handle *ip_mgr_init(void *logger, Maat_feather_t feather, struct htable_opts* opts);
void ip_mgr_destroy(struct ip_mgr_handle *handle);
struct cand_ip* ip_mgr_candidata_ip_get(struct ip_mgr_handle *handle, const char *user_name);
bool ip_mgr_candidate_ip_verify(struct ip_mgr_handle *handle, uint32_t ip);


