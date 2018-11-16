#define IP_MGR_MAC_LEN 18 
#define IP_MGR_IP_LEN 16 
#define IP_MGR_PORT_LEN 6

struct ip_mgr_cand_ip
{
    uint32_t ip;
    int reference;
    struct ip_mgr_vxlan_info *vxlan_info;
};

struct ip_mgr_vxlan_info
{
    char vxlan_outer_local_mac[IP_MGR_MAC_LEN];//接收到的数据包的本地设备MAC地址
    char vxlan_outer_gdev_mac[IP_MGR_MAC_LEN];//接收到的数据包的串行设备MAC地址
    char vxlan_outer_local_ip[IP_MGR_IP_LEN];
    char vxlan_outer_gdev_ip[IP_MGR_IP_LEN];//串行设备IP
    char vxlan_outer_gdev_port[IP_MGR_PORT_LEN];
    char vxlan_outer_local_port[IP_MGR_PORT_LEN];
    int vxlan_encap_type;
    int vxlan_link_id;
    int vxlan_link_dir;
    char vxlan_inner_smac[IP_MGR_MAC_LEN];
    char vxlan_inner_dmac[IP_MGR_MAC_LEN];
};  

struct ip_mgr_handle;
struct ip_mgr_handle *ip_mgr_init(void *logger, Maat_feather_t feather, struct htable_opts* opts);
void ip_mgr_destroy(struct ip_mgr_handle *handle);
struct ip_mgr_cand_ip* ip_mgr_candidata_ip_get(struct ip_mgr_handle *handle, const char *user_name);
bool ip_mgr_candidate_ip_verify(struct ip_mgr_handle *handle, uint32_t ip);


