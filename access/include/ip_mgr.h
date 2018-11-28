#define IP_MGR_MAC_LEN 18 
#define IP_MGR_IP_LEN 16 
#define IP_MGR_PORT_LEN 6

struct ip_mgr_cand_ip_detail
{
    uint32_t ip;
    int reference;
    struct ip_mgr_vxlan_info *vxlan_info;
    uint32_t mrl_ip;
};


struct ip_mgr_vxlan_info
{
    int vxlan_link_id;
    int vxlan_encap_type;
    int vxlan_link_dir;
    int vxlan_vpn_id;
    char vxlan_outer_local_port[IP_MGR_PORT_LEN];
    char vxlan_outer_gdev_port[IP_MGR_PORT_LEN];
    char vxlan_outer_local_ip[IP_MGR_IP_LEN];
    char vxlan_outer_gdev_ip[IP_MGR_IP_LEN];//串行设备IP
    char vxlan_outer_local_mac[IP_MGR_MAC_LEN];//接收到的数据包的本地设备MAC地址
    char vxlan_outer_gdev_mac[IP_MGR_MAC_LEN];//接收到的数据包的串行设备MAC地址
    char vxlan_inner_smac[IP_MGR_MAC_LEN];
    char vxlan_inner_dmac[IP_MGR_MAC_LEN];
};  

struct ip_mgr_handle;
struct ip_mgr_handle *ip_mgr_init(const char *profile, MESA_htable_handle cand_ip_detail_htable, struct field_stat_handle *fs_handle, 
                Maat_feather_t feather, void *logger);
void ip_mgr_destroy(struct ip_mgr_handle *handle);
int ip_mgr_candidata_ip_get(struct ip_mgr_handle *handle, const char *user_name, uint32_t *selected_ip);