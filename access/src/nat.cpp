#include "mgw_utils.h"
#include "nat.h"
#include "ip_mgr.h"
//hash表超时时间设为0，不超时
// hash表 value 为malloc

struct nat_handle
{
    void *logger;
    struct htable_opts* htable_opts_s;
    MESA_htable_handle ip2user_htable;  // should be thread-safe
    MESA_htable_handle snat_htable;
    MESA_htable_handle dnat_htable;
    int access_id;
};

struct session
{
     uint32_t sip;
     uint16_t sport;
     uint32_t dip;
     uint16_t dport;
     uint8_t proto;
};

struct ip_port_pair
{
     uint32_t ip;
     uint16_t port;
};

struct nat_ctx
{
    void *logger;
    char *buff;
    int len;
    MESA_htable_handle ip2user_htable; 
};

// input: ip packet 
// output: session <sip, dip, sport, dport, proto>
static int sess_get_from_packet(const char *buff, int len, struct session *sess)
{
    if(len < 20)
    {
        return -1;
    }
    struct iphdr *_iphdr = (struct iphdr *)buff;
    int iphdr_len = _iphdr->ihl * 4;
    sess->sip = _iphdr->saddr;
    sess->dip = _iphdr->daddr;
    sess->proto = _iphdr->protocol;
    switch(sess->proto)
    {
        case PROTO_TCP:
        {
            if(len < 40)
            {
                return -1;
            }
            struct tcphdr *_tcphdr = (struct tcphdr *)(buff + iphdr_len);
            sess->sport = _tcphdr->source;
            sess->dport = _tcphdr->dest;
            break;
        }
        case PROTO_UDP:
        {
            if(len < 28)
            {
                return -1;
            }
            struct udphdr *_udphdr = (struct udphdr *)(buff + iphdr_len);
            sess->sport = _udphdr->source;
            sess->dport = _udphdr->dest;
            break;
        }
        case PROTO_ICMP:
        {
            if(len < 28)
            {
                return -1;
            }
            break;
        }
        default:
            return -1;
            break;
    }
    return 0;
}

static int packet_src_replace(const char *buff, int len, struct ip_port_pair *pair)
{
    
    struct iphdr *_iphdr = (struct iphdr *)buff;
    int iphdr_len = _iphdr->ihl * 4;
    _iphdr->saddr = pair->ip;
    switch(_iphdr->protocol)
    {
        case PROTO_TCP:
        {
            struct tcphdr *_tcphdr = (struct tcphdr *)(buff + iphdr_len);
            _tcphdr->source = pair->port;
            break;
        }
        case PROTO_UDP:
        {
            struct udphdr *_udphdr = (struct udphdr *)(buff + iphdr_len);
            _udphdr->source = pair->port;
            break;
        }
        case PROTO_ICMP:
            break;
        default:
            break;
    }
    return 0;
}

static int packet_dest_replace(const char *buff, int len, struct ip_port_pair *pair)
{
    struct iphdr *_iphdr = (struct iphdr *)buff;
    int iphdr_len = _iphdr->ihl * 4;
    _iphdr->daddr = pair->ip;
    switch(_iphdr->protocol)
    {
        case PROTO_TCP:
        {
            struct tcphdr *_tcphdr = (struct tcphdr *)(buff + iphdr_len);
            _tcphdr->dest = pair->port;
            break;
        }
        case PROTO_UDP:
        {
            struct udphdr *_udphdr = (struct udphdr *)(buff + iphdr_len);
            _udphdr->dest = pair->port;
            break;
        }
        case PROTO_ICMP:
            break;
        default:
            break;
    }
    return 0;
}

static void snat_htable_data_free_cb(void *data)
{
    FREE(&data);
}

static void dnat_htable_data_free_cb(void *data)
{
    FREE(&data);
}


struct nat_handle * nat_init(MESA_htable_handle _ip2user_htable, void *logger, struct htable_opts* opts)
{
    struct nat_handle *handle = ALLOC(struct nat_handle, 1);
    handle->logger = logger;
    handle->ip2user_htable = _ip2user_htable;
    handle->htable_opts_s = opts;
    handle->snat_htable = mgw_utils_create_htable("snat_htable", opts, (void *)snat_htable_data_free_cb, NULL);
    handle->dnat_htable = mgw_utils_create_htable("dnat_htable", opts, (void *)dnat_htable_data_free_cb, NULL);
    handle->access_id = 0;
    return handle;
}

void nat_destroy(struct nat_handle *handle)
{
    MESA_htable_destroy(handle->snat_htable, snat_htable_data_free_cb);
    MESA_htable_destroy(handle->dnat_htable, dnat_htable_data_free_cb);
    FREE(&handle);
}

static long snat_htable_query_cb(void *data, const uchar *key, uint size, void *user_arg)
{
    struct ip_port_pair *pair = (struct ip_port_pair *)user_arg;
    if(data != NULL)
    {
        struct ip_port_pair *_data = (struct ip_port_pair *)data;
        pair->ip = _data->ip;
        pair->port = _data->port;
        return HTABLE_KEY_EXISTED;
    }
    else
    {
        return HTABLE_KEY_NOT_EXISTED;
    }
}

static long dnat_htable_query_cb(void *data, const uchar *key, uint size, void *user_arg)
{
    struct ip_port_pair *pair = (struct ip_port_pair *)user_arg;
    if(data != NULL)
    {
        struct ip_port_pair *_data = (struct ip_port_pair *)data;
        pair->ip = _data->ip;
        pair->port = _data->port;
        return HTABLE_KEY_EXISTED;
    }
    else
    {
        return HTABLE_KEY_NOT_EXISTED;
    }
}

static uint16_t get_candidate_port(int access_id, struct session *sess, uint32_t cand_ip)
{   
    u_int16_t random  = mgw_utils_get_random(64);
    uint16_t hash = ((sess->dip)^(htons(sess->dport))^(sess->proto)^cand_ip)&0xff;
    uint16_t port = (access_id << 14) + (random << 8) + hash;
    return htons(port);
}

static struct ip_port_pair * snat_pair_get(struct nat_handle *handle, struct ip_mgr_handle *_ip_mgr_handle, 
                            const char *user_name, struct session *snat_key, struct ip_mgr_vxlan_info **vxlan_info)
{
    int retry_times = 10;
    void *logger = handle->logger;
    for(int i = 0; i < retry_times; i++)
    {
        struct ip_mgr_cand_ip* _cand_ip = ip_mgr_candidata_ip_get(_ip_mgr_handle, user_name);
        if(_cand_ip == NULL)
        {
            MGW_LOG_INFO(logger, "Failed to find ip and port, user_name is %s", user_name);
            return NULL;
        }
        u_int16_t port = get_candidate_port(handle->access_id, snat_key, _cand_ip->ip);
        struct session dnat_key;
        dnat_key.sip = snat_key->dip;
        dnat_key.sport = snat_key->dport;
        dnat_key.proto = snat_key->proto;
        dnat_key.dip = _cand_ip->ip;
        dnat_key.dport = port;
        long dnat_cb_rtn = -1;
        struct ip_port_pair pair;
        MESA_htable_search_cb(handle->dnat_htable, (const unsigned char *)(&dnat_key), sizeof(dnat_key), dnat_htable_query_cb, (void *)(&pair), &dnat_cb_rtn);
        if(dnat_cb_rtn == HTABLE_KEY_EXISTED)
        {
            MGW_LOG_INFO(logger, "Select ip and port conflict, retry times is %d", i);
            continue;
        }
        else
        {
            struct ip_port_pair *selected_pair = ALLOC(struct ip_port_pair, 1);
            selected_pair->ip = _cand_ip->ip;
            _cand_ip->reference ++;
            selected_pair->port = port;
            *vxlan_info = _cand_ip->vxlan_info;
            return selected_pair;
        }
    }
    MGW_LOG_INFO(logger, "Failed to find ip and port, retry times is %d", retry_times - 1);
    return NULL;
}

int nat_src_convert(struct nat_handle *handle, struct ip_mgr_handle *_ip_mgr_handle, char *buff, int len, struct ip_mgr_vxlan_info **vxlan_info)
{
    void *logger = handle->logger;
    //get session
    struct session snat_key;
    int rtn = sess_get_from_packet(buff, len, &snat_key);
    if(rtn == -1)
    {
        MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
        return NAT_COVERT_FAILURE;
    }
    char snat_key_sip[MGW_SYMBOL_MAX];
    char snat_key_dip[MGW_SYMBOL_MAX];
    char snat_value_ip[MGW_SYMBOL_MAX];
    char dnat_key_sip[MGW_SYMBOL_MAX];
    char dnat_key_dip[MGW_SYMBOL_MAX];
    char dnat_value_ip[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(snat_key.sip, snat_key_sip);
    mgw_utils_inet_ntoa(snat_key.dip, snat_key_dip);
    MGW_LOG_INFO(logger, "Before snat: session is <%s:%d  %s:%d  %d>", 
        snat_key_sip, ntohs(snat_key.sport), snat_key_dip, ntohs(snat_key.dport), snat_key.proto);
    //query snat_htable，get ip_port pair
    long snat_cb_rtn = -1;
    struct ip_port_pair snat_value;
    MESA_htable_search_cb(handle->snat_htable, (const unsigned char *)(&snat_key), sizeof(snat_key), snat_htable_query_cb, (void *)(&snat_value), &snat_cb_rtn);
    bool ip_is_valid = ip_mgr_candidate_ip_verify(_ip_mgr_handle, snat_value.ip);
    if(snat_cb_rtn == HTABLE_KEY_EXISTED && ip_is_valid == true)
    {
        mgw_utils_inet_ntoa(snat_value.ip, snat_value_ip);
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s， key is <%s:%d  %s:%d  %d>, value is <%s, %d>", "ip2user_htable",
             snat_key_sip, ntohs(snat_key.sport), snat_key_dip, ntohs(snat_key.dport), snat_key.proto, snat_value_ip, snat_value.port);
        packet_src_replace(buff, len, &snat_value);
    }
    else
    {
        //if session exists in sant but ip is valid. del session from snat and dnat
        if(snat_cb_rtn == HTABLE_KEY_EXISTED)
        {
            rtn = MESA_htable_del(handle->snat_htable, (const unsigned char *)(&snat_key), sizeof(snat_key), NULL);
            // data may be freed because of expire
            if(rtn < 0 && rtn != MESA_HTABLE_RET_NOT_FOUND)
            {
                MGW_LOG_ERROR(handle->logger, "MESA_htable: failed at del, errno is %d, table is %s, key is <%s:%d %s,%d, %d>", rtn, "snat_htable", 
                    snat_key_sip, ntohs(snat_key.sport), snat_key_dip, ntohs(snat_key.dport), snat_key.proto);
                return NAT_COVERT_FAILURE;;
            }
            struct session dnat_key;
            dnat_key.sip = snat_key.dip;
            dnat_key.sport = snat_key.dport;
            dnat_key.dip = snat_value.ip;
            dnat_key.dport = snat_value.port;
            dnat_key.proto = snat_key.proto;
            mgw_utils_inet_ntoa(dnat_key.sip, dnat_key_sip);
            mgw_utils_inet_ntoa(dnat_key.dip, dnat_key_dip);
            rtn = MESA_htable_del(handle->dnat_htable, (const unsigned char *)(&dnat_key), sizeof(dnat_key), NULL);
            if(rtn < 0 && rtn != MESA_HTABLE_RET_NOT_FOUND)
            {
                MGW_LOG_ERROR(handle->logger, "MESA_htable: failed at del, errno is %d, table is %s, key is <%s:%d %s,%d, %d>", rtn, "dnat_htable", 
                    snat_key_sip, ntohs(dnat_key.sport), snat_key_dip, ntohs(snat_key.dport), snat_key.proto);
                return NAT_COVERT_FAILURE;;
            }
        }
        uint32_t sip = snat_key.sip;
        char *user_name;
        user_name = (char *)MESA_htable_search(handle->ip2user_htable, (const unsigned char *)(&sip), sizeof(sip));
        if(user_name != NULL)
        {
            struct ip_port_pair *snat_value = snat_pair_get(handle, _ip_mgr_handle, user_name, &snat_key, vxlan_info);
            if(snat_value == NULL)
            {
                 return NAT_COVERT_FAILURE;
            }
            //add sess to snat, dnat
            rtn = MESA_htable_add(handle->snat_htable, (const unsigned char *)(&snat_key), sizeof(snat_key), (const void*)snat_value);
            mgw_utils_inet_ntoa(snat_value->ip, snat_value_ip);
            if(rtn < 0)
            {
                MGW_LOG_ERROR(logger, "MESA_htable: Failed at add to %s, key is <%s:%d %s,%d, %d>, value is <%s, %d>", "snat_htable",
                    snat_key_sip, ntohs(snat_key.sport), snat_key_dip, ntohs(snat_key.dport), snat_key.proto, snat_value_ip, ntohs(snat_value->port));
                return NAT_COVERT_FAILURE;
            }
            MGW_LOG_INFO(logger, "MESA_htable: Succeed at add to %s, key is <%s:%d %s,%d, %d>, value is <%s, %d>", "snat_htable",
                    snat_key_sip, ntohs(snat_key.sport), snat_key_dip, ntohs(snat_key.dport), snat_key.proto, snat_value_ip, ntohs(snat_value->port));
            struct session dnat_key;
            dnat_key.sip = snat_key.dip;
            dnat_key.sport = snat_key.dport;
            dnat_key.dip = snat_value->ip;
            dnat_key.dport = snat_value->port;
            dnat_key.proto = snat_key.proto;
            struct ip_port_pair *dnat_value = ALLOC(struct ip_port_pair, 1);
            dnat_value->ip = snat_key.sip;
            dnat_value->port = snat_key.sport;
            mgw_utils_inet_ntoa(dnat_key.sip, dnat_key_sip);
            mgw_utils_inet_ntoa(dnat_key.dip, dnat_key_dip);
            mgw_utils_inet_ntoa(dnat_value->ip, dnat_value_ip);
            rtn = MESA_htable_add(handle->dnat_htable, (const unsigned char *)(&dnat_key), sizeof(dnat_key), (const void*)dnat_value);
            if(rtn < 0)
            {
                MGW_LOG_ERROR(logger, "MESA_htable: Failed at add to %s, key is <%s:%d %s,%d, %d>, value is <%s, %d>", "dnat_htable",
                    dnat_key_sip, ntohs(dnat_key.sport), dnat_key_dip, ntohs(dnat_key.dport), dnat_key.proto, dnat_value_ip, ntohs(dnat_value->port));
                return NAT_COVERT_FAILURE;
            }
            MGW_LOG_INFO(logger, "MESA_htable: Succeed at add to %s, key is <%s:%d %s,%d, %d>, value is <%s, %d>", "dnat_htable",
                    dnat_key_sip, ntohs(dnat_key.sport), dnat_key_dip, ntohs(dnat_key.dport), dnat_key.proto, dnat_value_ip, ntohs(dnat_value->port));
            packet_src_replace(buff, len, snat_value);
            rtn = sess_get_from_packet(buff, len, &snat_key);
            if(rtn == -1)
            {
                MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
                return NAT_COVERT_FAILURE;
            }
            mgw_utils_inet_ntoa(snat_key.sip, snat_key_sip);
            mgw_utils_inet_ntoa(snat_key.dip, snat_key_dip);
            MGW_LOG_INFO(logger, "After snat: session is <%s:%d  %s:%d  %d>", 
                snat_key_sip, ntohs(snat_key.sport), snat_key_dip, ntohs(snat_key.dport), snat_key.proto);
            return NAT_COVERT_SUCCESS;
        }
        else
        {
            MGW_LOG_ERROR(logger, "Failed at find user_name, ip %s", snat_key_sip);
            return NAT_COVERT_FAILURE;
        }
    }
}


int nat_dest_convert(struct nat_handle *handle, char *buff, int len)
{
    void *logger = handle->logger;
    //get session
    struct session dnat_key;
    int rtn = sess_get_from_packet(buff, len, &dnat_key);
    if(rtn == -1)
    {
        MGW_LOG_ERROR(logger, "Failed at parse packet, packet len is %d", len);
        return NAT_COVERT_FAILURE;
    }
    char dnat_key_sip[MGW_SYMBOL_MAX];
    char dnat_key_dip[MGW_SYMBOL_MAX];
    char dnat_value_ip[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(dnat_key.sip, dnat_key_sip);
    mgw_utils_inet_ntoa(dnat_key.dip, dnat_key_dip);
    MGW_LOG_INFO(logger, "Before dnat: session is <%s:%d  %s:%d  %d>", 
        dnat_key_sip, ntohs(dnat_key.sport), dnat_key_dip, ntohs(dnat_key.dport), dnat_key.proto);

    //query dnat，get ip and port
     long dnat_cb_rtn = -1;
     struct ip_port_pair dnat_value;
     MESA_htable_search_cb(handle->dnat_htable, (const unsigned char *)(&dnat_key), sizeof(dnat_key), dnat_htable_query_cb, (void *)(&dnat_value), &dnat_cb_rtn);
    if(dnat_cb_rtn == HTABLE_KEY_EXISTED)
    {
        mgw_utils_inet_ntoa(dnat_value.ip, dnat_value_ip);
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s， key is <%s:%d %s,%d, %d>, value is <%s, %d>", "dnat_htable",
            dnat_key_sip, ntohs(dnat_key.sport), dnat_key_dip, ntohs(dnat_key.dport), dnat_key.proto, dnat_value_ip, ntohs(dnat_value.port));
        packet_dest_replace(buff, len, &dnat_value);
        rtn = sess_get_from_packet(buff, len, &dnat_key);
        if(rtn == -1)
        {
            MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
            return NAT_COVERT_FAILURE;
        }
        mgw_utils_inet_ntoa(dnat_key.sip, dnat_key_sip);
        mgw_utils_inet_ntoa(dnat_key.dip, dnat_key_dip);
        MGW_LOG_INFO(logger, "After snat: session is <%s:%d  %s:%d  %d>", 
            dnat_key_sip, ntohs(dnat_key.sport), dnat_key_dip, ntohs(dnat_key.dport), dnat_key.proto);
        return NAT_COVERT_SUCCESS;
    }
    else
    {
        MGW_LOG_INFO(logger, "MESA_htable: key not existed, table is %s， key is <%s:%d %s,%d, %d>", "dnat_htable",
            dnat_key_sip, ntohs(dnat_key.sport), dnat_key_dip, ntohs(dnat_key.dport), dnat_key.proto);
        return NAT_COVERT_FAILURE;
    }
}
