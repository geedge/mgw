#include "mgw_utils.h"
#include "nat.h"
#include "ip_mgr.h"
//hash表超时时间设为0，不超时
// hash表 value 为malloc

struct nat_handle
{
    void *logger;
    MESA_htable_handle ip2user_htable;  // should be thread-safe
    MESA_htable_handle snat_htable;
    MESA_htable_handle dnat_htable;
    MESA_htable_handle cand_ip_detail_htable;
    struct field_stat_handle *fs_handle;
    int access_id;
};

struct field_stat_handle *g_fs_handle;

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
    uint16_t tot_len = ntohs(_iphdr->tot_len);
    uint16_t iphdr_len = _iphdr->ihl * 4;
    _iphdr->saddr = pair->ip;
    switch(_iphdr->protocol)
    {
        case PROTO_TCP:
        {
            struct tcphdr *_tcphdr = (struct tcphdr *)(buff + iphdr_len);
            uint16_t tcp_len = tot_len - iphdr_len;

            /* test
            uint16_t correct_tcp_check = _tcphdr->check;
            printf("correct_tcp_check is %0x\n", correct_tcp_check);
            _tcphdr->check = 0;
            u_int16_t my_tcp_check = mgw_utils_tcp_checksum(_tcphdr, tcp_len, _iphdr->saddr, _iphdr->daddr);
            printf("tcp_len is %d, my_tcp_check is %0x\n", tcp_len, my_tcp_check);
            */

            _tcphdr->source = pair->port;
            _tcphdr->check = 0;
            uint16_t tcp_checksum = mgw_utils_tcp_checksum(_tcphdr, tcp_len, _iphdr->saddr, _iphdr->daddr);
            _tcphdr->check = tcp_checksum;
            break;
        }
        case PROTO_UDP:
        {
            struct udphdr *_udphdr = (struct udphdr *)(buff + iphdr_len);
            uint16_t udp_len = tot_len - iphdr_len;
            _udphdr->source = pair->port;
            _udphdr->check = 0;
            uint16_t udp_checksum = mgw_utils_udp_checksum(_udphdr, udp_len, _iphdr->saddr, _iphdr->daddr);
            _udphdr->check = udp_checksum;
            break;
        }
        case PROTO_ICMP:
            break;
        default:
            break;
    }
    _iphdr->check = 0;
    uint16_t ip_checksum  = mgw_utils_ip_checksum(buff, iphdr_len);
    _iphdr->check = ip_checksum;
    return 0;
}

static int packet_dest_replace(const char *buff, int len, struct ip_port_pair *pair)
{
    struct iphdr *_iphdr = (struct iphdr *)buff;
    uint16_t tot_len = ntohs(_iphdr->tot_len);
    uint16_t iphdr_len = _iphdr->ihl * 4;
    _iphdr->daddr = pair->ip;
    switch(_iphdr->protocol)
    {
        case PROTO_TCP:
        {
            struct tcphdr *_tcphdr = (struct tcphdr *)(buff + iphdr_len);
            uint16_t tcp_len = tot_len - iphdr_len;

            /* test
            uint16_t correct_tcp_check = _tcphdr->check;
            printf("correct_tcp_check is %0x\n", correct_tcp_check);
            _tcphdr->check = 0;
            u_int16_t my_tcp_check = mgw_utils_tcp_checksum(_tcphdr, tcp_len, _iphdr->saddr, _iphdr->daddr);
            printf("tcp_len is %d, my_tcp_check is %0x\n", tcp_len, my_tcp_check);
            */

            _tcphdr->dest = pair->port;
            _tcphdr->check = 0;
            uint16_t tcp_checksum = mgw_utils_tcp_checksum(_tcphdr, tcp_len, _iphdr->saddr, _iphdr->daddr);
            _tcphdr->check = tcp_checksum;
            break;
        }
        case PROTO_UDP:
        {
            struct udphdr *_udphdr = (struct udphdr *)(buff + iphdr_len);
            uint16_t udp_len = tot_len - iphdr_len;
            _udphdr->dest = pair->port;
            _udphdr->check = 0;
            uint16_t udp_checksum = mgw_utils_udp_checksum(_udphdr, udp_len, _iphdr->saddr, _iphdr->daddr);
            _udphdr->check = udp_checksum;
            break;
        }
        case PROTO_ICMP:
            break;
        default:
            break;
    }
    _iphdr->check = 0;
    uint16_t ip_checksum  = mgw_utils_ip_checksum(buff, iphdr_len);
    _iphdr->check = ip_checksum;
    return 0;
}

static void snat_htable_data_free_cb(void *data)
{
    //printf("call snat_htable_data_free_cb\n");
    FS_operate(g_fs_handle->handle, g_fs_handle->line_snat, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    FREE(&data);
}

static void dnat_htable_data_free_cb(void *data)
{
    //printf("call dnat_htable_data_free_cb\n");
    FS_operate(g_fs_handle->handle, g_fs_handle->line_dnat, g_fs_handle->cloumn_element_num, FS_OP_ADD, -1);
    FREE(&data);
}


struct nat_handle * nat_init(const char *profile, MESA_htable_handle ip2user_htable, MESA_htable_handle cand_ip_detail_htable, 
                        struct field_stat_handle *fs_handle, void *logger)
{
    struct nat_handle *handle = ALLOC(struct nat_handle, 1);
    handle->logger = logger;
    handle->fs_handle = fs_handle;
    handle->ip2user_htable = ip2user_htable;
    handle->cand_ip_detail_htable = cand_ip_detail_htable;
    handle->snat_htable = mgw_utils_create_htable(profile, "snat_htable", (void *)snat_htable_data_free_cb, NULL, logger);
    handle->dnat_htable = mgw_utils_create_htable(profile, "dnat_htable", (void *)dnat_htable_data_free_cb, NULL, logger);
    handle->access_id = 0;
    g_fs_handle = fs_handle;
    return handle;
}

void nat_destroy(struct nat_handle *handle)
{
    MESA_htable_destroy(handle->snat_htable, NULL);
    MESA_htable_destroy(handle->dnat_htable, NULL);
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

/*
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
*/

static uint16_t get_candidate_port(int access_id, struct session *sess, uint32_t cand_ip)
{   
    u_int16_t random  = mgw_utils_get_random(64);
    uint16_t hash = ntohl(sess->dip) ^ ntohl(cand_ip) ^ ntohs(sess->dport) ^ (sess->proto);
    hash &= 0xff;
    uint16_t port = (access_id << 14) + (random << 8) + hash;
    /*
    #ifdef DEBUG
    printf("test_hash: dip is %0x, dport is %0x, cand_ip is %0x, proto is %0x, generate port is %0x\n",
            ntohl(sess->dip), ntohs(sess->dport), ntohl(cand_ip), sess->proto, port);
    #endif
    */
    return htons(port);
}

//get snat_value, if succeed, has already added to dnat_htable
static struct ip_port_pair * snat_value_get(struct nat_handle *handle, struct ip_mgr_handle *_ip_mgr_handle, const char *user_name, 
    struct session *snat_key, struct ip_mgr_vxlan_info **vxlan_info, uint32_t *mrl_ip)
{
    struct field_stat_handle *fs_handle = handle->fs_handle;
    int retry_times = 10;
    void *logger = handle->logger;
    struct session *dnat_key = ALLOC(struct session, 1);
    dnat_key->sip = snat_key->dip;
    dnat_key->sport = snat_key->dport;
    dnat_key->proto = snat_key->proto;
    struct ip_port_pair *snat_value = ALLOC(struct ip_port_pair, 1);
    struct ip_port_pair *dnat_value = ALLOC(struct ip_port_pair, 1);
    dnat_value->ip = snat_key->sip;
    dnat_value->port = snat_key->sport;
    char dnat_key_sip[MGW_SYMBOL_MAX];
    char dnat_key_dip[MGW_SYMBOL_MAX];
    char dnat_value_ip[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(dnat_key->sip, dnat_key_sip);
    mgw_utils_inet_ntoa(dnat_value->ip, dnat_value_ip);
    for(int i = 0; i < retry_times; i++)
    {
        uint32_t cand_ip;
        int rtn = ip_mgr_candidata_ip_get(_ip_mgr_handle, user_name, &cand_ip);
        if(rtn < 0)
        {
            MGW_LOG_INFO(logger, "Failed to find ip and port, user_name is %s", user_name);
            FREE(&dnat_key);
            FREE(&dnat_value);
            FREE(&snat_value);
            return NULL;
        }
        u_int16_t port = get_candidate_port(handle->access_id, snat_key, cand_ip);
        dnat_key->dip = cand_ip;
        dnat_key->dport = port;
        snat_value->ip = cand_ip;
        snat_value->port = port;
        mgw_utils_inet_ntoa(dnat_key->dip, dnat_key_dip);
        // check if cand_ip is still valid
        struct ip_mgr_cand_ip_detail *cand_ip_detail = NULL;
        cand_ip_detail = (struct ip_mgr_cand_ip_detail *)MESA_htable_search(handle->cand_ip_detail_htable, (const unsigned char *)(&cand_ip), sizeof(cand_ip));
        FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
        char _ip[MGW_SYMBOL_MAX];
        mgw_utils_inet_ntoa(cand_ip, _ip);
        if(cand_ip_detail == NULL)
        {
            FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
            MGW_LOG_ERROR(logger, "MESA_htable: table is %s, key %s not existed", "cand_ip_detail_htable", _ip);
            continue;
        }
        MGW_LOG_INFO(logger, "MESA_htable: table is %s, key %s existed", "cand_ip_detail_htable", _ip);
        FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        
        //try to add to dnat
        rtn = MESA_htable_add(handle->dnat_htable, (const unsigned char *)dnat_key, sizeof(struct session), (void *)dnat_value);
        if(rtn < 0 && rtn != MESA_HTABLE_RET_DUP_ITEM)
        {
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at add to %s, key is <%s:%d %s,%d, %d>, value is <%s, %d>, rtn is %d", "dnat_htable",
                dnat_key_sip, ntohs(dnat_key->sport), dnat_key_dip, ntohs(dnat_key->dport), dnat_key->proto, dnat_value_ip, ntohs(dnat_value->port), rtn);
            continue;
        }
        if(rtn == MESA_HTABLE_RET_DUP_ITEM)
        {
            MGW_LOG_INFO(logger, "Selected ip and port <%s:%d> conflict", dnat_key_dip, ntohs(dnat_key->dport));
            continue;
        }
        //rtn >= 0, succeed to add to dnat
        MGW_LOG_INFO(logger, "MESA_htable: Succeed at add to %s, key is <%s:%d %s,%d, %d>, value is <%s, %d>", "dnat_htable",
                dnat_key_sip, ntohs(dnat_key->sport), dnat_key_dip, ntohs(dnat_key->dport), dnat_key->proto, dnat_value_ip, ntohs(dnat_value->port));
        FS_operate(fs_handle->handle, fs_handle->line_dnat, fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        //reference + 1, when to --?
        cand_ip_detail->reference ++;
        *vxlan_info = cand_ip_detail->vxlan_info;
        *mrl_ip = cand_ip_detail->mrl_ip;
        FREE(&dnat_key);
        return snat_value;
    }
    MGW_LOG_ERROR(logger, "Failed to find ip and port, retry times is %d", retry_times - 1);
    FREE(&dnat_key);
    FREE(&dnat_value);
    FREE(&snat_value);
    return NULL;
}

int nat_src_convert(struct nat_handle *handle, struct ip_mgr_handle *_ip_mgr_handle, char *buff, int len, 
    struct ip_mgr_vxlan_info **vxlan_info, uint32_t *mrl_ip)
{
    struct field_stat_handle *fs_handle = handle->fs_handle;
    void *logger = handle->logger;
    //get session
    struct session *snat_key = ALLOC(struct session, 1);
    int rtn = sess_get_from_packet(buff, len, snat_key);
    if(rtn == -1)
    {
        MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
        FREE(&snat_key);
        return NAT_COVERT_FAILURE;
    }
    char snat_key_sip[MGW_SYMBOL_MAX];
    char snat_key_dip[MGW_SYMBOL_MAX];
    char snat_value_ip[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(snat_key->sip, snat_key_sip);
    mgw_utils_inet_ntoa(snat_key->dip, snat_key_dip);

    //for test
    /*
    if(strncmp(snat_key_dip, "61.135.169.121", MGW_SYMBOL_MAX) != 0)
    {
        return NAT_COVERT_FAILURE;
    }
    */

    MGW_LOG_INFO(logger, "Before snat: session is <%s:%d  %s:%d  %d>", 
        snat_key_sip, ntohs(snat_key->sport), snat_key_dip, ntohs(snat_key->dport), snat_key->proto);
    //query snat_htable，get ip_port pair
    long snat_cb_rtn = -1;
    struct ip_port_pair *snat_value = ALLOC(struct ip_port_pair, 1);
    MESA_htable_search_cb(handle->snat_htable, (const unsigned char *)(snat_key), sizeof(struct session), snat_htable_query_cb, (void *)(snat_value), &snat_cb_rtn);
    FS_operate(fs_handle->handle, fs_handle->line_snat, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
    if(snat_cb_rtn == HTABLE_KEY_EXISTED)
    {
        FS_operate(fs_handle->handle, fs_handle->line_snat, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        mgw_utils_inet_ntoa(snat_value->ip, snat_value_ip);
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s， key is <%s:%d  %s:%d  %d>, value is <%s, %d>", "snat_htable",
                snat_key_sip, ntohs(snat_key->sport), snat_key_dip, ntohs(snat_key->dport), snat_key->proto, snat_value_ip, ntohs(snat_value->port));
        struct ip_mgr_cand_ip_detail *cand_ip_detail = NULL;
        cand_ip_detail = (struct ip_mgr_cand_ip_detail *)MESA_htable_search(handle->cand_ip_detail_htable, (const unsigned char *)(&(snat_value->ip)), sizeof(snat_value->ip));
        FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
        if(cand_ip_detail != NULL)
        {
            FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
            MGW_LOG_INFO(handle->logger, "MESA_htable, key existed, table is %s, key is %s", "cand_ip_detail_htable", snat_value_ip);
            packet_src_replace(buff, len, snat_value);
            //after snat 
            rtn = sess_get_from_packet(buff, len, snat_key);
            if(rtn == -1)
            {
                MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
                FREE(&snat_key);
                FREE(&snat_value);
                return NAT_COVERT_FAILURE;
            }
            MGW_LOG_INFO(logger, "After snat: session is <%s:%d  %s:%d  %d>", 
                snat_key_sip, ntohs(snat_key->sport), snat_key_dip, ntohs(snat_key->dport), snat_key->proto);
            *vxlan_info = cand_ip_detail->vxlan_info;
            *mrl_ip = cand_ip_detail->mrl_ip;
            FREE(&snat_key);
            FREE(&snat_value);
            return NAT_COVERT_SUCCESS;
        }
        else
        {
            FS_operate(fs_handle->handle, fs_handle->line_ip_detail, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
            MGW_LOG_INFO(handle->logger, "MESA_htable, key not existed, table is %s, key is %s", "cand_ip_detail_htable", snat_value_ip);
            //if session exists in sant but ip is valid. del session from snat, do not del dnat
            rtn = MESA_htable_del(handle->snat_htable, (const unsigned char *)(snat_key), sizeof(struct session), NULL);
            if(rtn < 0 && rtn != MESA_HTABLE_RET_NOT_FOUND)
            {
                MGW_LOG_ERROR(handle->logger, "MESA_htable: Failed at del, rtn is %d, table is %s, key is <%s:%d %s,%d, %d>", rtn, "snat_htable", 
                    snat_key_sip, ntohs(snat_key->sport), snat_key_dip, ntohs(snat_key->dport), snat_key->proto);
                FREE(&snat_key);
                FREE(&snat_value);
                return NAT_COVERT_FAILURE;;
            }
            MGW_LOG_INFO(handle->logger, "MESA_htable: Succeed at del, table is %s, key is <%s:%d %s,%d, %d>", "snat_htable", 
                    snat_key_sip, ntohs(snat_key->sport), snat_key_dip, ntohs(snat_key->dport), snat_key->proto);
        }
    }
    //do snat 
    FS_operate(fs_handle->handle, fs_handle->line_snat, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
    FREE(&snat_value);
    uint32_t sip = snat_key->sip;
    char *user_name = NULL;
    user_name = (char *)MESA_htable_search(handle->ip2user_htable, (const unsigned char *)(&sip), sizeof(sip));
    FS_operate(fs_handle->handle, fs_handle->line_ip2user, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
    if(user_name != NULL)
    {
        FS_operate(fs_handle->handle, fs_handle->line_ip2user, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        snat_value = snat_value_get(handle, _ip_mgr_handle, user_name, snat_key, vxlan_info, mrl_ip);
        if(snat_value == NULL)
        {
            FREE(&snat_key);
            FREE(&snat_value);
            return NAT_COVERT_FAILURE;
        }
        //add sess to snat
        rtn = MESA_htable_add(handle->snat_htable, (const unsigned char *)(snat_key), sizeof(struct session), (const void*)snat_value);
        mgw_utils_inet_ntoa(snat_value->ip, snat_value_ip);
        if(rtn < 0)
        {
            MGW_LOG_ERROR(logger, "MESA_htable: Failed at add to %s, key is <%s:%d %s,%d, %d>, value is <%s, %d>, rtn is %d", "snat_htable",
                snat_key_sip, ntohs(snat_key->sport), snat_key_dip, ntohs(snat_key->dport), snat_key->proto, snat_value_ip, ntohs(snat_value->port), rtn);
            FREE(&snat_key);
            FREE(&snat_value);
            return NAT_COVERT_FAILURE;
        }
        FS_operate(fs_handle->handle, fs_handle->line_snat, fs_handle->cloumn_element_num, FS_OP_ADD, 1);
        MGW_LOG_INFO(logger, "MESA_htable: Succeed at add to %s, key is <%s:%d %s,%d, %d>, value is <%s, %d>", "snat_htable",
                snat_key_sip, ntohs(snat_key->sport), snat_key_dip, ntohs(snat_key->dport), snat_key->proto, snat_value_ip, ntohs(snat_value->port));
        packet_src_replace(buff, len, snat_value);
        rtn = sess_get_from_packet(buff, len, snat_key);
        if(rtn == -1)
        {
            MGW_LOG_ERROR(logger, "Failed at parse packet, len is %d", len);
            FREE(&snat_key);
            return NAT_COVERT_FAILURE;
        }
        mgw_utils_inet_ntoa(snat_key->sip, snat_key_sip);
        mgw_utils_inet_ntoa(snat_key->dip, snat_key_dip);
        MGW_LOG_INFO(logger, "After snat: session is <%s:%d  %s:%d  %d>", 
            snat_key_sip, ntohs(snat_key->sport), snat_key_dip, ntohs(snat_key->dport), snat_key->proto);
        FREE(&snat_key);
        return NAT_COVERT_SUCCESS;
    }
    else
    {
        FS_operate(fs_handle->handle, fs_handle->line_ip2user, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        MGW_LOG_ERROR(logger, "Failed at find user_name, ip %s", snat_key_sip);
        FREE(&snat_key);
        return NAT_COVERT_FAILURE;
    }
    FREE(&snat_key);
    return NAT_COVERT_FAILURE;
}


int nat_dest_convert(struct nat_handle *handle, char *buff, int len)
{
    struct field_stat_handle *fs_handle = handle->fs_handle;
    void *logger = handle->logger;
    //get session
    struct session *dnat_key = ALLOC(struct session, 1);
    int rtn = sess_get_from_packet(buff, len, dnat_key);
    if(rtn == -1)
    {
        MGW_LOG_ERROR(logger, "Failed at nat_dest_convert: parse packet failed, packet len is %d", len);
        FREE(&dnat_key);
        return NAT_COVERT_FAILURE;
    }
    char dnat_key_sip[MGW_SYMBOL_MAX];
    char dnat_key_dip[MGW_SYMBOL_MAX];
    char dnat_value_ip[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(dnat_key->sip, dnat_key_sip);
    mgw_utils_inet_ntoa(dnat_key->dip, dnat_key_dip);
    MGW_LOG_INFO(logger, "Before dnat: session is <%s:%d  %s:%d  %d>", 
        dnat_key_sip, ntohs(dnat_key->sport), dnat_key_dip, ntohs(dnat_key->dport), dnat_key->proto);

    //query dnat，get ip and port
    long dnat_cb_rtn = -1;
    struct ip_port_pair dnat_value;
    MESA_htable_search_cb(handle->dnat_htable, (const unsigned char *)(dnat_key), sizeof(struct session), dnat_htable_query_cb, (void *)(&dnat_value), &dnat_cb_rtn);
    FS_operate(fs_handle->handle, fs_handle->line_dnat, fs_handle->cloumn_queyr_num, FS_OP_ADD, 1);
    if(dnat_cb_rtn == HTABLE_KEY_EXISTED)
    {
        FS_operate(fs_handle->handle, fs_handle->line_dnat, fs_handle->cloumn_cache_hit, FS_OP_ADD, 1);
        mgw_utils_inet_ntoa(dnat_value.ip, dnat_value_ip);
        MGW_LOG_INFO(logger, "MESA_htable: key existed, table is %s， key is <%s:%d %s,%d, %d>, value is <%s, %d>", "dnat_htable",
            dnat_key_sip, ntohs(dnat_key->sport), dnat_key_dip, ntohs(dnat_key->dport), dnat_key->proto, dnat_value_ip, ntohs(dnat_value.port));
        packet_dest_replace(buff, len, &dnat_value);
        rtn = sess_get_from_packet(buff, len, dnat_key);
        if(rtn == -1)
        {
            MGW_LOG_ERROR(logger, "Failed at nat_dest_convert: parse packet failed, packet len is %d", len);
            FREE(&dnat_key);
            return NAT_COVERT_FAILURE;
        }
        mgw_utils_inet_ntoa(dnat_key->sip, dnat_key_sip);
        mgw_utils_inet_ntoa(dnat_key->dip, dnat_key_dip);
        MGW_LOG_INFO(logger, "After dnat: session is <%s:%d  %s:%d  %d>", 
            dnat_key_sip, ntohs(dnat_key->sport), dnat_key_dip, ntohs(dnat_key->dport), dnat_key->proto);
        FREE(&dnat_key);
        return NAT_COVERT_SUCCESS;
    }
    else
    {
        FS_operate(fs_handle->handle, fs_handle->line_dnat, fs_handle->cloumn_cache_miss, FS_OP_ADD, 1);
        MGW_LOG_INFO(logger, "MESA_htable: key not existed, table is %s， key is <%s:%d %s:%d %d>", "dnat_htable",
            dnat_key_sip, ntohs(dnat_key->sport), dnat_key_dip, ntohs(dnat_key->dport), dnat_key->proto);
        FREE(&dnat_key);
        return NAT_COVERT_FAILURE;
    }
}
