#include "mgw_utils.h"

static int __wrapper_MESA_htable_set_opt(MESA_htable_handle table, enum MESA_htable_opt opt_type, unsigned value, void *logger, const char *symbol)
{
	int ret = MESA_htable_set_opt(table, opt_type, &value, (int)(sizeof(value)));
	if(unlikely(ret != 0))
    {
        exit(EXIT_FAILURE);
        MGW_LOG_ERROR(logger, "Failed at MESA_htable_set_opt, htable is %s, opt_type is %d", symbol, opt_type);
    }
	return ret;
}

static int __wrapper_MESA_htable_set_opt(MESA_htable_handle table, enum MESA_htable_opt opt_type, void * val, size_t len, void *logger, const char *symbol)
{
	int ret = MESA_htable_set_opt(table, opt_type, val, (int)len);
	if(unlikely(ret != 0))
    {
        exit(EXIT_FAILURE);
        MGW_LOG_ERROR(logger, "Failed at MESA_htable_set_opt, htable is %s, opt_type is %d", symbol, opt_type);
    }
	return ret;
}

MESA_htable_handle mgw_utils_create_htable(const char *symbol, struct htable_opts *_htable_opts, void *free_data_cb, void *expire_notify_cb)
{
	int ret = 0;
    void *logger = _htable_opts->logger;
	MESA_htable_handle htable = MESA_htable_born();
	__wrapper_MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, _htable_opts->mho_screen_print_ctrl, logger, symbol);
	__wrapper_MESA_htable_set_opt(htable, MHO_THREAD_SAFE, _htable_opts->mho_thread_safe, logger, symbol);
	__wrapper_MESA_htable_set_opt(htable, MHO_MUTEX_NUM, _htable_opts->mho_mutex_num, logger, symbol);
	__wrapper_MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, _htable_opts->mho_hash_slot_size, logger, symbol);
	__wrapper_MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, _htable_opts->mho_hash_slot_size * 4, logger, symbol);
	__wrapper_MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, _htable_opts->mho_expire_time, logger, symbol);
	__wrapper_MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, HASH_ELIMINATE_ALGO_FIFO, logger, symbol);
	ret = __wrapper_MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,
	    (void *)free_data_cb, sizeof(free_data_cb), logger, symbol);
	//ret = __wrapper_MESA_htable_set_opt(htable, MHO_CBFUN_DATA_EXPIRE_NOTIFY,
	//	(void *)key_keeper_verify_cb);
	ret = MESA_htable_mature(htable);
	if(unlikely(ret != 0))
    {
        exit(EXIT_FAILURE);
        MGW_LOG_ERROR(logger, "Failed at MESA_htable_mature, htable is %s", symbol);
    }
	return htable;
}


unsigned int mgw_utils_get_random(unsigned int num)
{
    return (rand() % num);
}

int mgw_utils_inet_ntoa(uint32_t ip, char *dest)
 {
	 const char *_ip = inet_ntoa(*(struct in_addr *)&ip);
	 strncpy(dest, _ip, MGW_SYMBOL_MAX);
	 return 0;
 }

uint16_t mgw_utils_ip_checksum(const void *buff, size_t hdr_len)
{
	unsigned long sum = 0;
	const uint16_t *ip1; 
	ip1 = (const uint16_t *)buff;
	while (hdr_len > 1)
	{
		sum += *ip1++;
		if (sum & 0x80000000)
		{
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		hdr_len -= 2;
	}
	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16); 
	}
	return(~sum);
}

 uint16_t mgw_utils_tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
 {
	const uint16_t *buf = (const uint16_t *)buff;
	uint16_t *ip_src=(uint16_t *)&src_addr, *ip_dst=(uint16_t *)&dest_addr;
	uint32_t sum;
	size_t length=len;
	// Calculate the sum                                            //
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
		{
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd          //
		sum += *((uint8_t *)buf); 
	}
	// Add the pseudo-header                                        //
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length); 
	// Add the carries                                              //
	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	// Return the one's complement of sum                           //
	return ( (uint16_t)(~sum)  );
}

uint16_t mgw_utils_udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
 {
	const uint16_t *buf = (u_int16_t *)buff;
	uint16_t *ip_src=(u_int16_t *)&src_addr, *ip_dst=(u_int16_t *)&dest_addr;
	uint32_t sum;
	size_t length=len;
	// Calculate the sum                                            //
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
		{
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd          //
		sum += *((uint8_t *)buf);
	}

	// Add the pseudo-header                                        //
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_UDP);
	sum += htons(length);

	// Add the carries                                              //
	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	// Return the one's complement of sum                           //
	return ( (uint16_t)(~sum)  );
 }
 