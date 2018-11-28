#include "mgw_utils.h"

static int __wrapper_MESA_htable_set_opt(MESA_htable_handle table, enum MESA_htable_opt opt_type, unsigned value, void *logger, const char *symbol)
{
	int ret = MESA_htable_set_opt(table, opt_type, &value, (int)(sizeof(value)));
	if(unlikely(ret != 0))
    {
		MGW_LOG_ERROR(logger, "Failed at MESA_htable_set_opt, htable is %s, opt_type is %d", symbol, opt_type);
        exit(EXIT_FAILURE);
    }
	return ret;
}

static int __wrapper_MESA_htable_set_opt(MESA_htable_handle table, enum MESA_htable_opt opt_type, void * val, size_t len, void *logger, const char *symbol)
{
	int ret = MESA_htable_set_opt(table, opt_type, val, (int)len);
	if(unlikely(ret != 0))
    {
		MGW_LOG_ERROR(logger, "Failed at MESA_htable_set_opt, htable is %s, opt_type is %d", symbol, opt_type);
        exit(EXIT_FAILURE);
    }
	return ret;
}

MESA_htable_handle mgw_utils_create_htable(const char *profile, const char *section, void *free_data_cb, void *expire_notify_cb, void *logger)
{
    int mho_screen_print_ctrl;
    int mho_thread_safe;
    int mho_mutex_num;
    int mho_hash_slot_size;
	int mho_hash_max_element_num;
    int mho_expire_time;
	char mho_eliminate_type[MGW_SYMBOL_MAX];
	MESA_load_profile_int_def(profile, section, "mho_screen_print_ctrl", &mho_screen_print_ctrl, 1);
    MESA_load_profile_int_def(profile, section, "mho_thread_safe", &mho_thread_safe, 0);
    MESA_load_profile_int_def(profile, section, "mho_mutex_num", &mho_mutex_num, 12);
    MESA_load_profile_int_def(profile, section, "mho_hash_slot_size", &mho_hash_slot_size, 1234);
	MESA_load_profile_int_def(profile, section, "mho_hash_max_element_num", &mho_hash_max_element_num, 12345);
    MESA_load_profile_int_def(profile, section, "mho_expire_time", &mho_expire_time, 3600);
	MESA_load_profile_string_def(profile, section, "mho_eliminate_type", mho_eliminate_type, sizeof(mho_eliminate_type), "FIFO");
	MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n mho_screen_print_ctrl: %d\n mho_thread_safe: %d\n mho_mutex_num: %d\n"
		"mho_hash_slot_size: %d\n mho_hash_max_element_num: %d\n mho_expire_time: %d\n mho_eliminate_type: %s\n", section,
		mho_screen_print_ctrl, mho_thread_safe, mho_mutex_num, mho_hash_slot_size, mho_hash_max_element_num, mho_expire_time, mho_eliminate_type);
	MESA_htable_handle htable = MESA_htable_born();
	__wrapper_MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, mho_screen_print_ctrl, logger, section);
	__wrapper_MESA_htable_set_opt(htable, MHO_THREAD_SAFE, mho_thread_safe, logger, section);
	__wrapper_MESA_htable_set_opt(htable, MHO_MUTEX_NUM, mho_mutex_num, logger, section);
	__wrapper_MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, mho_hash_slot_size, logger, section);
	__wrapper_MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, mho_hash_max_element_num, logger, section);
	__wrapper_MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, mho_expire_time, logger, section);
	if(strncmp(mho_eliminate_type, "LRU", MGW_SYMBOL_MAX) == 0)
	{
		__wrapper_MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, HASH_ELIMINATE_ALGO_LRU, logger, section);
	}
	else
	{
		__wrapper_MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, HASH_ELIMINATE_ALGO_FIFO, logger, section);
	}

	 __wrapper_MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,
	    (void *)free_data_cb, sizeof(free_data_cb), logger, section);
	//ret = __wrapper_MESA_htable_set_opt(htable, MHO_CBFUN_DATA_EXPIRE_NOTIFY,
	//	(void *)key_keeper_verify_cb);
	int ret = MESA_htable_mature(htable);
	if(unlikely(ret != 0))
    {
		MGW_LOG_ERROR(logger, "Failed at MESA_htable_mature, htable is %s", section);
        exit(EXIT_FAILURE);
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
 