
#include "mgw_utils.h"
#include <maxminddb.h>

struct ip_locator_handle
{
    MMDB_s mmdb;
    void *logger;
    char level[MGW_SYMBOL_MAX];  
    char inside_domain[MGW_SYMBOL_MAX];
};

void ip_locator_destroy(struct ip_locator_handle *handle)
{
    MMDB_close(&(handle->mmdb));
    FREE(&handle);
}

struct ip_locator_handle * ip_locator_init(const char *profile, void *logger)
{
    const char *section = "ip_locator";
    struct ip_locator_handle *handle = ALLOC(struct ip_locator_handle, 1);
    MESA_load_profile_string_def(profile, section, "level", handle->level, MGW_SYMBOL_MAX, "COUNTRY");
    MESA_load_profile_string_def(profile, section, "inside_domain", handle->inside_domain, MGW_SYMBOL_MAX, "China");
    MGW_LOG_INFO(logger, "MESA_prof_load, [%s]:\n level: %s\n inside_domain: %s", 
            "ip_locator", handle->level, handle->inside_domain);
    handle->logger = logger;
    const char *path = "/opt/mgw/ip_locator/db/v4/all_ip_info_v4.mmdb";
    int rtn = MMDB_open(path, MMDB_MODE_MMAP, &(handle->mmdb)); 
    if(rtn != MMDB_SUCCESS)
    {
        MGW_LOG_ERROR(logger, "Failed at MMDB_open, rtn is %d", rtn);
        return NULL;
    }
    return handle;
}

int ip_locator_is_inside(struct ip_locator_handle *handle, uint32_t ip, bool *is_inside)
{
    char ip_str[MGW_SYMBOL_MAX];
    mgw_utils_inet_ntoa(ip, ip_str);
    int gai_error, mmdb_error;  
    void *logger = handle->logger;
    MMDB_lookup_result_s result = MMDB_lookup_string(&(handle->mmdb), ip_str, &gai_error, &mmdb_error);
    if (gai_error != 0) 
    {       
        MGW_LOG_ERROR(logger, "Error from getaddrinfo for %s - %s!", ip_str, gai_strerror(gai_error));
        return -1;
    }   
    if (mmdb_error != MMDB_SUCCESS) 
    {
        MGW_LOG_ERROR(logger, "Got an error from libmaxminddb: %s!", MMDB_strerror(mmdb_error));
        return -1;
    }  
    MMDB_entry_data_s entry_data;
    if (result.found_entry) 
    {      
        int status = MMDB_get_value(&result.entry, &entry_data, handle->level, NULL);
        if (MMDB_SUCCESS != status)     
        {
            MGW_LOG_ERROR(logger, "Got an error looking up the entry data - %s!", MMDB_strerror(status));
            return -1;
        }      
        if (entry_data.has_data)        
        {           
            char location[MGW_SYMBOL_MAX];
            memcpy(location, entry_data.utf8_string, entry_data.data_size);
            location[entry_data.data_size] = '\0';
            MGW_LOG_INFO(logger, "ip_locator: ip is %s, location is %s", ip_str, location);
            if(memcmp(handle->inside_domain, entry_data.utf8_string, entry_data.data_size) == 0)
            {
                *is_inside = true;
            }
            else
            {
                *is_inside = false;
            }
            return 0;
        }
    }
    return -1;
}