struct ip_locator_handle;

struct ip_locator_handle * ip_locator_init(const char *profile, void *logger);
int ip_locator_is_inside(struct ip_locator_handle *handle, uint32_t ip, bool *is_inside);
void ip_locator_destroy(struct ip_locator_handle *handle);