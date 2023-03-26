int get_local_ip(char *dest, const char *interface_name);
int resolve_hostname(const char* hostname, char* dest);
unsigned short check_sum(unsigned short *dgm, int bytes);
