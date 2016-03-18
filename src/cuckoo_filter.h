/*
  API's Visible to external sources for working with cuckoo filters.
*/

short add_cuckoo_filter(const char* name,const long long unsigned int m_bit_length_in_bits);

short add_element(const char* name, const char* key);

short is_member(const char* name, const char* key);

short delete_element(const char* name, const char* key);

short delete_cuckoo_filter(const char* name);

void view_all_filters_details();

void remove_all_filters();
