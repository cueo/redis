/*
  API's Visible to external sources for working with cuckoo filters.
*/

short add_cuckoo_filter(const char* name,const unsigned int m_bit_length_in_bits);

short insert_element(const char* name, const char* key);

short delete_element(const char* name, const char* key);

short is_member(const char* name, const char* key);

short remove_cuckoo_filter(const char* name);

