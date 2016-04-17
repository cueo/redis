//#include <stdio.h>
//#include <string.h>
//#include <stdlib.h>
#include "server.h"
#include "crc64.h"

#include <assert.h>
#include <math.h>

#define __MAX_SIZE_OF_CUCKOO_FILTER 512*1024*1024//4294967295 bits

#define M_BIT_ARRAY_LENGTH_TYPE u_int32_t
#define M_BIT_ARRAY_ID_TYPE M_BIT_ARRAY_LENGTH_TYPE
#define FINGER_PRINT_TYPE unsigned char

/*A bucket can hold a  max of 8 entries/elements (elements conatin 1 finger-print(8-bit) each.*/
#define __MAX_ELEMS_IN_A_BUCKET 8

#define __MAX_CUCKOO_KICKS 100

/*
    The internal structure that holds the information about all the cuckoo filters.
*/
struct __cuckoo_filter
{
  
   //The internal m_bit_array that contains the finger-print of the given keys. This is divided into multiple groups(buckets) containing max 8 elements or entries.
   FINGER_PRINT_TYPE * __m_bit_finger_print_array;
 
   //The total no.. of logical buckets into which the actual finger-print array is divided into. The index of these buckets should start from '1'. This is the assumption.
    M_BIT_ARRAY_ID_TYPE __total_no_of_buckets;

// TO DO :- ADD PLACEHOLDER FOR STORING THE ACTUAL VALUES, FOR TESTING THE PERFORMANCE AND FALSE POSITIVE PROBABILITIES.

    M_BIT_ARRAY_LENGTH_TYPE __m_bit_arr_len_in_bytes;//length of the m_bit_array.

};


/*List of functions */

FINGER_PRINT_TYPE __get_pearson_8_bit_finger_print(unsigned const char *key);
FINGER_PRINT_TYPE __get_finger_print(const char* key);

M_BIT_ARRAY_LENGTH_TYPE __murmur3_32_bit_hash(const char *key);
M_BIT_ARRAY_LENGTH_TYPE __get_hash_1(const char* key);
M_BIT_ARRAY_LENGTH_TYPE __get_hash_2(FINGER_PRINT_TYPE finger_print, M_BIT_ARRAY_LENGTH_TYPE hash1);

short __insert_element(struct __cuckoo_filter* filter,const char* key);
short __check_or_delete_element(struct __cuckoo_filter* filter, const char* key, short __should_delete_element);
short __is_element_present_in_bucket(FINGER_PRINT_TYPE finger_print,M_BIT_ARRAY_LENGTH_TYPE bucket_no,const struct __cuckoo_filter* const my_filter,  M_BIT_ARRAY_LENGTH_TYPE * indexWhereElemIsPresent);
short __remove_element(struct __cuckoo_filter* filter, const char* key);
short __remove_specified_filter(struct __cuckoo_filter* temp);

M_BIT_ARRAY_LENGTH_TYPE __getBucketNumber(const struct __cuckoo_filter * const ckFilter, M_BIT_ARRAY_LENGTH_TYPE elem_insertion_index);
M_BIT_ARRAY_LENGTH_TYPE __getFirstIndexOfTheBucket(const struct __cuckoo_filter * const ckFilter, M_BIT_ARRAY_LENGTH_TYPE bucket_no);
M_BIT_ARRAY_LENGTH_TYPE __getLastIndexOfTheBucket(const struct __cuckoo_filter * const ckFilter, M_BIT_ARRAY_LENGTH_TYPE bucket_no);
short __is_bucket_empty(const struct __cuckoo_filter *my_filter, const M_BIT_ARRAY_LENGTH_TYPE index,M_BIT_ARRAY_LENGTH_TYPE * indexOfEmptyElement);

short add_element(struct __cuckoo_filter* filter,const char* key);
short is_member(struct __cuckoo_filter* filter, const char* key);
short delete_element(struct __cuckoo_filter* filter, const char* key);



/*
    Function : Checks if an element is present in the given bucket.
    Input : finger_print - The finger-print that is checked for its presence in the bucket of the filter.
            bucket - The bucket within which the element is checked for its presence.
    Output : 1 - if the element is present in the bucket.
             0 - if the element is not present in the bucket.
*/
short 
__is_element_present_in_bucket(FINGER_PRINT_TYPE finger_print,M_BIT_ARRAY_LENGTH_TYPE bucket_no,const struct __cuckoo_filter* const my_filter, M_BIT_ARRAY_LENGTH_TYPE * indexWhereElemIsPresent)
{
    //PRINT_TRACE("Checking if element is present in the specified bucket.");
    assert(my_filter->__m_bit_finger_print_array);
    * indexWhereElemIsPresent = 0;
   
    //get starting index of bucket in the given filter...
    M_BIT_ARRAY_LENGTH_TYPE firstIndex = __getFirstIndexOfTheBucket(my_filter, bucket_no);
    
    M_BIT_ARRAY_LENGTH_TYPE lastIndex = __getLastIndexOfTheBucket(my_filter, bucket_no);
    //get ending index of bucket in the given filter.

    M_BIT_ARRAY_LENGTH_TYPE iterIndex = firstIndex;

    //For each of entries b/w and including first and second index, check if the element contains finger-print.
    for(iterIndex = firstIndex; iterIndex <= lastIndex; iterIndex ++)
    {
        //TO DO :- since currently the finger-print is 8 bit, we can compare using single equality operator,
        //This comparison logic should be changed if finger-print is not 8-bit.
        if(finger_print == my_filter->__m_bit_finger_print_array[iterIndex])
        {
//#if PRINT_DEBUG
            //printf("\n The filter named '%s' has an empty free in the bucket number '%d'\n",my_filter->__name,bucket_no);
//#endif
            *indexWhereElemIsPresent = iterIndex;
            
            //sprintf(temp_char_arr,"The bucket contains the fingerprint %c",finger_print);
            //PRINT_DEBUG(temp_char_arr);
            return 1;//Bucket entry is empty
        }
    }

    //sprintf(temp_char_arr,"The bucket doesn't contain the fingerprint %c",finger_print);
    //PRINT_DEBUG(temp_char_arr);
    return 0;
}


/*
    Function :
    Returns the bucket number into which the element is to be inserted. A bucket can contain n elements.
    Input : elem_insertion_index - The element index where the element is to be stored.
    Output : bucket-number - Bucket to which this element belongs. The item can be stored in any of the elements/places which are contained in the bucket. 
*/
M_BIT_ARRAY_LENGTH_TYPE
__getBucketNumber(const struct __cuckoo_filter* const ckFilter, M_BIT_ARRAY_LENGTH_TYPE elem_insertion_index)
{
//#if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Getting Bucket Number\n");
//#endif
    //PRINT_TRACE("Getting Bucket Number");
    
    //The size of each bucket, i.e. the number of elements that a single bucket can contain, is pre-defined.
    //The index will start from '0', but for calculation we need it to be started from 1, hence we will consider index+1.
   M_BIT_ARRAY_LENGTH_TYPE  bucketNo = ceil((elem_insertion_index + 1)/(float)(__MAX_ELEMS_IN_A_BUCKET));
   //sprintf(temp_char_arr,"bucket_no : %d",bucketNo);
   //PRINT_DEBUG(temp_char_arr);
   assert(bucketNo >= 1 && bucketNo <= ckFilter->__total_no_of_buckets);
   return bucketNo;
}


/*
    Function : Determines the first index of the given bucket.
    Input : bucket_no - The bucket number for which the first index of the bucket is to be determined.
    Output : The first index of the bucket.
*/
M_BIT_ARRAY_LENGTH_TYPE 
__getFirstIndexOfTheBucket(const struct __cuckoo_filter * const ckFilter , M_BIT_ARRAY_LENGTH_TYPE bucket_no)
{
//#if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Getting First Index\n");
//#endif
    //PRINT_TRACE("Getting First Index");
    assert(bucket_no >= 1);
    M_BIT_ARRAY_LENGTH_TYPE firstIndex = 0;
    firstIndex = (__MAX_ELEMS_IN_A_BUCKET * (bucket_no - 1));
    assert(firstIndex >= 0 && firstIndex <= ckFilter->__m_bit_arr_len_in_bytes - 1);
    //sprintf(temp_char_arr,"first index of bucket %d is %d",bucket_no,firstIndex);
    //PRINT_DEBUG(temp_char_arr);
    return firstIndex;
}


/*
    Function : Determines the last index of the given bucket.
    Input : bucket_no - The bucket number for which the last index of the bucket is to be determined.
    Output : The last index of the bucket.
*/
M_BIT_ARRAY_LENGTH_TYPE 
__getLastIndexOfTheBucket(const struct __cuckoo_filter * const ckFilter, M_BIT_ARRAY_LENGTH_TYPE bucket_no)
{
// #if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Getting Last Index\n");
//#endif   assert(bucket_no >= 1);
    //PRINT_TRACE("Getting Last Index");
    M_BIT_ARRAY_LENGTH_TYPE lastIndex = 0;
    lastIndex = (__MAX_ELEMS_IN_A_BUCKET * bucket_no) - 1;
    //assert(lastIndex >= 0 && lastIndex <= ckFilter->__m_bit_arr_len_in_bytes - 1);//The second condition is not true always.
    assert(lastIndex >= 0);
    //sprintf(temp_char_arr,"last index of bucket %d is %d",bucket_no,lastIndex);
    //PRINT_DEBUG(temp_char_arr);
    return lastIndex;
}


/*
    Re-using pearsons algorithm.
    Function returns 8-bit finger-print for a given key.
    Input :- key -- key for which the finger print is generated.
    Output :- 8-bit finger-print for the given key.
    Pearsons_hash is much faster and non-cryptographic hash, also provides a perfect hash function.
*/
static const FINGER_PRINT_TYPE __EMPTY_ELEMENT = 0;

FINGER_PRINT_TYPE 
__get_pearson_8_bit_finger_print(unsigned const char *key)
{
//#if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Calculating Finger-Print\n");
//#endif
 //PRINT_TRACE("Calculating Finger-Print");
 unsigned int index=0;

 //TO DO:- fix the hack.
 //The 71st entry in the above table is set to 255 (removing the earlier value(0), because if value is 0, then the memory is considered to be empty.
 
 
 static const FINGER_PRINT_TYPE __pearson_substitution_table[256] = 
 {
    // 256 values 0-255 in any (random) order suffices
    98,  6, 85,150, 36, 23,112,164,135,207,169,  5, 26, 64,165,219, //  1

    61, 20, 68, 89,130, 63, 52,102, 24,229,132,245, 80,216,195,115, //  2

    90,168,156,203,177,120,  2,190,188,  7,100,185,174,243,162, 10, //  3

    237, 18,253,225,  8,208,172,244,255,126,101, 79,145,235,228,121, //  4

    123,251, 67,250,161,  107, 255, 97,241,111,181, 82,249, 33, 69, 55, //  5

    59,153, 29,  9,213,167, 84, 93, 30, 46, 94, 75,151,114, 73,222, //  6

    197, 96,210, 45, 16,227,248,202, 51,152,252,125, 81,206,215,186, //  7

    39,158,178,187,131,136,  1, 49, 50, 17,141, 91, 47,129, 60, 99, //  8

    154, 35, 86,171,105, 34, 38,200,147, 58, 77,118,173,246, 76,254, //  9

    133,232,196,144,198,124, 53,  4,108, 74,223,234,134,230,157,139, // 10

    189,205,199,128,176, 19,211,236,127,192,231, 70,233, 88,146, 44, // 11

    183,201, 22, 83, 13,214,116,109,159, 32, 95,226,140,220, 57, 12, // 12

    221, 31,209,182,143, 92,149,184,148, 62,113, 65, 37, 27,106,166, // 13

    3, 14,204, 72, 21, 41, 56, 66, 28,193, 40,217, 25, 54,179,117, // 14

    238, 87,240,155,180,170,242,212,191,163, 78,218,137,194,175,110, // 15

    43,119,224, 71,122,142, 42,160,104, 48,247,103, 15, 11,138,239  // 16

 };

FINGER_PRINT_TYPE finger_print = __pearson_substitution_table[key[0] % 256];
 
 unsigned int len = strlen(key);//May get memory out of range error..

 for (index = 1; index < len; index++) 
 {
    finger_print = __pearson_substitution_table[finger_print ^ key[index]];
 }

 //sprintf(temp_char_arr,"Finger Print for the given key %s is %c",key,finger_print);
 //PRINT_DEBUG(temp_char_arr);
 return finger_print;
}


/*
    Function that provides 32-bit hash value for the given key.
    Input :- key -- key for which the hash value is returned.
    Output :- 32-bit hash value for the given key.
    NOTE : This is faster and provides 32-bit hash value. Non-cryptographic algorithm.
*/

#define ROT32(x, y) ((x << y) | (x >> (32 - y))) // avoid effort

M_BIT_ARRAY_LENGTH_TYPE 
__murmur3_32_bit_hash(const char* key)
{
// #if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Calculating Hash Code\n");
//#endif
    //PRINT_TRACE("Calculating Hash Code");
    static const u_int32_t c1 = 0xcc9e2d51;
    static const u_int32_t c2 = 0x1b873593;
    static const u_int32_t r1 = 15;
    static const u_int32_t r2 = 13;
    static const u_int32_t m = 5;
    static const u_int32_t n = 0xe6546b64;
    static const u_int32_t seed = 0x00000003;//This was actually the argument to this function.
    M_BIT_ARRAY_LENGTH_TYPE hash = seed;
    u_int32_t len = strlen(key);
    const int nblocks = len / 4;
    const u_int32_t *blocks = (const u_int32_t *) key;
    int i;
    u_int32_t k;

    for (i = 0; i < nblocks; i++)
    {
        k = blocks[i];
        k *= c1;
        k = ROT32(k, r1);
        k *= c2;
        hash ^= k;
        hash = ROT32(hash, r2) * m + n;
    }

    const u_int8_t *tail = (const u_int8_t *) (key + nblocks * 4);
    u_int32_t k1 = 0;
    switch (len & 3) 
    {
      case 3:
           k1 ^= tail[2] << 16;
      case 2:
           k1 ^= tail[1] << 8;
      case 1:
           k1 ^= tail[0];
           k1 *= c1;
           k1 = ROT32(k1, r1);
           k1 *= c2;
           hash ^= k1;
    }
    
    hash ^= len;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    //sprintf(temp_char_arr,"Hash for the given key %s is %u",key,hash);
    //PRINT_DEBUG(temp_char_arr);
    return hash;
}


/*
    Functions to check if the bucket entry(that holds the fingerprint) is empty.
    Input : filter -- the cuckoo filter whose bucket is to be checked.
            entry-index -- the entry index that is to be checked for emptyness.
    Output : Returns 1 if bucket is empty.
             Returns 0 if bucket is not empty.
*/
short 
__is_bucket_empty(const struct  __cuckoo_filter *my_filter, const M_BIT_ARRAY_LENGTH_TYPE bucket_no, M_BIT_ARRAY_LENGTH_TYPE * indexOfEmptyElement)
{
// #if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Checking for Empty Bucket\n");
//#endif
    //PRINT_TRACE("Checking for Empty Bucket");
    assert(my_filter->__m_bit_finger_print_array);
   
    //get starting index of bucket in the given filter...
    M_BIT_ARRAY_LENGTH_TYPE firstIndex = __getFirstIndexOfTheBucket(my_filter, bucket_no);
    
    M_BIT_ARRAY_LENGTH_TYPE lastIndex = __getLastIndexOfTheBucket(my_filter, bucket_no);
    //get ending index of bucket in the given filter.

    M_BIT_ARRAY_LENGTH_TYPE iterIndex = firstIndex;

    //For each of entries b/w and including first and second index, check if there's any empty element.
    for(iterIndex = firstIndex; iterIndex <= lastIndex; iterIndex ++)
    {
        if(__EMPTY_ELEMENT == my_filter->__m_bit_finger_print_array[iterIndex])
        {
            //set insertion index to this index value..
            *indexOfEmptyElement = iterIndex;
//#if PRINT_DEBUG
            //printf("\n The filter named '%s' has an empty free in the bucket number '%d'\n",my_filter->__name,bucket_no);
//#endif
            //sprintf(temp_char_arr,"The filter named %s has an empty space at the bucket number %d",my_filter->__name,bucket_no);
            //PRINT_DEBUG(temp_char_arr);
            return 1;//Bucket entry is empty
        }
    }
//#if //PRINT_DEBUG
    //printf("\n The filter named '%s' has no free space in the bucket number '%d'\n", my_filter->__name,bucket_no);
//#endif
    //sprintf(temp_char_arr,"The filter named '%s' has no free space in the bucket number '%d'",my_filter->__name,bucket_no);
    //PRINT_DEBUG(temp_char_arr);
    *indexOfEmptyElement = 0;
    return 0;//Bucket entry is not empty
}


/*
    NOTE :- This API is not exposed to outside world..
    Input : key - Integer for which finger-print is generated.
    Output : Finger-Print for given key..
*/
//M_BIT_ARRAY_CONTENT_TYPE __get_finger_print(int key)
FINGER_PRINT_TYPE 
__get_finger_print(const char* key)
{
// #if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Getting Finger-Print\n");
//#endif //User pearsons hashing technique for generating the 8-bit fingerprint for given key.
  //PRINT_TRACE("Getting Finger-Print");
  if(NULL == key)
    return 0;
  return __get_pearson_8_bit_finger_print(key);
}//end of get_finger_print function


/*
    Function Returns the first hash value for given key.
    Input : key -- The key for which hash value is returned.
    Output :
        The first hash value which is the index to the m_bit_array.
*/
M_BIT_ARRAY_LENGTH_TYPE 
__get_hash_1(const char* key)
{
//#if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Getting First Hash\n");
//#endif
    //PRINT_TRACE("Getting First Hash");
    if(NULL == key)
        return 0;
    return __murmur3_32_bit_hash(key);
}


/*
    Function returns the second hash value for the given key and first hash value.
    Input : finger_print -- The key for which first hash value is to be returned.
            hash1 -- The first hash value using which the second hash value is calculated.
    Output :
        The second hash value which is also the index to the m_bit_array.
*/
M_BIT_ARRAY_LENGTH_TYPE 
__get_hash_2(FINGER_PRINT_TYPE finger_print, M_BIT_ARRAY_LENGTH_TYPE hash1)
{
// #if PRINT_TRACE
    //printf("\n [PRINT_TRACE] Getting Second Hash\n");
//#endif
     //PRINT_TRACE("Getting Second Hash");
    //return hash1 XOR __get_hash_1(finger_print)
    return (hash1 ^ __get_hash_1(&finger_print));
}




/*
    Function to insert values into cuckoo filter.
    Input : key -- The item to be inserted into the cuckoo filter.
            name -- The name of the cuckoo filter.
    Output :
        Returns 0 -- insertion is successful
        Returns 1 -- insertion fails.
*/
short 
__insert_element(struct __cuckoo_filter* filter,const char* key)
{
    //PRINT_TRACE("Adding Element to Filter");
    if(NULL == key)
        return 0;

    if(NULL == filter)
        return 0;
    
    assert(filter->__m_bit_finger_print_array);

    //get finger print for given key..
    FINGER_PRINT_TYPE finger_print = __get_finger_print(key);
 
    M_BIT_ARRAY_LENGTH_TYPE hash1 = __get_hash_1(key);
    //This hash1 must be < finger_print array length. This hash1 should be converted into the bucket number in which the finger print is to be stored.
    hash1 = hash1 % filter->__m_bit_arr_len_in_bytes;
    M_BIT_ARRAY_LENGTH_TYPE bucket_1 = __getBucketNumber(filter,hash1);
 
    M_BIT_ARRAY_LENGTH_TYPE emptyLocationInBucket = 0;

    //Insert into the first bucket, to empty location.
    if(__is_bucket_empty(filter,bucket_1,&emptyLocationInBucket))
    {
        //Fill this entry with the fingerprint.
        filter->__m_bit_finger_print_array[emptyLocationInBucket] = finger_print;
//#if PRINT_DEBUG
        //printf("\n Inserted element into index : %d : of first bucket",emptyLocationInBucket);
//#endif
        //sprintf(temp_char_arr,"Inserted element '%s' into index : %d of the first bucket",key,emptyLocationInBucket);
        //PRINT_DEBUG(temp_char_arr);
        return 1;
    }

    //Else try inserting into second bucket..

    //NOTE :- There is a possibility of getting both hashes in single bucket.. TO DO :- Make this not to happen.
    //M_BIT_ARRAY_LENGTH_TYPE hash2 = __get_hash_2(finger_print,hash1);
    M_BIT_ARRAY_LENGTH_TYPE hash2 = __get_hash_2(finger_print,bucket_1);

    //This hash2 must be < finger_print array length.
    hash2 = hash2 % filter->__m_bit_arr_len_in_bytes;

    M_BIT_ARRAY_LENGTH_TYPE bucket_2 = __getBucketNumber(filter,hash2);

    if(__is_bucket_empty(filter,bucket_2,&emptyLocationInBucket))
    {
        //Fill this entry with the fingerprint.
        filter->__m_bit_finger_print_array[emptyLocationInBucket] = finger_print;
//#if PRINT_DEBUG
        //printf("\n Inserted element into index : %d : of second bucket",emptyLocationInBucket);
//#endif
        //sprintf(temp_char_arr,"Inserted element '%s' into index : %d of the second bucket",key,emptyLocationInBucket);
        //PRINT_DEBUG(temp_char_arr);
        return 1;
    }

    //If both the buckets are not empty, then start finding empty element location.
    else
    {
        //The bucket entries were not empty. Find empty space and fill it with fingerprint.
//#if PRINT_DEBUG
        //printf("\n No buckets were empty, starting to cuckoo the elements to find the new empty position\n");
//#endif
        //sprintf(temp_char_arr,"No buckets were empty, Finding empty locations by starting the process of Cuckoo-Kicks");
        //PRINT_DEBUG(temp_char_arr);
        
        M_BIT_ARRAY_LENGTH_TYPE * randomlyChosenBucket = NULL;
        unsigned int cuckoo_kick_count = 0;
        M_BIT_ARRAY_LENGTH_TYPE randomlySelectedIndex = 0;
        FINGER_PRINT_TYPE tempFingerPrint = 0;
        unsigned short randomNumber = 0;
        //M_BIT_ARRAY_LENGTH_TYPE firstIndex = 0,lastIndex = 0;

        //Choose a random bucket first...
        randomNumber = rand()%2;
        randomlyChosenBucket = randomNumber ? &bucket_2 : &bucket_1 ;//This is either 1 or 2.

        //assert(randomlyChosenBucket >= 1 && randomlyChosenBucket <= 2);
        //firstIndex = __getFirstIndexOfTheBucket(filter,*(randomlyChosenBucket));
        //lastIndex = __getLastIndexOfTheBucket(filter,*(randomlyChosenBucket));

        for(cuckoo_kick_count = 1; cuckoo_kick_count <= __MAX_CUCKOO_KICKS; cuckoo_kick_count++)
        {
            //select a random element from the bucket and swap it with current cuckoo filter.
            randomNumber = rand()%__MAX_ELEMS_IN_A_BUCKET;
            //sprintf(temp_char_arr,"Randomly Chosen entry in the selected bucket is : %d",randomNumber);
            //PRINT_DEBUG(temp_char_arr);

            randomlySelectedIndex = (randomNumber)+(__getFirstIndexOfTheBucket(filter,*(randomlyChosenBucket)));
            //sprintf(temp_char_arr,"The equivalent index of randomly chosen entry %d is %d",randomNumber,randomlySelectedIndex);
            //PRINT_DEBUG(temp_char_arr);

            //swap finger-print and selected_finger-print.
            tempFingerPrint = filter->__m_bit_finger_print_array[randomlySelectedIndex];
            filter->__m_bit_finger_print_array[randomlySelectedIndex] = finger_print;
            finger_print = tempFingerPrint;

            //Relocate the swapped element to its another equivalent bucket., So get the equivalent bucket.
           //if(randomlyChosenBucket 
            hash2 = __get_hash_2(finger_print,*(randomlyChosenBucket));
            //This hash2 must be < finger_print array length.
            hash2 = hash2 % filter->__m_bit_arr_len_in_bytes;
            bucket_2 = __getBucketNumber(filter,hash2);
            randomlyChosenBucket = &bucket_2;

            if(__is_bucket_empty(filter,bucket_2,&emptyLocationInBucket))
            {
                //Fill this entry with the fingerprint.
                filter->__m_bit_finger_print_array[emptyLocationInBucket] = finger_print;
                //sprintf(temp_char_arr,"Inserted element '%s' into index : %d of the bucket during CUCKOO KICK NO - %d",key,emptyLocationInBucket,cuckoo_kick_count);
                //PRINT_DEBUG(temp_char_arr);
                return 1;
            } 

        }//end of for..
        //sprintf(temp_char_arr,"Maximum Cuckoo Kicks EXCEEDED. Filter is Considered as FULL.");
        //PRINT_DEBUG(temp_char_arr);
        return 0;
    }//end of else...

    assert(0 && "Control should not reach here ");
    return 0;//This should not be reached.
}


/*
    Function to check or delete if a key is present in the cuckoo filter set.
    Input : name -- cuckoo filter in which the key is to be checked.
             key -- The key to be checked for.
    Output : 
        Returns 0 -- if the key is not found.
        Returns 1 -- if the key is found in the cuckoo filter 'name'
*/
short 
__check_or_delete_element(struct __cuckoo_filter* filter , const char* key, short __should_delete_element)
{
    //PRINT_TRACE("Checking Element Existence.");

     if( NULL == key)
        return 0;

    if(NULL == filter)
        return 0;
    
    assert(filter->__m_bit_finger_print_array);

    //get finger print for given key..
    FINGER_PRINT_TYPE finger_print = __get_finger_print(key);
 
    M_BIT_ARRAY_LENGTH_TYPE hash1 = __get_hash_1(key);
    //This hash1 must be < finger_print array length. This hash1 should be converted into the bucket number in which the finger print is to be stored.
    hash1 = hash1 % filter->__m_bit_arr_len_in_bytes;
    M_BIT_ARRAY_LENGTH_TYPE bucket_1 = __getBucketNumber(filter,hash1);
    M_BIT_ARRAY_LENGTH_TYPE locWhereElemIsPresent = 0;

    //Check if element is present in first bucket.
    if(__is_element_present_in_bucket(finger_print,bucket_1,filter,&locWhereElemIsPresent))
    {
        //sprintf(temp_char_arr,"Element %s found at bucket number: %d at index %d",key,bucket_1,locWhereElemIsPresent);
        //PRINT_DEBUG(temp_char_arr);
        if(__should_delete_element)
        {
            //sprintf(temp_char_arr,"Deleting the element %s from index %d.",key,locWhereElemIsPresent);
            //PRINT_DEBUG(temp_char_arr);
            filter->__m_bit_finger_print_array[(locWhereElemIsPresent)] = __EMPTY_ELEMENT;
        }
        return 1;
    }

    //Else check the element presence in second bucket.

    //M_BIT_ARRAY_LENGTH_TYPE hash2 = __get_hash_2(finger_print,hash1);
    M_BIT_ARRAY_LENGTH_TYPE hash2 = __get_hash_2(finger_print,bucket_1);

    //This hash2 must be < finger_print array length.
    hash2 = hash2 % filter->__m_bit_arr_len_in_bytes;

    M_BIT_ARRAY_LENGTH_TYPE bucket_2 = __getBucketNumber(filter,hash2);

    //Check element presence in bucket 2.
    if(__is_element_present_in_bucket(finger_print,bucket_2,filter,&locWhereElemIsPresent))
    {
        //sprintf(temp_char_arr,"Element '%s' found at bucket number: %d at index %d",key,bucket_2,locWhereElemIsPresent);
        //PRINT_DEBUG(temp_char_arr);
        if(__should_delete_element)
        {
            //sprintf(temp_char_arr,"Deleting the element %s from index %d.\",key,locWhereElemIsPresent");
            //PRINT_DEBUG(temp_char_arr);
            filter->__m_bit_finger_print_array[(locWhereElemIsPresent)] = __EMPTY_ELEMENT;        
        }
        return 1;
    }

    //sprintf(temp_char_arr,"Element '%s' NOT FOUND in the filter",key);
    //PRINT_DEBUG(temp_char_arr);

    if(__should_delete_element)
    {
        //sprintf(temp_char_arr,"Cannot Delete the key %s",key);
        //PRINT_DEBUG(temp_char_arr);
        //DO Nothing.. or else reply error from Redis.
    }
    return 0; 
}


/*
    Function to delete the key from cuckoo filter.
    Input : key -- The key to be deleted from the cuckoo filter.
            name -- The name of cuckoo filter from which the key is to be deleted.
    Output : 
            Returns 0 -- if key deletion fails.
            Returns 1 -- if the key is deleted successfully.
*/
short
__remove_element(struct __cuckoo_filter* filter , const char* key)
{
    //PRINT_TRACE("\"Removing the element\"");
    if(NULL == key)
        return 0;    
    return __check_or_delete_element(filter,key,1);
}



/*
    Function : Removes the specified filter from the list.
    Input : filter - The pointer to the filter that is to be removed.
    Output : 1 - If the filter was removed successfully.
             0 - Failed to remove the specified filter.
*/
short 
__remove_specified_filter(struct __cuckoo_filter* temp)
{
    //PRINT_TRACE("Removing Specified Filter");

    if(NULL == temp)
    {
        //PRINT_DEBUG("Invalid filter specified");
        return 0;
    }


    //Finished deleting the filter from list.
    //Start de-allocating the memory for that filter.
    M_BIT_ARRAY_LENGTH_TYPE i = 0;

    
    free(temp->__m_bit_finger_print_array);
    temp->__m_bit_finger_print_array = NULL;

    //Now free the memory allocated to the filter itself.
    free(temp);
    temp = NULL;

    return 1;
}


/*
    Function to insert values into cuckoo filter.
    Input : key -- The item to be inserted into the cuckoo filter.
            filter -- The cuckoo filter.
    Output :
        Returns 0 -- insertion is successful
        Returns 1 -- insertion fails.
*/
//unsigned short insert_element(const char* name, const int key)
short 
add_element(struct __cuckoo_filter* filter,const char* key)
{
    //PRINT_TRACE("Adding element to cuckoo filter");
    if(NULL == key)
        return 0;
    return __insert_element(filter,key);    
}



/*
    Function to check if a key is present in the cuckoo filter set.
    Input : filter -- cuckoo filter in which the key is to be checked.
             key -- The key to be checked for.
    Output : 
        Returns 0 -- if the key is not found.
        Returns 1 -- if the key is found in the cuckoo filter 'name'
*/
//unsigned short is_member(const char* name, const int key)
short 
is_member(struct __cuckoo_filter* filter, const char* key)
{
    //PRINT_TRACE("Checking if element is member of filter.");
    if( NULL == key)
        return 0;

    return __check_or_delete_element(filter,key,0);
}


/*
    Function to delete the key from cuckoo filter.
    Input : key -- The key to be deleted from the cuckoo filter.
            filter -- The cuckoo filter from which the key is to be deleted.
    Output : 
            Returns 0 -- if key deletion fails.
            Returns 1 -- if the key is deleted successfully.
*/
short 
delete_element(struct __cuckoo_filter* filter, const char* key)
{
    //PRINT_TRACE("Deleting element from filter");
    if(NULL == key)
        return 0;

    return __remove_element(filter,key); 
}



static inline size_t buflen(uint64_t m)
{
    return sizeof(struct __cuckoo_filter) + m;
}

//Redis Command Implementation..
void 
cuckoocreateCommand(client *c)
{
    robj *o;
    long m;
    size_t byte;
    struct __cuckoo_filter* new_filter;

    if (C_OK != getLongFromObjectOrReply(c, c->argv[2],&m,
                    "cuckoo filter bits is not an integer or out of range"))
        return;
    if (m <= 0) {
        addReplyError(c,"cuckoo filter bits is not an positive integer");
        return;
    }


    byte = buflen(m);
    if (byte > __MAX_SIZE_OF_CUCKOO_FILTER) {
        addReplyError(c,"cuckoo filter size exceeds maximum allowed size (512MB)");
        return;
    }

    o = lookupKeyWrite(c->db,c->argv[1]);
    if (o == NULL) {
        o = createObject(OBJ_STRING,sdsnewlen(NULL,byte));
        dbAdd(c->db,c->argv[1],o);
    } else {
        addReplyError(c,"filter object is already exist");
        return;
    }
    
    new_filter = (struct __cuckoo_filter*) o->ptr;
    new_filter->__m_bit_arr_len_in_bytes = m;//because 1 byte per item.
    new_filter->__total_no_of_buckets = ceil(m / (float)__MAX_ELEMS_IN_A_BUCKET);
    //new_filter->__m_bit_finger_print_array = NULL;//Don't reset to NULL, memory already allocated.
    new_filter->__m_bit_finger_print_array = (FINGER_PRINT_TYPE *)(new_filter + 1);
    
    signalModifiedKey(c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_STRING,"bfcreate",c->argv[1],c->db->id);
    server.dirty++;
    addReply(c,shared.ok);
}




void cuckooinsertelementCommand(client *c) {
    robj *o;
    char *err = "invalid filter format", *buf;
    size_t len, byte;
    int i;
    struct __cuckoo_filter *filter;

    if ((o = lookupKeyWriteOrReply(c,c->argv[1],shared.nokeyerr)) == NULL
         || (checkType(c,o,OBJ_STRING))) return;
    if (o->encoding != OBJ_ENCODING_RAW) {
        addReplyError(c,err);
        return;
    }

    len = sdslen(o->ptr);
    if (len < sizeof(struct __cuckoo_filter)) {
        addReplyError(c,err);
        return;
    }

    filter = (struct __cuckoo_filter*)o->ptr;
    //byte = buflen(filter->m);
    byte = buflen(filter->__m_bit_finger_print_array);
    buf = (char*)(filter + 1);
    if (len != byte) {
        addReplyError(c,err);
        return;
    }


    addReplyMultiBulkLen(c,c->argc-2);
    for (i = 2; i < c->argc; i++) {
        if(__insert_element(filter,c->argv[i]))
            addReply(c,shared.cone);
        else
            addReply(c,shared.czero);
    }

    signalModifiedKey(c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_STRING,"bfadd",c->argv[1],c->db->id);
    server.dirty++;
    
    addReply(c,shared.ok);
}


void cuckooremoveelementCommand(client *c) {
    robj *o;
    char *err = "invalid filter format", *buf;
    size_t len, byte;
    int i;
    struct __cuckoo_filter *filter;

    if ((o = lookupKeyWriteOrReply(c,c->argv[1],shared.nokeyerr)) == NULL
         || (checkType(c,o,OBJ_STRING))) return;
    if (o->encoding != OBJ_ENCODING_RAW) {
        addReplyError(c,err);
        return;
    }

    len = sdslen(o->ptr);
    if (len < sizeof(struct __cuckoo_filter)) {
        addReplyError(c,err);
        return;
    }

    filter = (struct __cuckoo_filter*)o->ptr;
    //byte = buflen(filter->m);
    byte = buflen(filter->__m_bit_finger_print_array);
    buf = (char*)(filter + 1);
    if (len != byte) {
        addReplyError(c,err);
        return;
    }

    addReplyMultiBulkLen(c,c->argc-2);
    for (i = 2; i < c->argc; i++) {
        if(delete_element(filter,c->argv[i]))
            addReply(c,shared.cone);
        else
            addReply(c,shared.czero);
    }

    signalModifiedKey(c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_STRING,"bfadd",c->argv[1],c->db->id);
    server.dirty++;
    
    addReply(c,shared.ok);
}


void cuckoocheckelementCommand(client *c) {
    robj *o;
    char *err = "invalid filter format", *buf;
    size_t len, byte;
    int i;
    struct __cuckoo_filter *filter;

    if ((o = lookupKeyWriteOrReply(c,c->argv[1],shared.nokeyerr)) == NULL
         || (checkType(c,o,OBJ_STRING))) return;
    if (o->encoding != OBJ_ENCODING_RAW) {
        addReplyError(c,err);
        return;
    }

    len = sdslen(o->ptr);
    if (len < sizeof(struct __cuckoo_filter)) {
        addReplyError(c,err);
        return;
    }

    filter = (struct __cuckoo_filter*)o->ptr;
    //byte = buflen(filter->m);
    byte = buflen(filter->__m_bit_finger_print_array);
    buf = (char*)(filter + 1);
    if (len != byte) {
        addReplyError(c,err);
        return;
    }

    addReplyMultiBulkLen(c,c->argc-2);
    for (i = 2; i < c->argc; i++) {
        if(is_member(filter,c->argv[i]))
            addReply(c,shared.cone);
        else
            addReply(c,shared.czero);
    }

    signalModifiedKey(c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_STRING,"bfadd",c->argv[1],c->db->id);
    server.dirty++;
    
    addReply(c,shared.ok);
}