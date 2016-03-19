#include <string.h>
#include "cuckoo_filter.h"
enum
{
	FALSE = 0,
	TRUE = 1
}RETURN_STATUS;

/*
	Function : Testing positive test cases i.e. give it expected value (values in expected range) and check for output.
	Output : Displays positive test case results.
*/
void 
test_positive_test_cases()
{
	printf("\n**************** STARTED AUTOMATIC TESTING. TESTING FOR POSITIVE TEST CASES ***************\n");
	enum RETURN_STATUS expected_return_status = TRUE, actual_return_status = FALSE;
	char filter_name[18];
	char test_case_descr[512];
	unsigned int test_case_count = 1;
	unsigned long long int filter_size = 0;
	char key[1024];

	//Create a new cuckoo filter. check test result.
	remove_all_filters();
	strncpy(filter_name,"valid_cuckoo_name",18);
	filter_name[17] = '\0';
	filter_size = 256;
	sprintf(test_case_descr,"Test Case : %d  --> Create a Valid filter %s with size %d",test_case_count++,filter_name,filter_size);
	printf("\n%s\n",test_case_descr);
	actual_return_status = add_cuckoo_filter(filter_name,filter_size);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Failed to create a valid filter '%s' with valid size '%d'.\"\n",filter_name,filter_size);
	}
	else
	{
		printf("\nTest Case Passed : \"Succesfully created a valid filter '%s' with valid size '%d'.\"\n",filter_name,filter_size);
	}
	


	//Insert element into existing filter.
	remove_all_filters();
	strncpy(filter_name,"valid_cuckoo_name",18);
	filter_name[17] = '\0';
	filter_size = 256;	
	strncpy(key,"123123123123123123123",1024);
	key[1023] = '\0';
	sprintf(test_case_descr,"Test Case : %d  --> Insert valid element %s into an existing filter %s with size %d",test_case_count++,key,filter_name,filter_size);
	printf("\n%s\n",test_case_descr);
	add_cuckoo_filter(filter_name,filter_size);
	actual_return_status = add_element(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Failed to add valid element '%s' to a valid filter '%s' \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Succesfully added valid element '%s' to a valid filter '%s'\"\n",key,filter_name);
	}


	//Check an existing element from existing filter..
	remove_all_filters();
	strncpy(filter_name,"valid_cuckoo_name",18);
	filter_name[17] = '\0';
	filter_size = 256;	
	strncpy(key,"123123123123123123123",1024);
	key[1023] = '\0';
	sprintf(test_case_descr,"Test Case : %d  --> Check for existing element %s in an existing filter %s with size %d",test_case_count++,key,filter_name,filter_size);
	printf("\n%s\n",test_case_descr);
	add_cuckoo_filter(filter_name,filter_size);
	add_element(filter_name,key);
	actual_return_status = is_member(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Failed to check for existing valid element '%s' in a valid existing filter '%s' \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Found a valid existing element '%s' in a valid existing filter '%s'\"\n",key,filter_name);
	}


	//Delete an existing-element in the existing filter.
	remove_all_filters();
	strncpy(filter_name,"valid_cuckoo_name",18);
	filter_name[17] = '\0';
	filter_size = 256;	
	strncpy(key,"123123123123123123123",1024);
	key[1023] = '\0';
	sprintf(test_case_descr,"Test Case : %d  --> Delete an existing element %s from an existing filter %s with size %d",test_case_count++,key,filter_name,filter_size);
	printf("\n%s\n",test_case_descr);
	add_cuckoo_filter(filter_name,filter_size);
	add_element(filter_name,key);
	actual_return_status = delete_element(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Failed to Delete an existing valid element '%s' in a valid existing filter '%s' \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Successfully deleted a valid existing element '%s' in a valid existing filter '%s'\"\n",key,filter_name);
	}
	key[0] = '\0';


	//Delete an existing filter.
	remove_all_filters();
	strncpy(filter_name,"valid_cuckoo_name",18);
	filter_name[17] = '\0';
	filter_size = 256;
	sprintf(test_case_descr,"Test Case : %d  --> Delete an existing filter %s with size %d",test_case_count++,filter_name,filter_size);
	printf("\n%s\n",test_case_descr);
	add_cuckoo_filter(filter_name,filter_size);	
	actual_return_status = delete_cuckoo_filter(filter_name);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Failed to Delete an existing filter '%s' \"\n",filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Successfully deleted a valid existing filter '%s'\"\n",filter_name);
	}	

	printf("\n**************** ENDED TESTING FOR POSITIVE TEST CASES ***************\n");

	return;
}


/*
	Function : Testing negative test cases. i.e testing for invalid set of inputs.
	Output : Displays negative test case results.
*/
void
test_negative_test_cases()
{

	printf("\n**************** STARTED AUTOMATIC TESTING. TESTING FOR NEGATIVE TEST CASES ***************\n");

	enum RETURN_STATUS expected_return_status = FALSE, actual_return_status = TRUE;
	char filter_name[18];
	unsigned long long int filter_size = 0;
	char key[1024];
	unsigned int test_case_count = 1;


	//Create a filter with invalid name.
	//strncpy(filter_name,NULL,18);
	//filter_name[17] = '\0';
	remove_all_filters();
	filter_name = NULL;
	filter_size = 256;
	sprintf(test_case_descr,"Negative Test Case : %d  --> Create filter with Invalid-Name.",test_case_count++);
	printf("\n%s\n",test_case_descr);	
	actual_return_status = add_cuckoo_filter(filter_name,filter_size);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Filter with In-Valid name was created.\"\n");
	}
	else
	{
		printf("\nTest Case Passed : \"Filter with invalid name is not created.\"\n");
	}



	//Create filter with invalid zero(0) size.
	remove_all_filters();
	strncpy(filter_name,"NULL",18);
	filter_name[17] = '\0';
	filter_size = 0;
	sprintf(test_case_descr,"Negative Test Case : %d  --> Create filter by name %s with Invalid-Size %d.",test_case_count++,filter_name,filter_size);
	printf("\n%s\n",test_case_descr);		
	actual_return_status = add_cuckoo_filter(filter_name,filter_size);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Filter with In-Valid size '%d' was created.\"\n",filter_size);
	}
	else
	{
		printf("\nTest Case Passed : \"Filter with invalid size '%d' is not created.\"\n",filter_size);
	}



	//Create existing filter. check test result.
	remove_all_filters();
	strncpy(filter_name,"NULL",18);
	filter_name[17] = '\0';
	filter_size = 1 ;
	sprintf(test_case_descr,"Negative Test Case : %d  --> Re-Create an existing filter with name %s and size %d.",test_case_count++,filter_name,filter_size);
	printf("\n%s\n",test_case_descr);
	//NOTE :- The following lines are not redundant. DO NOT REMOVE FOLLOWING LINES.
	add_cuckoo_filter(filter_name,filter_size);
	actual_return_status = add_cuckoo_filter(filter_name,filter_size);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Filter with Duplicate name '%s' was created.\"\n",filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Filter with Duplicate name '%s' is not created.\"\n",filter_name);
	}


	//Create a filter with size exceeding the limit of 512MB currently.
	remove_all_filters();
	strncpy(filter_name,"NULL",18);
	filter_name[17] = '\0';
	filter_size = 513*1024*1024;
	sprintf(test_case_descr,"Negative Test Case : %d  --> Create a filter by name %s and size %d (Exceeding the limit of 512MB).",test_case_count++,filter_name,filter_size);
	printf("\n%s\n",test_case_descr);
	actual_return_status = add_cuckoo_filter(filter_name,filter_size);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Filter with In-Valid size (Exceeding Maximum Limit of 512MB) '%d' was created.\"\n",filter_size);
	}
	else
	{
		printf("\nTest Case Passed : \"Filter with In-Valid size (Exceeding Maximum Limit of 512MB) '%d' is not created.\"\n",filter_size);
	}


	//Insert element into non-existing filter.
	remove_all_filters();
	strncpy(filter_name,"NON_EXISTING_FILT",18);
	filter_name[17] = '\0';
	strncpy(key,"123123123123123123123",1024);
	key[1023] = '\0';
	sprintf(test_case_descr,"Negative Test Case : %d  --> Insert element %s into non-existing filter %s.",test_case_count++,key,filter_name);
	printf("\n%s\n",test_case_descr);
	actual_return_status = add_element(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"A Valid element '%s' was inserted into non-existing filter '%s'!!!!! \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"A Valid element '%s' was NOT inserted into non-existing filter '%s'.\"\n",key,filter_name);
	}


	//Delete non-existing element from existing filter.
	remove_all_filters();
	strncpy(filter_name,"filter_name",18);
	filter_name[17] = '\0';	
	filter_size = 1;
	strncpy(key,"key",1024);
	key[1023] = '\0';
	sprintf(test_case_descr,"Negative Test Case : %d  --> Delete non-existant element %s from existing filter %s.",test_case_count++,key,filter_name);
	printf("\n%s\n",test_case_descr);
	add_cuckoo_filter(filter_name,filter_size );
	actual_return_status = delete_element(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Deleted a non-existing element '%s' from an existing filter '%s' \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Could not deleted a non-existing element '%s' from existing filter '%s'\"\n",key,filter_name);
	}
	key[0] = '\0';


	//Delete element from non-existing filter.
	remove_all_filters();
	strncpy(filter_name,"__non_existent",18);
	filter_name[17] = '\0';	
	filter_size = 1;
	strncpy(key,"key",1024);
	key[1023] = '\0';
	sprintf(test_case_descr,"Negative Test Case : %d  --> Delete an element %s from non-existing filter %s.",test_case_count++,key,filter_name);
	printf("\n%s\n",test_case_descr);
	actual_return_status = delete_element(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Deleted an element '%s' from non-existing filter '%s' \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Could not delete an element '%s' from non-existing filter '%s'\"\n",key,filter_name);
	}
	key[0] = '\0';	


	//Delete a non-existing filter.
	remove_all_filters();
	strncpy(filter_name,"123__non_existent",18);
	filter_name[17] = '\0';	
	sprintf(test_case_descr,"Negative Test Case : %d  --> Delete non-existing filter %s.",test_case_count++,filter_name);
	printf("\n%s\n",test_case_descr);
	actual_return_status = delete_cuckoo_filter(filter_name);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Deleted non-existing filter '%s' \"\n",filter_name);
	}
	else
	{d
		printf("\nTest Case Passed : \"Could not delete non-existing filter '%s'\"\n",filter_name);
	}	



	//Check for non-existing element in the existing filter.
	remove_all_filters();
	strncpy(filter_name,"new_filter",18);
	filter_name[17] = '\0';	
	filter_size = 1;
	strncpy(key,"unknown_key",1024);
	key[1023] = '\0';
	filter_name[17] = '\0';	
	sprintf(test_case_descr,"Negative Test Case : %d  --> Check non-existing element %s in the existing filter %s.",test_case_count++,key,filter_name);
	printf("\n%s\n",test_case_descr);	
	add_cuckoo_filter(filter_name,filter_size);
	actual_return_status = is_member(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Found non-existing element in  '%s' in a valid existing filter '%s' \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Could not find non-existing element '%s' in a valid existing filter '%s'\"\n",key,filter_name);
	}


	//Check for an element in non-existing filter.
	remove_all_filters();
	strncpy(filter_name,"000_non_exist",18);
	filter_name[17] = '\0';	
	strncpy(key,"unknown_key",1024);
	key[1023] = '\0';
	sprintf(test_case_descr,"Negative Test Case : %d  --> Check for an element %s in the non-existing filter %s.",test_case_count++,key,filter_name);
	printf("\n%s\n",test_case_descr);
	actual_return_status = is_member(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Found an element '%s' in non-existing filter '%s' \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Could not find an element '%s' in non-existing filter '%s'\"\n",key,filter_name);
	}

	printf("\n**************** STARTED AUTOMATIC TESTING. TESTING FOR NEGATIVE TEST CASES ***************\n");	
	
	return;
}