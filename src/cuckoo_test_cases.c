#include <string.h>
#include "cuckoo_filter.h"


/*
	Function : Testing positive test cases i.e. give it expected value (values in expected range) and check for output.
	Output : Displays positive test case results.
*/
void 
test_positive_test_cases()
{
	short expected_return_status = 0, actual_return_status = 0;
	char filter_name[18];
	unsigned long long int filter_size = 0;
	char key[1024];

	//Create a new cuckoo filter. check test result.
	strncpy(filter_name,"valid_cuckoo_name",18);
	filter_name[17] = '\0';
	filter_size = 256;
	expected_return_status = 1;
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
	strncpy(key,"123123123123123123123",1024);
	key[1023] = '\0';
	expected_return_status = 1;
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
	expected_return_status = 1;
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
	expected_return_status = 1;
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
	expected_return_status = 1;
	actual_return_status = delete_cuckoo_filter(filter_name);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Failed to Delete an existing filter '%s' \"\n",filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Successfully deleted a valid existing filter '%s'\"\n",filter_name);
	}	


	return;
}


/*
	Function : Testing negative test cases. i.e testing for invalid set of inputs.
	Output : Displays negative test case results.
*/
void
test_negative_test_cases()
{

	short expected_return_status = 0, actual_return_status = 0;
	char filter_name[18];
	unsigned long long int filter_size = 0;
	char key[1024];


	//Create a filter with invalid name.
	//strncpy(filter_name,NULL,18);
	//filter_name[17] = '\0';
	filter_name = NULL;
	filter_size = 256;
	expected_return_status = 0;
	actual_return_status = add_cuckoo_filter(filter_name,filter_size);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Filter with In-Valid name '%s' was created.\"\n",filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Filter with invalid name '%s' is not created.\"\n",filter_name);
	}



	//Create filter with invalid zero(0) size.
	strncpy(filter_name,"NULL",18);
	filter_name[17] = '\0';
	filter_size = 0;
	expected_return_status = 0;
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
	strncpy(filter_name,"NULL",18);
	filter_name[17] = '\0';
	filter_size = 1 ;
	expected_return_status = 0;
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
	strncpy(filter_name,"NULL",18);
	filter_name[17] = '\0';
	filter_size = 513*1024*1024;
	expected_return_status = 0;
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
	strncpy(filter_name,"NON_EXISTING_FILT",18)
	filter_name[17] = '\0';
	strncpy(key,"123123123123123123123",1024);
	key[1023] = '\0';
	expected_return_status = 0;
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
	strncpy(filter_name,"filter_name",18)
	filter_name[17] = '\0';	
	filter_size = 1;
	strncpy(key,"key",1024);
	key[1023] = '\0';
	expected_return_status = 0;
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
	strncpy(filter_name,"__non_existent",18)
	filter_name[17] = '\0';	
	filter_size = 1;
	strncpy(key,"key",1024);
	key[1023] = '\0';
	expected_return_status = 0;
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
	strncpy(filter_name,"123__non_existent",18);
	filter_name[17] = '\0';	
	expected_return_status = 0;
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
	strncpy(filter_name,"new_filter",18);
	filter_name[17] = '\0';	
	filter_size = 1;
	strncpy(key,"unknown_key",1024);
	key[1023] = '\0';
	expected_return_status = 0;
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
	strncpy(filter_name,"000_non_exist",18);
	filter_name[17] = '\0';	
	strncpy(key,"unknown_key",1024);
	key[1023] = '\0';
	expected_return_status = 0;
	actual_return_status = is_member(filter_name,key);
	if(actual_return_status != expected_return_status)
	{
		printf("\nTest Case Failed : \"Found an element '%s' in non-existing filter '%s' \"\n",key,filter_name);
	}
	else
	{
		printf("\nTest Case Passed : \"Could not find an element '%s' in non-existing filter '%s'\"\n",key,filter_name);
	}

	to do call remove_all_filters() function in-between..
	return;
}