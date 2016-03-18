#include <stdio.h>
#include "cuckoo_filter.h"

typedef enum user_options
{    
    NONE = 0,
    CREATE_CUCKOO_FILTER,
    INSERT_KEY_INTO_FILTER,
    CHECK_IF_KEY_EXISTS,
    DELETE_KEY_FROM_FILTER,
    DELETE_CUCKOO_FILTER,
    DISPLAY_FILTERS_LIST,
}USER_OPTIONS;


int main()
{
    printf("\n********************Testing Cuckoo Filter Implementation****************\n");
    USER_OPTIONS option = NONE;
    unsigned int quit = 0;
    char cuck_name[32];
    char key[1024];
    long long unsigned int filter_size = 0;

    do
    {
        printf("\nEnter \
\n\t%d --> Create Cuckoo Filter\n \
\t%d --> Insert Element into Filter\n \
\t%d --> Check for Element in Filter\n \
\t%d --> Delete Element from Filter\n \
\t%d --> Delete Cuckoo Filter\n \
\t%d --> Display Cuckoo Filters List\n \
\t%d --> EXIT\n:",\
                CREATE_CUCKOO_FILTER,\
                INSERT_KEY_INTO_FILTER,\
                CHECK_IF_KEY_EXISTS,\
                DELETE_KEY_FROM_FILTER,\
                DELETE_CUCKOO_FILTER,\
                DISPLAY_FILTERS_LIST,\
                NONE\
                );
        scanf("%d",&option);

        cuck_name[0] ='\0';
        key[0] = '\0';
        filter_size = 0;

        switch(option)
        {
            case CREATE_CUCKOO_FILTER :
                //add_cuckoo_filter("cuckoo_name",10);
                printf("\nEnter the name of cuckoo filter");
                scanf("%s",&cuck_name);
                //gets(cuck_name);
                printf("\nEnter the size (total no of elements to be inserted) into the cuckoo filter.");
                //gets(key);
                scanf("%d",&filter_size );
                add_cuckoo_filter(cuck_name,filter_size );
                break;

            case INSERT_KEY_INTO_FILTER :
                //add_element("cuckoo_name","elem_1");
                printf("\nEnter the name of cuckoo filter");
                scanf("%s",&cuck_name);
                //gets(cuck_name);
                printf("\nEnter the key to be inserted");
                scanf("%s",&key);
                //gets(key);
                add_element(cuck_name,key);
                break;

            case CHECK_IF_KEY_EXISTS :
                //is_member("cuckoo_name",10);
                printf("\nEnter the name of cuckoo filter");
                scanf("%s",&cuck_name);
                //gets(cuck_name);
                printf("\nEnter the key to be checked for its existence");
                scanf("%s",&key);
                //gets(key);
                is_member(cuck_name,key);
                break;

            case DELETE_KEY_FROM_FILTER :
                //delete_element("cuckoo_name","elem_2");
                printf("\nEnter the name of cuckoo filter");
                //gets(cuck_name);
                scanf("%s",&cuck_name);
                printf("\nEnter the key to be deleted");
                scanf("%s",&key);
                //gets(key);
                delete_element(cuck_name,key);
                break;

            case DELETE_CUCKOO_FILTER :
                //delete_cuckoo_filter("cuckoo_name");
                printf("\nEnter the name of cuckoo filter");
                scanf("%s",&cuck_name);
                //gets(cuck_name);
                delete_cuckoo_filter(cuck_name);
                break;

            case DISPLAY_FILTERS_LIST :
                 view_all_filters_details();
                 break;
            case NONE :
                printf("\n Exiting....\n");
                quit = 1;
                break;
            default :
                printf("\nEntered Option is invalid. Try Again\n");
                break;
        }
        option = NONE;

    }while(!quit);

}//end of main function.

