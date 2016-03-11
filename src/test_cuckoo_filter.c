#include <stdio.h>
#include "cuckoo_filter.h"

typedef enum user_options
{    
    NONE = 0,
    CREATE_CUCKOO_FILTER,
    INSERT_KEY_INTO_FILTER,
    DELETE_KEY_FROM_FILTER,
    DELETE_CUCKOO_FILTER
}USER_OPTIONS;


int main()
{
    printf("\n********************Testing Cuckoo Filter Implementation****************\n");
    USER_OPTIONS option = NONE;
    unsigned int quit = 0;

    do
    {
        printf("\nEnter \
\n\t%d --> Create Cuckoo Filter\n \
\t%d --> Insert Element into Filter\n \
\t%d --> Delete Element from Filter\n \
\t%d --> Delete Cuckoo Filter\n \
\t%d --> EXIT\n:",\
                CREATE_CUCKOO_FILTER,\
                INSERT_KEY_INTO_FILTER,\
                DELETE_KEY_FROM_FILTER,\
                DELETE_CUCKOO_FILTER,\
                NONE\
                );
        scanf("%d",&option);

        switch(option)
        {
            case CREATE_CUCKOO_FILTER :
                add_cuckoo_filter("cuckoo_name",10);
                break;

            case INSERT_KEY_INTO_FILTER :
                add_element("cuckoo_name","elem_1");
                break;

            case DELETE_KEY_FROM_FILTER :
                delete_element("cuckoo_name","elem_2");
                break;

            case DELETE_CUCKOO_FILTER :
                delete_cuckoo_filter("cuckoo_name");
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
