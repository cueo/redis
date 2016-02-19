#include <stdio.h>
#include "cuckoo_filter.h"

enum
{    
    NONE = 0,
    CREATE_CUCKOO_FILTER,
    INSERT_KEY_INTO_FILTER,
    DELETE_KEY_FROM_FILTER
}user_options;


int main()
{
    printf("\nTesting Cuckoo Filter Implementation\n");
    user_options option = NONE;
    unsigned int quit = 0;

    do
    {
        printf("\nEnter \t%d --> Create Cuckoo Filter\n \
                \t%d --> Insert Element into Filter\n \
                \t%d --> Delete Element from Filter\n \
                ",CREATE_CUCKOO_FILTER,INSERT_KEY_INTO_FILTER,DELETE_KEY_FROM_FILTER);
        scanf("%d",&option);

        switch(option)
        {
            case CREATE_CUCKOO_FILTER :
                break;

            case INSERT_KEY_INTO_FILTER :
                break;

            case DELETE_KEY_FROM_FILTER :
                break;

            case NONE :
                printf("\n Exiting....\n");
                quit = 1;
                break;
            default :
                printf("\nEntered Option is invalid. Try Again\n");
                break;
        }

    }while(!quit);

}//end of main function.
