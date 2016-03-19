#!/usr/bin/bash
echo "************* COMPILING THE CUCKOO FILTER LIBRARY SOURCE FILE  (gcc -c -g -DDEBUG cuckoo_filter.c)   ***********"
gcc -c -g -DDEBUG cuckoo_filter.c

echo "************* CREATING CUCKOO FILTER LIBRARY cuckoo_filter.a (ar rvs cuckoo_filter.a cuckoo_filter.o)  ************"
ar rvs cuckoo_filter.a cuckoo_filter.o

echo "***********  COMPILING THE TEST CUCKOO FILTER SOURCE FILE (gcc -g test_cuckoo_filter.c cuckoo_filter.a -lm -o cuckoo_start.out) ***************"
gcc -g test_cuckoo_filter.c cuckoo_filter.a -lm -o cuckoo_start.out


echo "************** END OF COMPILATION ****************"
echo " Check Manually if any error are generated during compilation"
