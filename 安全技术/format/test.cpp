#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
 
int main(int argc, char * argv[])
{
    char a[1024];
    memset(a, '\0', 1024);
    read(0, a, 1024);
    printf(a);
    return 0;
}
