#include <stdio.h>
#include <string.h>

int main(int argc, char * argv[])
{
    char a[1024];
    strcpy(a, argv[1]);
    printf(a);
    printf("\n");
}