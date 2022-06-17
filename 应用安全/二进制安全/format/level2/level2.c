#include <stdio.h>

int main() {
    int flag=5;
    int *p = &flag;
    char a[100];
    scanf("%s",a);
    printf(a);
    if(flag == 2000)
    {
        printf("good\n" );
    }
    return 0;
}