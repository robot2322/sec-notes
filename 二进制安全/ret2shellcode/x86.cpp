#include <stdio.h>
#include <string.h>
void SayHello(char* name)
{
    char tmpName[60];
    strcpy(tmpName, name);
    printf("Hello %s\n", tmpName);
}
int main(int argc, char** argv)
{
    if (argc != 2) {
        printf("Usage: hello <name>.\n");
        return 1;
    }
    SayHello(argv[1]);
    return 0;
}