/* gcc -o buf_to_double buf_to_double.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
    size_t i = 0;
    for(i = 0; i < strlen(argv[1]); i += 8) 
    {
        char buf[1024];
        double d;

        /* Convert the value to a double */
        memcpy(&d, argv[1] + i, 8);

        /* Turn the double into a string */
        sprintf(buf, "%.127lg\n", d);
        printf("%s", buf);
    }
    exit(0);
}
