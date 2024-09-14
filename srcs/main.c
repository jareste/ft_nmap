#include <string.h>
#include <stdio.h>
#include <ft_malloc.h>
#include <parse_arg.h>

int main(int argc, char **argv)
{
    int flags = 0;
    // void *encrypt = NULL;
    // algorithms algorithm = NONE;

    // if (argc < 2) usage(0);

    parse_args(argc, argv, &flags, &encrypt, &algorithm);

    return 0;
}