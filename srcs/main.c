#include <string.h>
#include <stdio.h>
#include <ft_malloc.h>
#include <parse_arg.h>
#include <unistd.h>
#include <ft_nmap.h>

int main(int argc, char **argv)
{
    nmap_context context;
    // int flags = 0;
    // void *encrypt = NULL;
    // algorithms algorithm = NONE;

    if (argc < 2) return 1;//usage(0);
    
    (void)argv;

    if (geteuid() != 0)
    {
        fprintf(stderr, "This program requires root privileges.\n");
        return 1;
    }

    parse_args(argc, argv, &context);

    return 0;
}