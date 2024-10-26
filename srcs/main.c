#include <string.h>
#include <stdio.h>
#include <ft_malloc.h>
#include <parse_arg.h>
#include <unistd.h>
#include <ft_nmap.h>
#include <nmap_api.h>
#include <error_codes.h>

int main(int argc, char **argv)
{
    nmap_context context;

    (void)argv;

    /* this goes first so i give the user no data about the program itself. s*/
    if (geteuid() != 0)
    {
        fprintf(stderr, "This program requires root privileges.\n");
        return FAILURE;
    }

    if (argc < 2) FT_NMAP_USAGE(FAILURE);


    parse_args(argc, argv, &context);

    nmap_main(&context);

    destroy_context(&context);

    return 0;
}