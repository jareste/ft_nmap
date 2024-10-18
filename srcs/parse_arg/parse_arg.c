/***************************/
/*        INCLUDES         */
/***************************/

#include <ft_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <ft_list.h>
#include <errno.h>
#include <ft_nmap.h>
#include <getopt.h>

/***************************/
/*        DEFINES          */
/***************************/

typedef struct {
    const char* name;
    ScanType   scan;
} scan_entry;

static const scan_entry g_scans[] = {
    { "syn", S_SYN },
    { "null", S_NULL },
    { "ack", S_ACK },
    { "fin", S_FIN },
    { "xmas", S_XMAS },
    { "udp", S_UDP },
    { "all", NONE },
    { NULL, NONE }
};

#define get_scan_name(x) g_scans[x].name
#define get_scan_scan(x) g_scans[x].scan

/***************************/
/*        METHODS          */
/***************************/

// static void read_file(const char *filename, char **content)
// {
//     if (access(filename, F_OK) != 0)
//     {
//         fprintf(stderr, "ft_ssl: %s: No such file or directory\n", filename);
//         return;
//     }

//     if (access(filename, R_OK) != 0)
//     {
//         fprintf(stderr, "ft_ssl: %s: Permission denied\n", filename);
//         return;
//     }

//     FILE *file = fopen(filename, "rb");
//     if (!file)
//     {
//         fprintf(stderr, "ft_ssl: %s: %s\n", filename, strerror(errno));
//         /* NEVER HERE */
//         ft_assert(file, "Fatal error: Could not open file.");
//     }

//     fseek(file, 0, SEEK_END);
//     long file_size = ftell(file);
//     fseek(file, 0, SEEK_SET);

//     *content = malloc(file_size + 1);

//     size_t read_size = fread(*content, 1, file_size, file);
//     if (read_size != (size_t)file_size)
//     {
//         perror("Error reading file");
//         free(*content);
//         fclose(file);
//         exit(EXIT_FAILURE);
//     }

//     (*content)[file_size] = '\0';

//     fclose(file);
// }


// static void read_stdin(char **encrypt)
// {
//     size_t buffer_size = 1024;
//     size_t total_size = 0;
//     char *buffer = malloc(buffer_size);
//     int c;

//     while ((c = getchar()) != EOF)
//     {
//         if (total_size + 1 >= buffer_size)
//         {
//             buffer_size *= 2;
//             char *new_buffer = realloc(buffer, buffer_size);
//             buffer = new_buffer;
//         }
//         buffer[total_size++] = (char)c;
//     }

//     buffer[total_size] = '\0';

//     *encrypt = buffer;
// }

/* TODO
    validate format 'XXXX - XXXX'
    validate range pos0 < pos1

*/
void get_ports(char* arg, nmap_context* ctx)
{
    char* number;
    int i = 0;

    /* TODO check to remove spaces '7            -             9' */
    number = strtok(arg, "-");
    if (number == NULL)
    /* TODO ASSERT*/
        printf("I will assert!!!\n");
    for (i = 0; number[i]; i++)
        if (!isdigit(number[i]) || (i > 3)) /*TOOD ASSERT */ printf("I will assert!!!\n");

    ctx->port_range[0] = atoi(number);
    /* todo check max port number and negative */

    number = strtok(NULL, "-");
    if (number == NULL)
    /* TODO ASSERT*/
        printf("I will assert!!!\n");

    for (i = 0; number[i]; i++)
        if (!isdigit(number[i]) || (i > 3)) /*TOOD ASSERT */ printf("I will assert!!!\n");

    ctx->port_range[1] = atoi(number);

    number = strtok(NULL, "-");
    if (number)
    /* TODO ASSERT*/
        printf("I will assert!!!\n");

    printf("port range %d-%d\n", ctx->port_range[0], ctx->port_range[1]);


}


/* this will assert */
void get_scans(char* arg, nmap_context* ctx)
{
    /*
        TODO review
    */
    char* scan = NULL;
    int i = 0;

    scan = strtok(arg, ",");
    while (scan)
    {
        for (i = 0; (get_scan_name(i) != NULL) && (strcmp(scan, get_scan_name(i)) != 0);i++)
            ;
        
        if (get_scan_name(i))
            ctx->scans |= get_scan_scan(i);
        else
            /*TODO assert*/
            printf("'%s' scan type not found or invalid\n", scan);

        scan = strtok(NULL, ",");
    }

    if (ctx->scans == 0)
        /*ASSERT!!!*/
        printf("no scan found!!!\n");
    else
        printf("scan found\n");
}

void parse_args(int argc, char *argv[], nmap_context* ctx)
{
    int opt;

    /* TODO review*/
    memset(ctx, 0, sizeof(nmap_context));

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"ports", required_argument, 0, 'p'},
        {"ip", required_argument, 0, 'i'},
        {"file", required_argument, 0, 'f'},
        {"speedup", required_argument, 0, 0},
        {"scan", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "?hp:i:f:s:", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case '?':
            case 'h':
                // print_usage(*algorithm, EXIT_SUCCESS);
                exit(0);
            case 'p': /* port */
                /* TODO set the port range, if it's set twice assert */
                get_ports(optarg, ctx);
                // *flags |= P_FLAG;
                break;
            case 'i': /* ip */
                /* TODO add to scan list */
                // *flags |= Q_FLAG;
                break;
            case 'r': /* file */
                // *flags |= R_FLAG;
                break;
            case 's': /* scan */
                if (optarg)
                {
                    get_scans(optarg, ctx);
                }
                else
                {
                    fprintf(stderr, "Option -s contains garbage as argument: %s.\n", optarg);
                    fprintf(stderr, "This will become fatal error in the future.\n");
                }
                break;
            case 0: /* speedup */
                if (strcmp("speedup", long_options[optind-1].name) == 0)
                {
                    printf("Speedup option with value %s\n", optarg);
                }
                break;
            default:
                // print_usage(*algorithm, EXIT_FAILURE);
                exit(1);
        }
    }

    // stdin_buffer = NULL;
    // for (int i = optind+1; i < argc; i++)
    // {
    //     if (!can_read_file(*algorithm))
    //     {
    //         fprintf(stderr, "ft_ssl: Error: %s does not accept files as input.\n", get_scan_name(*algorithm));
    //         print_usage(*algorithm, EXIT_FAILURE);
    //         exit(1);
    //     }

    //     read_file(argv[i], &stdin_buffer);
    //     if (stdin_buffer)
    //     {
    //         list_add_last(list, stdin_buffer, argv[i], TYPE_FILE);
    //         free(stdin_buffer);
    //         stdin_buffer = NULL;
    //     }
    // }

    // if (optind >= argc)
    // {
    //     fprintf(stderr, "Expected argument after options\n");
    //     print_usage(*algorithm, EXIT_FAILURE);
    //     exit(1);
    // }

    // /* chekc if something to read from stdin. */
    // if (!isatty(fileno(stdin)) && (*flags & P_FLAG || *list == NULL)) {
    //     read_stdin(&stdin_buffer);
    //     list_add_last(list, stdin_buffer, (*flags & P_FLAG) ? stdin_buffer : "stdin", (*flags & P_FLAG) ? TYPE_STDIN_NORMAL : TYPE_STDIN);
    //     free(stdin_buffer);
    // }

    // /* no input recieved, so we read from stdin. */
    // if ((*list == NULL))
    // {
    //     read_stdin(&stdin_buffer);
    //     list_add_last(list, stdin_buffer, (*flags & P_FLAG) ? stdin_buffer : "stdin", (*flags & P_FLAG) ? TYPE_STDIN_NORMAL : TYPE_STDIN);
    //     free(stdin_buffer);
    // }
}