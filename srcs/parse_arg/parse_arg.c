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
#include <error_codes.h>

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

void parse_file(const char *file_path, nmap_context* ctx)
{
    FILE *file = fopen(file_path, "r");
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    target_t*   target = NULL;

    if (file == NULL)
    {
        perror("Error opening file");
        return;
    }

    fseek(file, 0, SEEK_END);
    if (ftell(file) == 0)
    {
        printf("The file is empty.\n");
        fclose(file);
        return;
    }
    rewind(file);

    while ((read = getline(&line, &len, file)) != -1)
    {
        if ((read == 1) && (line[0] == '\n'))
            continue;
        if (line[read - 1] == '\n')
            line[read - 1] = '\0';
        target = malloc(sizeof(target_t));
        target->address = strdup(line);
        FT_LIST_ADD_LAST(&ctx->dst, target);
    }

    free(line);
    fclose(file);
}

void get_ports(char *arg, nmap_context *ctx)
{
    char*   number;
    int     i;
    int     port1;
    int     port2;
    
    number = strtok(arg, "-");
    ft_assert(number, "ft_nmap: Fatal error: Invalid port range format. Format 'X-X'\n");
    
    for (i = 0; number[i]; i++)
        ft_assert(isdigit(number[i]), "ft_nmap: Fatal error: Invalid port range format 'X-X'. Non-digit characters found.\n");

    port1 = atoi(number);

    ft_assert(port1 > 0 && port1 <= 1024, "ft_nmap: Fatal error: Invalid port range. Ports must be between 1 and 1024.\n");

    number = strtok(NULL, "-");
    ft_assert(number, "ft_nmap: Fatal error: Invalid port range format. Missing second port. Format 'X-X'\n");
    
    for (i = 0; number[i]; i++)
        ft_assert(isdigit(number[i]), "ft_nmap: Fatal error: Invalid port range format. Non-digit characters found.\n");
        
    port2 = atoi(number);

    ft_assert(port2 > 0 && port2 <= 1024, "ft_nmap: Fatal error: Invalid port range. Ports must be between 1 and 1024.\n");
    ft_assert(port1 < port2, "ft_nmap: Fatal error: Invalid port range. The first port must be less than the second port.\n");

    ctx->port_range[0] = port1;
    ctx->port_range[1] = port2;

    printf("Valid port range: %d-%d\n", ctx->port_range[0], ctx->port_range[1]);
}

void get_scans(char* arg, nmap_context* ctx)
{
    /* should never happen */
    ft_assert(arg, "ft_nmap: Fatal error: argument is NULL.\n");
    ft_assert(ctx, "ft_nmap: Fatal error: context is NULL.\n");

    char* scan = NULL;
    int i = 0;

    scan = strtok(arg, ",");
    while (scan)
    {
        for (i = 0; (get_scan_name(i) != NULL) && (strcmp(scan, get_scan_name(i)) != 0); i++)
            ;

        if (get_scan_name(i))
            ctx->scans |= get_scan_scan(i);
        else
            ft_assert(0, "ft_nmap: Fatal error: scan type not found or invalid.\n");

        scan = strtok(NULL, ",");
    }

    if (ctx->scans == 0)
        ft_assert(0, "ft_nmap: Fatal error: no scan found, please provide a valid scan type.\n");
}

void parse_args(int argc, char *argv[], nmap_context* ctx)
{
    int         opt;
    target_t*   target = NULL;

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
                FT_NMAP_USAGE(EXIT_SUCCESS);
                // print_usage(*algorithm, EXIT_SUCCESS);
                exit(0);
            case 'p': /* port */
                ctx->flags |= FLAG_PORTS;
                get_ports(optarg, ctx);
                break;
            case 'i': /* ip */
                printf("IP: %s\n", optarg);
                ft_assert(optarg, "ft_nmap: Fatal error: Invalid target IP.\n");
                target = malloc(sizeof(target_t));
                target->address = strdup(optarg);
                FT_LIST_ADD_LAST(&ctx->dst, target);
                break;
            case 'f': /* file */
                parse_file(optarg, ctx);
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
                ctx->flags |= FLAG_SPEED;
                ft_assert(optarg, "ft_nmap: Fatal error: Invalid speedup value. Must be a number.\n");
                
                for (int k = 0; optarg[k]; k++)
                    ft_assert(isdigit(optarg[k]), "ft_nmap: Fatal error: Invalid speedup value. Must be a number.\n");
                
                ctx->speedup = atoi(optarg);
                
                break;
            default:
                FT_NMAP_USAGE(EXIT_SUCCESS);
        }
    }

    if (ctx->dst == NULL) {fprintf(stderr, "ft_ssl: No scan dst provided.\n"); FT_NMAP_USAGE(FAILURE);}

    target_t *tmp = ctx->dst;
    while (tmp)
    {
        printf("Target: %s\n", tmp->address);
        tmp = FT_LIST_GET_NEXT(&ctx->dst, tmp);
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