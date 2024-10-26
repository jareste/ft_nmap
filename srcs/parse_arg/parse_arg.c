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
    int        flag;
} scan_entry;

static const scan_entry g_scans[] = {
    { "syn", S_SYN, FLAG_SYN },
    { "null", S_NULL, FLAG_NULL },
    { "ack", S_ACK, FLAG_ACK },
    { "fin", S_FIN, FLAG_FIN },
    { "xmas", S_XMAS, FLAG_XMAS },
    { "udp", S_UDP, FLAG_UDP },
    { "all", NONE, FLAG_SYN | FLAG_NULL | FLAG_FIN | FLAG_XMAS | FLAG_ACK | FLAG_UDP },
    { NULL, NONE, 0 }
};

#define get_scan_name(x) g_scans[x].name
#define get_scan_scan(x) g_scans[x].scan
#define get_scan_flag(x) g_scans[x].flag

/***************************/
/*        METHODS          */
/***************************/

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
        for (i = 0; (get_scan_name(i) != NULL) && (strcasecmp(scan, get_scan_name(i)) != 0); i++)
            ;

        if (get_scan_name(i))
            ctx->scans |= get_scan_flag(i);
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

    ctx->port_range[0] = 1;
    ctx->port_range[1] = 1024;

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"ports", required_argument, 0, 'p'},
        {"ip", required_argument, 0, 'i'},
        {"file", required_argument, 0, 'f'},
        {"speedup", required_argument, 0, 0},
        {"scan", required_argument, 0, 's'},
        {"os", no_argument, 0, 'O'},
        {"fast", no_argument, 0, 'F'},
        {"max-rate", required_argument, 0, 2},
        {"min-rate", required_argument, 0, 3},
        {"open", no_argument, 0, 1},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "?hp:i:f:s:", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case '?':
            case 'h':
                FT_NMAP_USAGE(EXIT_SUCCESS);
                exit(0);
            case 'p': /* port */
                ctx->flags |= FLAG_PORTS;
                get_ports(optarg, ctx);
                break;
            case 'i': /* ip */
                ft_assert(optarg, "ft_nmap: Fatal error: Invalid target IP.\n");
                target = malloc(sizeof(target_t));
                target->address = strdup(optarg);
                FT_LIST_ADD_LAST(&ctx->dst, target);
                break;
            case 'f': /* file */
                parse_file(optarg, ctx);
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
            case 'O': /* os */
                ctx->flags |= FLAG_OS;
                break;
            case 'F': /* fast */
                ctx->flags |= FLAG_FAST;
                break;
            case 1: /* open */
                ctx->flags |= FLAG_OPEN;
                break;
            case 0: /* speedup */
                ctx->flags |= FLAG_SPEED;
                ft_assert(optarg, "ft_nmap: Fatal error: Invalid speedup value. Must be a number.\n");
                
                for (int k = 0; optarg[k]; k++)
                    ft_assert(isdigit(optarg[k]), "ft_nmap: Fatal error: Invalid speedup value. Must be a number.\n");
                
                ctx->speedup = atoi(optarg);
                if (ctx->speedup < 1)
                {
                    fprintf(stderr, "ft_nmap: Warning: Speedup value is less than 1. Setting to 1.\n");
                    ctx->speedup = 1;
                }
                break;
            case 2: /* max-rate */
                ctx->flags |= FLAG_MXRATE;
                if (optarg)
                {
                    ctx->max_rate = strtoull(optarg, NULL, 10);
                    if (ctx->max_rate < 1)
                    {
                        ft_assert(0, "ft_nmap: Fatal error: Max rate value is less than 1.\n");
                    }
                }
                else
                {
                    ft_assert(0, "ft_nmap: Fatal error: Max rate value is missing.\n");
                }
                break;
            case 3: /* min-rate */
                ctx->flags |= FLAG_MNRATE;
                if (optarg)
                {
                    ctx->min_rate = strtoull(optarg, NULL, 10);
                    if (ctx->min_rate < 1)
                    {
                        ft_assert(0, "ft_nmap: Fatal error: Max rate value is less than 1.\n");
                    }
                }
                else
                {
                    ft_assert(0, "ft_nmap: Fatal error: Max rate value is missing.\n");
                }
                break;
            default:
                FT_NMAP_USAGE(EXIT_SUCCESS);
        }
    }

    /* no target provided error */
    if (ctx->dst == NULL) {fprintf(stderr, "ft_ssl: No scan dst provided.\n"); FT_NMAP_USAGE(FAILURE);}

    /*
        instead of launching all scans as subject states,
        if no scan it's specified i'm just launching one single scan.
        This is a design choice. And was made based on SYN being most common scan and also for
        avoiding possible firewall issues making the program malfunction (as original nmap does).
        It was noticed that under some circumstances, official nmap with UDP scan it's not doing
        it properly being blocked. With my code the same behavior was noticed. So, to avoid this
        issue, i'm just launching SYN scan by default and other scans just if specified.    
    */
    if (ctx->scans == 0) ctx->scans = FLAG_SYN;

    if (ctx->speedup == 0) ctx->speedup = 0;

}

void destroy_context(nmap_context* ctx)
{
    target_t* target = NULL;
    target_t *tmp = ctx->dst;

    while (tmp)
    {
        target = tmp;
        FT_LIST_POP(&ctx->dst, target);
        tmp = FT_LIST_GET_NEXT(&ctx->dst, tmp);
        free((char*)target->address);
        free(target);
    }
}
