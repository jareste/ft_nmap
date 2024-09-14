/***************************/
/*        INCLUDES         */
/***************************/

#include <ft_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <ft_ssl.h>
#include <ft_list.h>
#include <errno.h>
#include <utils.h>

/***************************/
/*        DEFINES          */
/***************************/

typedef struct {
    const char* name;
    scan_type   scan;
} scan_entry;

static const scan_entry g_scans[] = {
    { "syn", S_SYN },
    { "null", S_NULL },
    { "ack", S_ACK },
    { "fin", S_FIN },
    { "xmas", S_XMAS },
    { "udp", S_UDP },
    { "all", S_NONE },
    { NULL, S_NONE }
};

typedef enum {
    S_SYN,
    S_NULL,
    S_ACK,
    S_FIN,
    S_XMAS,
    S_UDP,
    S_NONE
} scan_type;


#define get_scan_name(x) g_scans[x].name
#define get_scan_scan(x) g_scans[x].scan

/***************************/
/*        METHODS          */
/***************************/

static void read_file(const char *filename, char **content)
{
    if (access(filename, F_OK) != 0)
    {
        fprintf(stderr, "ft_ssl: %s: No such file or directory\n", filename);
        return;
    }

    if (access(filename, R_OK) != 0)
    {
        fprintf(stderr, "ft_ssl: %s: Permission denied\n", filename);
        return;
    }

    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        fprintf(stderr, "ft_ssl: %s: %s\n", filename, strerror(errno));
        /* NEVER HERE */
        ft_assert(file, "Fatal error: Could not open file.");
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *content = malloc(file_size + 1);

    size_t read_size = fread(*content, 1, file_size, file);
    if (read_size != (size_t)file_size)
    {
        perror("Error reading file");
        free(*content);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    (*content)[file_size] = '\0';

    fclose(file);
}


static void read_stdin(char **encrypt)
{
    size_t buffer_size = 1024;
    size_t total_size = 0;
    char *buffer = malloc(buffer_size);
    int c;

    while ((c = getchar()) != EOF)
    {
        if (total_size + 1 >= buffer_size)
        {
            buffer_size *= 2;
            char *new_buffer = realloc(buffer, buffer_size);
            buffer = new_buffer;
        }
        buffer[total_size++] = (char)c;
    }

    buffer[total_size] = '\0';

    *encrypt = buffer;
}

static algorithms check_algorithm(const char *algorithm)
{
    if (algorithm == NULL) goto error;

    for (int i = 0; get_scan_name(i) != NULL; i++)
    {
        if (strcasecmp(algorithm, g_scans[i].name) == 0)
        {
            return get_scan_scan(i);
        }
    }

error:
    fprintf(stderr, "ft_ssl: Error: '%s' is an invalid command.\n", algorithm);
    print_usage(NONE, EXIT_FAILURE); /* EXITS */
    return NONE;
}

static bool can_read_file(algorithms algo)
{
    switch (algo)
    {
        case MD5:
        case SHA256:
        case WHIRLPOOL:
        case BLAKE2S:
            return true;
        default:
            return false;
    }
}

void check_flag(algorithms algo, int flag, char flag_name)
{
    switch (algo)
    {
        case MD5:
        case SHA256:
        case WHIRLPOOL:
        case BLAKE2S:
            if (flag & DIGEST_FLAGS)
                return;
            break;
        case BASE64:
            if (flag & CIPHER_FLAGS)
                    return;
                break;
        case DES:
        case DES_ECB:
        case DES_CBC:
        case DES_OFB:
        case DES3:
        case DES3_ECB:
        case DES3_CBC:
        case DES3_OFB:
            if (flag & CIPHER_FLAGS)
                return;
            break;
        default:
            print_usage(NONE, EXIT_FAILURE);
            break;
    }
    fprintf(stderr, "ft_ssl: Error: Invalid flag combination %c with algo %s.\n", flag_name, get_scan_name(algo));
    print_usage(NONE, EXIT_FAILURE);
}

void parse_args(int argc, char *argv[], int *flags, void** encrypt, algorithms* algorithm)
{
    int opt;
    char* stdin_buffer = NULL;
    list_t **list = (list_t **)encrypt;

    *algorithm = check_algorithm(argv[1]);
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"ports", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "?hi:m:q:df:4In6", long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case '?':
            case 'h':
                print_usage(*algorithm, EXIT_SUCCESS);
                exit(0);
            case 'p':
                check_flag(*algorithm, P_FLAG, 'p');
                *flags |= P_FLAG;
                break;
            case 'q':
                check_flag(*algorithm, Q_FLAG, 'q');
                *flags |= Q_FLAG;
                break;
            case 'r':
                check_flag(*algorithm, R_FLAG, 'r');
                *flags |= R_FLAG;
                break;
            case 's':
                check_flag(*algorithm, S_FLAG, 's');
                if (optarg)
                {
                    list_add_last(list, optarg, optarg, TYPE_NORMAL);
                }
                else
                {
                    fprintf(stderr, "Option -l contains garbage as argument: %s.\n", optarg);
                    fprintf(stderr, "This will become fatal error in the future.\n");
                }
                break;
            case 'e':
                check_flag(*algorithm, E_FLAG, 'e');
                if (*flags & D_FLAG)
                {
                    fprintf(stderr, "ft_ssl: Error: Cannot use -d and -e together.\n");
                    print_usage(*algorithm, EXIT_FAILURE);
                    exit(1);
                }
                *flags |= E_FLAG;
                break;
            case 'd':
                check_flag(*algorithm, D_FLAG, 'd');
                if (*flags & E_FLAG)
                {
                    fprintf(stderr, "ft_ssl: Error: Cannot use -d and -e together.\n");
                    print_usage(*algorithm, EXIT_FAILURE);
                    exit(1);
                }
                *flags |= D_FLAG;
                break;
            case 'i':
                check_flag(*algorithm, I_FLAG, 'i');
                if (optarg)
                {
                    read_file(optarg, &stdin_buffer);
                    list_add_last(list, stdin_buffer, optarg, TYPE_FILE);
                    free(stdin_buffer);
                    stdin_buffer = NULL;
                }
                else
                {
                    fprintf(stderr, "Option -i contains garbage as argument: %s.\n", optarg);
                    fprintf(stderr, "This will become fatal error in the future.\n");
                }
                break;
            case 'o':
            /*notok*/
                check_flag(*algorithm, O_FLAG, 'o');
                if (optarg)
                {
                    list_add_last(list, optarg, optarg, TYPE_NORMAL);
                }
                else
                {
                    fprintf(stderr, "Option -o contains garbage as argument: %s.\n", optarg);
                    fprintf(stderr, "This will become fatal error in the future.\n");
                }
                break;
            default:
                print_usage(*algorithm, EXIT_FAILURE);
                exit(1);
        }
    }

    stdin_buffer = NULL;
    for (int i = optind+1; i < argc; i++)
    {
        if (!can_read_file(*algorithm))
        {
            fprintf(stderr, "ft_ssl: Error: %s does not accept files as input.\n", get_scan_name(*algorithm));
            print_usage(*algorithm, EXIT_FAILURE);
            exit(1);
        }

        read_file(argv[i], &stdin_buffer);
        if (stdin_buffer)
        {
            list_add_last(list, stdin_buffer, argv[i], TYPE_FILE);
            free(stdin_buffer);
            stdin_buffer = NULL;
        }
    }

    if (optind >= argc)
    {
        fprintf(stderr, "Expected argument after options\n");
        print_usage(*algorithm, EXIT_FAILURE);
        exit(1);
    }

    /* chekc if something to read from stdin. */
    if (!isatty(fileno(stdin)) && (*flags & P_FLAG || *list == NULL)) {
        read_stdin(&stdin_buffer);
        list_add_last(list, stdin_buffer, (*flags & P_FLAG) ? stdin_buffer : "stdin", (*flags & P_FLAG) ? TYPE_STDIN_NORMAL : TYPE_STDIN);
        free(stdin_buffer);
    }

    /* no input recieved, so we read from stdin. */
    if ((*list == NULL))
    {
        read_stdin(&stdin_buffer);
        list_add_last(list, stdin_buffer, (*flags & P_FLAG) ? stdin_buffer : "stdin", (*flags & P_FLAG) ? TYPE_STDIN_NORMAL : TYPE_STDIN);
        free(stdin_buffer);
    }
}