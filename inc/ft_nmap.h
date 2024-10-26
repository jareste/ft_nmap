#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <ft_list.h>
#include <stdint.h>

#define UNUSED_PARAM(x) (void)(x)

typedef enum {
    TYPE_STDIN,
    TYPE_STDIN_NORMAL,
    TYPE_FILE,
    TYPE_NORMAL
} input_type;

typedef enum {
    false,
    true
} bool;

typedef enum {
    S_SYN = 1,
    S_NULL = 2,
    S_FIN = 3,
    S_XMAS = 4,
    S_ACK = 5,
    S_UDP = 6,
    NONE = 7
} ScanType;

typedef struct { /* useless? */
    const char* name;
    ScanType   scan;
} dst_ip_entry;

typedef struct {
    list_item_t list;
    const char* address;
} target_t;

typedef struct {
    target_t*   dst;
    int         port_range[2];
    int         flags;
    int         scans; /* this will be set as hexa flags. */
    int         speedup;
    uint64_t    max_rate;
    uint64_t    min_rate;
    // ScanType    type;
} nmap_context;

#define FLAG_SYN    0x0001
#define FLAG_NULL   0x0002
#define FLAG_FIN    0x0004
#define FLAG_XMAS   0x0008
#define FLAG_ACK    0x0010
#define FLAG_UDP    0x0020
#define FLAG_PORTS  0x0040
#define FLAG_SPEED  0x0080
#define FLAG_OS     0x0100
#define FLAG_FAST   0x0200
#define FLAG_MXRATE 0x0400
#define FLAG_OPEN   0x0800
#define FLAG_MNRATE 0x1000

#define FT_NMAP_USAGE(x)                                                        \
    do {                                                                       \
        printf("Usage: ft_nmap [--help] [--ports [NUMBER/RANGE]] "             \
               "--ip IP_ADDRESS [--speedup [NUMBER]] [--scan [TYPE]]\n"        \
               "       or: ft_nmap [--help] [--ports [NUMBER/RANGE]] "         \
               "--file FILE_PATH [--speedup [NUMBER]] [--scan [TYPE]]\n\n");   \
        printf("Options:\n");                                                  \
        printf("  -h, --help               Show this help message and exit\n");\
        printf("  -p, --ports              Specify ports as a single number or range (e.g., 22 or 1-1024)\n");\
        printf("  -i, --ip                 Specify a single IP address to scan (mandatory unless --file is used)\n");\
        printf("  -f, --file               Specify a file containing IP addresses (one per line)\n");\
        printf("      --speedup            Set the number of threads to speed up the scan (default: 0, max: 250)\n");\
        printf("  -s, --scan               Specify the type of scan to perform. (e.g., SYN, NULL, ACK, FIN, XMAS, UDP)\n");\
        printf("                           Multiple scans can be launched at once if comma separated (e.g., syn,ack)\n");\
        printf("  -O, --os                 Enable OS detection\n");             \
        printf("  -F, --fast               Enable fast scan mode\n");           \
        printf("      --max-rate           Set the maximum rate of packets to send per second\n");\
        printf("      --min-rate           Set the maximum rate of packets to send per second\n");\
        printf("      --open               Show only open ports\n");             \
        printf("\nExamples:\n");                                               \
        printf("  ft_nmap --ip 192.168.1.1 --ports 22 --scan SYN\n");          \
        printf("  ft_nmap --file targets.txt --ports 1-1024 --speedup 100\n"); \
        printf("  ft_nmap -i 10.0.0.5 -p 80-443 --scan SYN,ACK\n");            \
        exit(x);                                                    \
    } while (0)

#endif