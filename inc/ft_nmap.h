#ifndef FT_NMAP_H
#define FT_NMAP_H

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
    char        *dst_ip;
    int         port_range[2];
    int         flags;
    ScanType   type;
} nmap_context;

#endif