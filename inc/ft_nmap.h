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
    char        *target;
    int         port_range[2];
    int         flags;
    int         scans; /* this will be set as hexa flags. */
    // ScanType    type;
} nmap_context;

#define FLAG_SYN    0x0001
#define FLAG_NULL   0x0002
#define FLAG_FIN    0x0004
#define FLAG_XMAS   0x0008
#define FLAG_ACK    0x0010
#define FLAG_UDP    0x0020
#define FLAG_PORTS  0x0040
#define FLAG_FREE1  0x0080
#define FLAG_FREE2  0x0100
#define FLAG_FREE3  0x0200
#define FLAG_FREE4  0x0400
#define FLAG_FREE5  0x0800


#endif