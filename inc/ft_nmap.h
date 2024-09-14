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
    SYN,
    NULL,
    ACK,
    FIN,
    XMAS,
    UDP,
    NONE
} scan_type;


#endif