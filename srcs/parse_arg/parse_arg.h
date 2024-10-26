#ifndef PARSE_ARG_H
#define PARSE_ARG_H

#include <ft_nmap.h>

void parse_args(int argc, char *argv[], nmap_context* ctx);
void destroy_context(nmap_context* ctx);

#endif