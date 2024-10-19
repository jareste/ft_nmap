#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netdb.h>
#include <time.h>

#include <ft_nmap.h>
#include <nmap_api.h>
#include <ft_malloc.h>

#define PCKT_LEN 8192
#define MAX_PORTS 1024

typedef struct {
    const char* service; /* service name */
    int         is_open[6]; /* 1 == open, 2 == filtered, 0 == closed */
    int         scan_open; /* bitmask */
} scan_result;

static scan_result results[MAX_PORTS];

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

int get_bitmask(ScanType scan)
{
    switch (scan)
    {
        case S_SYN:
            return FLAG_SYN;
        case S_NULL:
            return FLAG_NULL;
        case S_FIN:
            return FLAG_FIN;
        case S_XMAS:
            return FLAG_XMAS;
        case S_ACK:
            return FLAG_ACK;
        case S_UDP:
            return FLAG_UDP;
        default:
            return 0;
    }
 
    return 1 << (scan - 1);
}

unsigned short csum(unsigned short *ptr, int nbytes)
{
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    
    return(answer);
}

void create_packet(char *packet, struct sockaddr_in *sin, int target_port, const char *source_ip, int scan_type)
{
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_header psh;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin->sin_addr.s_addr;

    iph->check = csum((unsigned short *)packet, iph->tot_len);

    tcph->source = htons(12345); /* source port */
    tcph->dest = htons(target_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; /* TCP header size */
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    switch(scan_type)
    {
        case S_SYN:
            tcph->syn = 1;
            break;
        case S_NULL:
            break;
        case S_FIN:
            tcph->fin = 1;
            break;
        case S_XMAS:
            tcph->fin = 1;
            tcph->psh = 1;
            tcph->urg = 1;
            break;
        case S_ACK:
            tcph->ack = 1;
            break;
        default:
            /* TODO ASSERT */
            ft_assert(0, "Unknown scan type\n");
            return;
    }

    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin->sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = csum((unsigned short *)pseudogram, psize);

    free(pseudogram);
}

void send_packets(int sock, const char *target_ip, const char *source_ip, int scan_type, int start_port, int end_port)
{
    struct sockaddr_in sin;
    char packet[PCKT_LEN];

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(target_ip);

    for (int port = start_port; port <= end_port; port++)
    {
        memset(packet, 0, PCKT_LEN);
        create_packet(packet, &sin, port, source_ip, scan_type);

        sin.sin_port = htons(port);

        if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            ft_assert(0, "Packet send failed");
            // perror("Packet send failed");
        }
        else
        {
            // printf("Sent packet to %s on port %d\n", target_ip, port);
        }
    }
}

static const char* services[] = {
    "HTTP", "SSH", "SMTP", "MySQL", "PostgreSQL", "FTP", "Telnet", "POP3", NULL
};

const char* identify_service_from_banner(const char* banner)
{

    for (int i = 0; services[i] != NULL; i++)
    {
        if (strstr(banner, services[i]))
        {
            return services[i];
        }
    }

    return "Unknown Service";
}

void set_nonblocking(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1)
    {
        ft_assert(0, "fcntl get failed");
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        ft_assert(0, "fcntl set non-blocking failed");
    }
}

void banner_grab(const char *target_ip, int port)
{
    int sock;
    struct sockaddr_in server;
    char message[1024], server_reply[2000];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        ft_assert(0, "Socket creation failed");
        return;
    }

    server.sin_addr.s_addr = inet_addr(target_ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        close(sock);
        return;
    }

    set_nonblocking(sock);

    snprintf(message, sizeof(message), "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target_ip);
    if (send(sock, message, strlen(message), 0) < 0)
    {
        close(sock);
        ft_assert(0, "Send failed");
    }

    fd_set readfds;
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    int activity = select(sock + 1, &readfds, NULL, NULL, &timeout);
    if (activity == 0)
    {
        close(sock);
        return;
    }
    else if (activity < 0)
    {
        close(sock);
        return;
    }

    int received_len = recv(sock, server_reply, sizeof(server_reply) - 1, 0);
    if (received_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
        // printf("Receive failed\n");
    }
    else if (received_len > 0)
    {
        server_reply[received_len] = '\0';

        const char* service_name = identify_service_from_banner(server_reply);
        // printf("Port %d is open - Service: %s\n", port, service_name);
        results[port].service = service_name;
    }
    else
    {
        // printf("No data received from port %d\n", port);
    }

    close(sock);
}

void receive_responses(int sock, const char *target_ip, int *ports_status, int scan_type)
{
    fd_set readfds;
    struct timeval timeout;
    char buffer[PCKT_LEN];
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);

    int ports_left = MAX_PORTS;
    // printf("scan_type: %d\n", scan_type);

    while (ports_left > 0)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        int ret = select(sock + 1, &readfds, NULL, NULL, &timeout);
        if (ret > 0)
        {
            memset(buffer, 0, PCKT_LEN);
            int data_size = recvfrom(sock, buffer, PCKT_LEN, 0, (struct sockaddr *)&source, &source_len);
            if (data_size > 0)
            {
                struct iphdr *iph = (struct iphdr *)buffer;
                struct tcphdr *tcph = (struct tcphdr *)(buffer + (iph->ihl * 4));

                if (iph->protocol == IPPROTO_TCP && source.sin_addr.s_addr == inet_addr(target_ip))
                {
                    int port = ntohs(tcph->source);
                    if (ports_status[port] == -1)
                    {
                        if (scan_type == S_SYN && tcph->syn == 1 && tcph->ack == 1)
                        {
                            // printf("Port %d is open (SYN-ACK received)\n", port);
                            results[port].is_open[scan_type-1] = 1;
                            results[port].scan_open |= get_bitmask(scan_type);
                            ports_status[port] = 1;
                        }
                        else if ((scan_type == S_FIN || scan_type == S_XMAS || scan_type == S_NULL) && tcph->rst == 1)
                        {
                            // printf("Port %d is closed (RST received)\n", port);
                            results[port].is_open[scan_type-1] = 0;
                            results[port].scan_open |= get_bitmask(scan_type);
                            ports_status[port] = 0;
                        }
                        else if (scan_type == S_ACK && tcph->rst == 1)
                        {
                            // printf("Port %d is unfiltered (RST received)\n", port);
                            results[port].is_open[scan_type-1] = 2;
                            results[port].scan_open |= get_bitmask(scan_type);
                            ports_status[port] = 1;
                        }
                        ports_left--;
                    }
                }
            }
        }
        else if (ret == 0)
        {
            for (int i = 0; i < MAX_PORTS; i++)
            {
                if (ports_status[i] == -1)
                {
                    results[i].is_open[scan_type-1] = 2;
                    results[i].scan_open |= get_bitmask(scan_type);
                    ports_status[i] = -2;
                    ports_left--;
                }
            }
        }
        else
        {
            ft_assert(0, "select error");
        }
    }
}

void get_local_ip(char **ip)
{
    char *buffer = *ip;
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sock < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in temp_addr;
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    temp_addr.sin_port = htons(53);

    connect(temp_sock, (struct sockaddr *)&temp_addr, sizeof(temp_addr));

    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    getsockname(temp_sock, (struct sockaddr *)&local_addr, &addr_len);

    inet_ntop(AF_INET, &local_addr.sin_addr, buffer, INET_ADDRSTRLEN);

    close(temp_sock);
}

int nmap(int scan_type, char* source_ip, char* target_ip, int start_port, int end_port)
{
    int sock;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        ft_assert(0, "Socket creation failed");
    }

    int ports_status[MAX_PORTS];
    for (int i = 0; i < MAX_PORTS; i++)
    {
        ports_status[i] = -1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        ft_assert(0, "Setting IP_HDRINCL failed");
    }
    
    send_packets(sock, target_ip, source_ip, scan_type, start_port, end_port);

    receive_responses(sock, target_ip, ports_status, scan_type);

    for (int port = 1; port <= MAX_PORTS; port++)
    {
        if (ports_status[port] == 1)
        {
            banner_grab(target_ip, port);
        }
    }

    close(sock);
    return 0;
}

int resolve_hostname(const char *hostname, char *resolved_ip)
{
    struct addrinfo hints, *res;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), resolved_ip, INET_ADDRSTRLEN);

    freeaddrinfo(res);
    return 0;
}


void print_scan_status(int status) {
    switch (status) {
        case 0:
            printf("Closed");
            break;
        case 1:
            printf("Open");
            break;
        case 2:
            printf("Filtered");
            break;
        default:
            printf("Unknown");
            break;
    }
}

void print_scan_result(int *is_open, int scans) {
    if (scans & FLAG_SYN) {
        printf(" SYN(");
        print_scan_status(is_open[S_SYN - 1]);
        printf(")");
    }
    if (scans & FLAG_NULL) {
        printf(" NULL(");
        print_scan_status(is_open[S_NULL - 1]);
        printf(")");
    }
    if (scans & FLAG_FIN) {
        printf(" FIN(");
        print_scan_status(is_open[S_FIN - 1]);
        printf(")");
    }
    if (scans & FLAG_XMAS) {
        printf(" XMAS(");
        print_scan_status(is_open[S_XMAS - 1]);
        printf(")");
    }
    if (scans & FLAG_ACK) {
        printf(" ACK(");
        print_scan_status(is_open[S_ACK - 1]);
        printf(")");
    }
    if (scans & FLAG_UDP) {
        printf(" UDP(");
        print_scan_status(is_open[S_UDP - 1]);
        printf(")");
    }
}

void print_result(nmap_context* ctx) {
    int start_port = ctx->port_range[0];
    int end_port = ctx->port_range[1];
    int total_ports = end_port - start_port + 1;
    int open_ports = 0;
    int closed_filtered_ports = 0;

    printf("Scan Configurations\n");
    printf("Target Ip-Address: %s\n", ctx->dst->address);
    printf("No of Ports to scan: %d\n", total_ports);
    printf("Scans to be performed: ");
    if (ctx->scans & FLAG_SYN) printf("SYN ");
    if (ctx->scans & FLAG_NULL) printf("NULL ");
    if (ctx->scans & FLAG_FIN) printf("FIN ");
    if (ctx->scans & FLAG_XMAS) printf("XMAS ");
    if (ctx->scans & FLAG_ACK) printf("ACK ");
    if (ctx->scans & FLAG_UDP) printf("UDP ");
    printf("\n");
    printf("No of threads: %d\n", ctx->speedup);
    printf("Scanning..\n");
    printf("................\n");

    printf("Open ports:\n");
    printf("%-6s %-20s %-42s %-10s\n", "Port", "Service Name", "Results", "Conclusion");
    printf("-------------------------------------------------------------\n");

    // Loop through the results to display open ports
    for (int i = start_port; i <= end_port; i++) {
        if (results[i].is_open[0] == 1) { // If the port is open (any scan detected as open)
            open_ports++;
            printf("%-6d %-20s ", i, results[i].service ? results[i].service : "Unassigned");
            print_scan_result(results[i].is_open, results[i].scan_open);
            printf("\t%-10s\n", "Open");
        } else {
            closed_filtered_ports++;
        }
    }

    // If the total ports to scan is greater than 20, summarize closed/filtered ports
    if (total_ports > 20) {
        printf("\nNote: Other ports are filtered or closed.\n");
    } else {
        printf("\nClosed/Filtered/Unfiltered ports:\n");
        printf("%-6s %-20s %-42s %-10s\n", "Port", "Service Name", "Results", "Conclusion");
        printf("-------------------------------------------------------------\n");

        for (int i = start_port; i <= end_port; i++) {
            if (results[i].is_open[0] != 1) { // If the port is not open
                printf("%-6d %-20s ", i, results[i].service ? results[i].service : "Unassigned");
                print_scan_result(results[i].is_open, results[i].scan_open);
                printf("\t%-10s\n", "Closed");
            }
        }
    }
}

int nmap_main(nmap_context* ctx)
{
    target_t *tmp = ctx->dst;
    struct timespec start, end;
    double elapsed;
    char *source_ip = malloc(INET_ADDRSTRLEN);

    while (tmp)
    {
        memset(results, 0, sizeof(results));

        /* time */
        clock_gettime(CLOCK_MONOTONIC, &start);

        get_local_ip(&source_ip);
        const char *target_ip = tmp->address;

        struct in_addr addr;
        char resolved_ip[INET_ADDRSTRLEN];

        if (inet_pton(AF_INET, target_ip, &addr) == 1)
        {
            strncpy(resolved_ip, target_ip, INET_ADDRSTRLEN);
        }
        else
        {
            if (resolve_hostname(target_ip, resolved_ip) != 0)
            {
                fprintf(stderr, "Error: Unable to resolve hostname %s\n", target_ip);
                free(source_ip);
                tmp = FT_LIST_GET_NEXT(&ctx->dst, tmp);
                continue;
            }
        }

        if (ctx->scans & FLAG_SYN)
            nmap(S_SYN, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1]);
        
        if (ctx->scans & FLAG_NULL)
            nmap(S_NULL, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1]);
        
        if (ctx->scans & FLAG_FIN)

            nmap(S_FIN, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1]);

        if (ctx->scans & FLAG_XMAS)
            nmap(S_XMAS, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1]);

        if (ctx->scans & FLAG_ACK)
            nmap(S_ACK, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1]);

        /* time */
        clock_gettime(CLOCK_MONOTONIC, &end);

        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        // printf("Scan results for %s\n\n\n", target_ip);
        print_result(ctx);

        printf("\nScan took %.5f secs\n", elapsed); // Placeholder for actual time


        tmp = FT_LIST_GET_NEXT(&ctx->dst, tmp);
    }

    return 0;
}


// int main(int argc, char *argv[])
// {
//     if (argc != 3)
//     {
//         printf("Usage: %s <target IP> <scan type>\n", argv[0]);
//         printf("Scan types: 1=SYN, 2=NULL, 3=FIN, 4=XMAS, 5=ACK\n");
//         return -1;
//     }

//     const char *target_ip = argv[1];
//     char *source_ip = malloc(INET_ADDRSTRLEN);
//     get_local_ip(&source_ip);  // Get the local IP dynamically

//     int scan_type = atoi(argv[2]);

//     int sock;

//     printf("Scanning target %s from source %s\n", target_ip, source_ip);
//     // Create a raw socket
//     sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
//     if (sock < 0)
//     {
//         perror("Socket creation failed");
//         return -1;
//     }

//     int ports_status[MAX_PORTS];
//     for (int i = 0; i < MAX_PORTS; i++) {
//         ports_status[i] = -1;
//     }

//     // Set IP_HDRINCL to tell the kernel that headers are included in the packet
//     int one = 1;
//     if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
//     {
//         perror("Setting IP_HDRINCL failed");
//         return -1;
//     }

//     send_packets(sock, target_ip, source_ip, scan_type, 1, MAX_PORTS);

//     // Wait for responses asynchronously
//     receive_responses(sock, target_ip, ports_status, scan_type);

//     for (int port = 1; port <= MAX_PORTS; port++)
//     {
//         if (ports_status[port] == 1)
//         {
//             banner_grab(target_ip, port);
//         }
//     }

//     close(sock);
//     return 0;
// }
