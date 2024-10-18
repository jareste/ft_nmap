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

#include <ft_nmap.h>
#include <nmap_api.h>

#define PCKT_LEN 8192
#define MAX_PORTS 1024

// Pseudo-header needed for TCP checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
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
            printf("Sending SYN packet.\n");
            break;
        case S_NULL:
            printf("Sending NULL packet.\n");
            break;
        case S_FIN:
            tcph->fin = 1;
            printf("Sending FIN packet.\n");
            break;
        case S_XMAS:
            tcph->fin = 1;
            tcph->psh = 1;
            tcph->urg = 1;
            printf("Sending XMAS packet.\n");
            break;
        case S_ACK:
            tcph->ack = 1;
            printf("Sending ACK packet.\n");
            break;
        default:
        /* TODO ASSERT */
            printf("Unknown scan type!\n");
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
            perror("Packet send failed");
        }
        else
        {
            printf("Sent packet to %s on port %d\n", target_ip, port);
        }
    }
}

static const char* services[] ={
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
        perror("fcntl get failed");
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        perror("fcntl set non-blocking failed");
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
        printf("Could not create socket\n");
        return;
    }

    server.sin_addr.s_addr = inet_addr(target_ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("connect failed");
        close(sock);
        return;
    }

    set_nonblocking(sock);

    printf("Sending GET request to port %d\n", port);
    snprintf(message, sizeof(message), "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target_ip);
    if (send(sock, message, strlen(message), 0) < 0)
    {
        printf("Send failed\n");
        close(sock);
        return;
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
        printf("Receive timed out\n");
        close(sock);
        return;
    }
    else if (activity < 0)
    {
        perror("select error");
        close(sock);
        return;
    }

    int received_len = recv(sock, server_reply, sizeof(server_reply) - 1, 0);
    if (received_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    {
        printf("Receive failed\n");
    }
    else if (received_len > 0)
    {
        server_reply[received_len] = '\0';

        const char* service_name = identify_service_from_banner(server_reply);
        printf("Port %d is open - Service: %s\n", port, service_name);
    }
    else
    {
        printf("No data received from port %d\n", port);
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

    timeout.tv_sec = 4;
    timeout.tv_usec = 0;

    int ports_left = MAX_PORTS;

    while (ports_left > 0)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

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
                    if (ports_status[port] == -1) {
                        if (scan_type == S_SYN && tcph->syn == 1 && tcph->ack == 1)
                        {
                            printf("Port %d is open (SYN-ACK received)\n", port);
                            ports_status[port] = 1;
                        }
                        else if ((scan_type == S_FIN || scan_type == S_XMAS || scan_type == S_NULL) && tcph->rst == 1)
                        {
                            printf("Port %d is closed (RST received)\n", port);
                            ports_status[port] = 0;
                        }
                        else if (scan_type == S_ACK && tcph->rst == 1)
                        {
                            printf("Port %d is unfiltered (RST received)\n", port);
                            ports_status[port] = 1;
                        }
                        ports_left--;
                    }
                }
            }
        }
        else if (ret == 0)
        {
            printf("Timeout: no more responses received, marking remaining ports as filtered.\n");
            for (int i = 0; i < MAX_PORTS; i++)
            {
                if (ports_status[i] == -1)
                {
                    ports_status[i] = -2;
                    ports_left--;
                }
            }
        }
        else
        {
            perror("select error");
            break;
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
    printf("Local IP: %s\n", buffer);
    close(temp_sock);
}

int nmap_main(nmap_context* ctx)
{
    // if (argc != 3)
    // {
    //     printf("Usage: %s <target IP> <scan type>\n", argv[0]);
    //     printf("Scan types: 1=SYN, 2=NULL, 3=FIN, 4=XMAS, 5=ACK\n");
    //     return -1;
    // }

    const char *target_ip = ctx->dst->address;
    char *source_ip = malloc(INET_ADDRSTRLEN);
    get_local_ip(&source_ip);  // Get the local IP dynamically

    int scan_type = atoi("3");

    int sock;

    printf("Scanning target %s from source %s\n", target_ip, source_ip);
    // Create a raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return -1;
    }

    int ports_status[MAX_PORTS];
    for (int i = 0; i < MAX_PORTS; i++) {
        ports_status[i] = -1;
    }

    // Set IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Setting IP_HDRINCL failed");
        return -1;
    }

    send_packets(sock, target_ip, source_ip, scan_type, 1, MAX_PORTS);

    // Wait for responses asynchronously
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
