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
#include <pthread.h>
#include <stdatomic.h>
#include <netinet/ip_icmp.h>

#include <ft_nmap.h>
#include <nmap_api.h>
#include <ft_malloc.h>

#define PCKT_LEN    8192
#define MAX_PORTS   1024

typedef struct {
    const char* service; /* service name */
    int         is_open[6]; /* 1 == open, 2 == filtered, 0 == closed */
    int         scan_open; /* bitmask */
    bool        any_open; /* if any scan marked as open */
    bool        any_filtered; /* if any scan marked as filtered */
} scan_result;

typedef struct {
    int start_port;
    int end_port;
    char* source_ip;
    char* target_ip;
    int scan_type;
    int worker_id;
    // int sock;
} task_param;

typedef struct {
    int         task_id;       // Task ID
    task_param* task_param;    // Parameter for the task
    bool        active;       // Whether this worker is currently processing a task
    bool        exit;         // Indicates if the worker should terminate
} worker_task;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    worker_task task;
    bool ready;
} worker_info;

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

int nmap(int scan_type, char* source_ip, char* target_ip, int start_port, int end_port);
int udp(char* target_ip, int start_port, int end_port);
void set_nonblocking(int sock);

worker_info *workers;
pthread_t *threads;

static scan_result results[MAX_PORTS];
static int worker_count = 1;
static char* os = NULL;
pthread_mutex_t results_mutex;
static uint64_t max_rate = 0;
static uint64_t min_rate = 0;

atomic_int next_task_id = 0;

int generate_task_id() {
    return atomic_fetch_add(&next_task_id, 1);
}

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

/* WORKERS */
void create_task_param(task_param* task_param, char* source_ip, char* target_ip, int start_port, int end_port, int scan_type)
{
    task_param->source_ip = source_ip;
    task_param->target_ip = target_ip;
    task_param->start_port = start_port;
    task_param->end_port = end_port;
    task_param->scan_type = scan_type;
}

void* worker_thread(void* arg)
{
    worker_info* winfo = (worker_info*)arg;
    task_param* task_param = NULL;


    while (true)
    {
        pthread_mutex_lock(&winfo->mutex);

        while (!winfo->ready)
        {
            pthread_cond_wait(&winfo->cond, &winfo->mutex);
        }

        if (winfo->task.exit)
        {
            pthread_mutex_unlock(&winfo->mutex);
            break;
        }

        task_param = winfo->task.task_param;

        if (task_param->scan_type == S_UDP)
            udp(task_param->target_ip, task_param->start_port, task_param->end_port);
        else
            nmap(task_param->scan_type, task_param->source_ip, task_param->target_ip, task_param->start_port, task_param->end_port);


        /* reset and mark it ready for performing something new. */
        winfo->ready = false;
        winfo->task.active = false;

        pthread_mutex_unlock(&winfo->mutex);
    }

    return NULL;
}

/* returns true if any worker still in progress */
bool all_workers_ready()
{
    for (int i = 0; i < worker_count; i++)
    {
        if (workers[i].ready)
        {
            return false;
        }
    }

    return true;
}

void initialize_workers()
{
    workers = (worker_info*)malloc(sizeof(worker_info) * worker_count);
    threads = (pthread_t*)malloc(sizeof(pthread_t) * worker_count);

    pthread_mutex_init(&results_mutex, NULL);

    for (int i = 0; i < worker_count; i++)
    {
        pthread_mutex_init(&workers[i].mutex, NULL);
        pthread_cond_init(&workers[i].cond, NULL);

        workers[i].ready = false;
        workers[i].task.active = false;
        workers[i].task.exit = false;

        if (pthread_create(&threads[i], NULL, worker_thread, &workers[i]) != 0)
        {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }
}


void assign_task_to_worker(task_param* task_param)
{
    int worker_id = -1;
    int task_id = generate_task_id();

    while (true)
    {
        for (int i = 0; i < worker_count; i++)
        {
            pthread_mutex_lock(&workers[i].mutex);
            if (!workers[i].task.active)
            {
                worker_id = i;
                break;
            }
            pthread_mutex_unlock(&workers[i].mutex);
        }

        if (worker_id != -1)
        {
            workers[worker_id].task.task_id = task_id;
            workers[worker_id].task.task_param = task_param;
            workers[worker_id].task.active = true;

            workers[worker_id].ready = true;
            pthread_cond_signal(&workers[worker_id].cond);

            pthread_mutex_unlock(&workers[worker_id].mutex);
            break;
        }

        usleep(10000);
    }
}

void shutdown_workers()
{
    for (int i = 0; i < worker_count; i++)
    {
        pthread_mutex_lock(&workers[i].mutex);
        workers[i].task.exit = true;
        workers[i].ready = true;
        pthread_cond_signal(&workers[i].cond);
        pthread_mutex_unlock(&workers[i].mutex);
    }

    for (int i = 0; i < worker_count; i++)
    {
        pthread_join(threads[i], NULL);
        pthread_mutex_destroy(&workers[i].mutex);
        pthread_cond_destroy(&workers[i].cond);
    }

    pthread_mutex_destroy(&results_mutex);
}

/* WORKERS END */

/* UDP */
void send_udp_packet(int sock, struct sockaddr_in *target, int port) {
    unsigned char dns_query[33] = {
        0x12, 0x34,  // Transaction ID
        0x01, 0x00,  // Flags: standard query
        0x00, 0x01,  // Questions: 1
        0x00, 0x00,  // Answer RRs: 0
        0x00, 0x00,  // Authority RRs: 0
        0x00, 0x00,  // Additional RRs: 0
        0x03, 0x77, 0x77, 0x77,  // "www"
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  // "google"
        0x03, 0x63, 0x6f, 0x6d,  // "com"
        0x00,  // Null terminator for the domain name
        0x00, 0x01,  // Type: A (Host Request)
        0x00, 0x01   // Class: IN (Internet)
    };

    const char *test_message = "Hello, UDP Service";
    const void *message;
    size_t message_length;

    // If scanning port 53 (DNS), send a DNS query; otherwise, send a simple UDP packet
    if (port == 53)
    {
        message = dns_query;
        message_length = sizeof(dns_query);
    }
    else
    {
        message = test_message;
        message_length = strlen(test_message);
    }

    int retries = 5;
    while (retries > 0)
    {
        if (sendto(sock, message, message_length, 0, (struct sockaddr *)target, sizeof(*target)) < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                retries--;
                usleep(10000);  // Wait for 10 milliseconds before retrying
                continue;
            }
            else
            {
                perror("sendto failed");
            }
        }
        break;
    }
}

void set_socket_send_buffer(int sock) {
    int buffer_size = 2 * 1024 * 1024;  // 1MB buffer size
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) < 0) {
        perror("Failed to set socket send buffer size");
    }
}

void set_socket_timeout(int sock, int sec, int usec)
{
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = usec;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
}

void scan_udp_ports(const char *target_ip, int start_port, int end_port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return;
    }

    set_socket_send_buffer(sock);
    set_nonblocking(sock);
    set_socket_timeout(sock, 1, 0);  // Set timeout for receiving data

    // Send packets to all ports quickly
    for (int port = start_port; port <= end_port; port++)
    {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, target_ip, &target.sin_addr);

        send_udp_packet(sock, &target, port);
    }

    // Use select to handle multiple responses at once
    fd_set readfds;
    struct timeval timeout;
    char buffer[1024];
    struct sockaddr_in response;
    socklen_t len = sizeof(response);
    int received;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    // Monitor for responses
    timeout.tv_sec = 2;  // Timeout value for how long to wait for responses
    timeout.tv_usec = 0;

    while (select(sock + 1, &readfds, NULL, NULL, &timeout) > 0)
    {
        if (FD_ISSET(sock, &readfds))
        {
            received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&response, &len);
            if (received >= 0)
            {
                int port = ntohs(response.sin_port);
                results[port].is_open[5] = 1;
                results[port].scan_open |= FLAG_UDP;
                results[port].service = port == 53 ? "domain" : "Unassigned";
                results[port].any_open = true;
            }
        }

        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
    }

    for (int i = start_port; i <= end_port; i++)
    {
        if (results[i].is_open[5] != 1)
        {
            results[i].is_open[5] = 0;
            results[i].scan_open |= FLAG_UDP;
        }
    }

    close(sock);
}


int udp(char* target_ip, int start_port, int end_port)
{
    scan_udp_ports(target_ip, start_port, end_port);
    
    return 0;
}
/* UDP_END*/

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

    uint64_t min_interval = min_rate ? 1000000 / min_rate : 0;
    uint64_t max_interval = max_rate ? 1000000 / max_rate : 0;

    struct timespec start, end, last_send;
    uint64_t since_last_send;

    clock_gettime(CLOCK_MONOTONIC, &last_send);

    for (int port = start_port; port <= end_port; port++)
    {
        memset(packet, 0, PCKT_LEN);
        create_packet(packet, &sin, port, source_ip, scan_type);
        sin.sin_port = htons(port);

        clock_gettime(CLOCK_MONOTONIC, &start);

        if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            fprintf(stderr, "Packet send failed %s\n", strerror(errno));
            if (errno == EPERM)
            {
                fprintf(stderr, "Ensure you are running as root or have necessary capabilities.\n");
            }
            ft_assert(0, "Packet send failed");
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        since_last_send = (end.tv_sec - last_send.tv_sec) * 1000000 + (end.tv_nsec - last_send.tv_nsec) / 1000;

        if (max_interval > 0)
        {
            usleep(max_interval);
        }

        if (min_interval > 0 && since_last_send < min_interval)
        {
            usleep(min_interval - since_last_send);
        }

        clock_gettime(CLOCK_MONOTONIC, &last_send);
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

    return "Unassigned";
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
    }
    else if (received_len > 0)
    {
        server_reply[received_len] = '\0';

        const char* service_name = identify_service_from_banner(server_reply);
        results[port].service = service_name;
    }
    else
    {
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

    while (ports_left > 0)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        timeout.tv_sec = 1;
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

                    pthread_mutex_lock(&results_mutex);
                    if (ports_status[port] == -1)
                    {
                        if (scan_type == S_SYN && tcph->syn == 1 && tcph->ack == 1)
                        {
                            results[port].is_open[scan_type - 1] = 1;
                            results[port].scan_open |= get_bitmask(scan_type);
                            ports_status[port] = 1;
                            results[port].any_open = true;
                        }
                        else if ((scan_type == S_FIN || scan_type == S_XMAS || scan_type == S_NULL) && tcph->rst == 1)
                        {
                            results[port].is_open[scan_type - 1] = 0;
                            results[port].scan_open |= get_bitmask(scan_type);
                            ports_status[port] = 0;
                        }
                        else if (scan_type == S_ACK && tcph->rst == 1)
                        {
                            results[port].is_open[scan_type - 1] = 2;
                            results[port].scan_open |= get_bitmask(scan_type);
                            ports_status[port] = 1;
                            // results[port].any_open = true;
                            results[port].any_filtered = true;
                        }
                        ports_left--;
                    }
                    pthread_mutex_unlock(&results_mutex);
                }
            }
        }
        else if (ret == 0)  // select() timeout
        {
            pthread_mutex_lock(&results_mutex);
            for (int i = 0; i < MAX_PORTS; i++)
            {
                if (ports_status[i] == -1)
                {
                    // Handle timeout differently based on scan type
                    switch (scan_type)
                    {
                        case S_SYN:
                            results[i].is_open[scan_type - 1] = 2; // Filtered
                            break;
                        case S_ACK:
                            results[i].is_open[scan_type - 1] = 2; // Filtered
                            break;
                        case S_FIN:
                        case S_NULL:
                        case S_XMAS:
                        case S_UDP:
                            results[i].is_open[scan_type - 1] = 3; // Open|Filtered
                            break;
                        default:
                            results[i].is_open[scan_type - 1] = 2; // Filtered as default
                            break;
                    }

                    results[i].scan_open |= get_bitmask(scan_type);
                    ports_status[i] = -2;
                    ports_left--;
                }
            }
            pthread_mutex_unlock(&results_mutex);
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
    
    // Create a new socket for each thread
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return -1;
    }
    
    // set_nonblocking(sock);

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Setting IP_HDRINCL failed");
        close(sock);
        return -1;
    }

    int ports_status[MAX_PORTS];
    for (int i = 0; i < MAX_PORTS; i++)
    {
        ports_status[i] = -1;
    }

    send_packets(sock, target_ip, source_ip, scan_type, start_port, end_port);
    receive_responses(sock, target_ip, ports_status, scan_type);

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
        // fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), resolved_ip, INET_ADDRSTRLEN);

    freeaddrinfo(res);
    return 0;
}


void print_scan_status(int status)
{
    switch (status)
    {
        case 0:
            printf("Closed");
            break;
        case 1:
            printf("Open");
            break;
        case 2:
            printf("Filtered");
            break;
        case 3:
            printf("Open|Filtered");
            break;
        default:
            printf("Unknown");
            break;
    }
}

void print_scan_result(int *is_open, int scans, bool flag_open)
{
    if (scans & FLAG_SYN)
    {
        if (!flag_open || (flag_open && is_open[S_SYN - 1] >= 1))
        {
            printf(" SYN(");
            print_scan_status(is_open[S_SYN - 1]);
            printf(")");
        }
    }
    if (scans & FLAG_NULL)
    {
        if (!flag_open || (flag_open && is_open[S_NULL - 1] >= 1))
        {
            printf(" NULL(");
            print_scan_status(is_open[S_NULL - 1]);
            printf(")");
        }
    }
    if (scans & FLAG_FIN)
    {
        if (!flag_open || (flag_open && is_open[S_FIN - 1] >= 1))
        {
            printf(" FIN(");
            print_scan_status(is_open[S_FIN - 1]);
            printf(")");
        }
    }
    if (scans & FLAG_XMAS)
    {
        if (!flag_open || (flag_open && is_open[S_XMAS - 1] >= 1))
        {
            printf(" XMAS(");
            print_scan_status(is_open[S_XMAS - 1]);
            printf(")");
        }
    }
    if (scans & FLAG_ACK)
    {
        if (!flag_open || (flag_open && is_open[S_ACK - 1] >= 1))
        {
            printf(" ACK(");
            print_scan_status(is_open[S_ACK - 1]);
            printf(")");
        }
    }
    if (scans & FLAG_UDP)
    {
        if (!flag_open || (flag_open && is_open[S_UDP - 1] >= 1))
        {
            printf(" UDP(");
            print_scan_status(is_open[S_UDP - 1]);
            printf(")");
        }
    }
}

void print_result(nmap_context* ctx, const char* target_ip)
{
    int start_port = ctx->port_range[0];
    int end_port = ctx->port_range[1];
    int total_ports = end_port - start_port + 1;
    int open_ports = 0;
    int filtered_ports = 0;
    int closed_filtered_ports = 0;
    int i;

    printf("Scan Configurations\n");
    printf("Target Ip-Address: %s\n", target_ip);

    if (os)
    {
        printf("OS: %s\n", os);
    }

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

    for (i = start_port; i <= end_port; i++)
    {
        if (results[i].any_open == true)
        {
            open_ports++;
        }
        if (results[i].any_filtered == true)
        {
            filtered_ports++;
        }

    }

    for (i = start_port; i <= end_port; i++)
    {
        if ((results[i].any_open == true) || (results[i].any_filtered && open_ports <= 20 && filtered_ports <= 20))
        {
            printf("%-6d %-20s ", i, results[i].service ? results[i].service : "Unassigned");
            print_scan_result(results[i].is_open, results[i].scan_open, ctx->flags & FLAG_OPEN);
            printf("\t%-10s\n", "Open");
        }
        else
        {
            closed_filtered_ports++;
        }
    }

    if (total_ports > 20)
    {
        printf("\nNote: Other ports are filtered or closed.\n");
    }
    else
    {
        printf("\nClosed/Filtered/Unfiltered ports:\n");
        printf("%-6s %-20s %-42s %-10s\n", "Port", "Service Name", "Results", "Conclusion");
        printf("-------------------------------------------------------------\n");

        for (int i = start_port; i <= end_port; i++)
        {
            if (results[i].any_open == false)
            {
                printf("%-6d %-20s ", i, results[i].service ? results[i].service : "Unassigned");
                print_scan_result(results[i].is_open, results[i].scan_open, ctx->flags & FLAG_OPEN);
                printf("\t%-10s\n", "Closed");
            }
        }
    }
}

/* Detect OS */
void analyze_response_patterns(int ttl, int window_size, bool df_flag)
{
    int adjusted_ttl;

    if (ttl <= 64)
    {
        adjusted_ttl = 64;
    }
    else if (ttl <= 128)
    {
        adjusted_ttl = 128;
    }
    else
    {
        adjusted_ttl = 255;
    }

    if (adjusted_ttl == 64 && (window_size == 29200 || window_size < 60000) && df_flag)
    {
        os = "Linux";
    }
    else if (adjusted_ttl == 128 && (window_size == 8192 || window_size == 65535) && df_flag)
    {
        os = "Windows";
    }
    else if (adjusted_ttl == 255 && window_size == 4128)
    {
        os = "Cisco";
    }
    else if (adjusted_ttl == 64 && window_size == 14600)
    {
        os = "FreeBSD";
    }
    else if (window_size == 0)
    {
        os = "Filtered/Complex";
    }
    else
    {
        os = "Unknown OS";
    }
}

void send_icmp_probe(const char *target_ip)
{
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock == -1)
    {
        perror("ICMP socket creation failed");
        return;
    }

    char icmp_packet[64];
    struct icmphdr *icmp_hdr = (struct icmphdr *)icmp_packet;
    memset(icmp_hdr, 0, sizeof(struct icmphdr));
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = htons(1234);
    icmp_hdr->un.echo.sequence = htons(1);
    icmp_hdr->checksum = csum((unsigned short *)icmp_packet, sizeof(icmp_packet));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &target.sin_addr);

    if (sendto(icmp_sock, icmp_packet, sizeof(icmp_packet), 0, (struct sockaddr *)&target, sizeof(target)) < 0)
    {
        perror("sendto failed (ICMP)");
    }

    close(icmp_sock);
}

void os_detection(const char *target_ip, int port, const char* source_ip)
{
    int sock;
    struct sockaddr_in server;
    char packet[PCKT_LEN];

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1)
    {
        perror("Socket creation failed");
        return;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &server.sin_addr);

    create_packet(packet, &server, port, source_ip, S_SYN);
    sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&server, sizeof(server));

    create_packet(packet, &server, port, source_ip, S_FIN);
    sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&server, sizeof(server));

    create_packet(packet, &server, port, source_ip, S_XMAS);
    sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&server, sizeof(server));

    send_icmp_probe(target_ip);

    fd_set readfds;
    struct timeval timeout;
    char buffer[1024];
    struct sockaddr_in response;
    socklen_t len = sizeof(response);
    int received;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    if (select(sock + 1, &readfds, NULL, NULL, &timeout) > 0)
    {
        if (FD_ISSET(sock, &readfds))
        {
            received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&response, &len);
            if (received >= 0)
            {
                struct iphdr *response_iph = (struct iphdr *)buffer;
                struct tcphdr *response_tcph = (struct tcphdr *)(buffer + (response_iph->ihl * 4));

                int ttl = response_iph->ttl;
                int window_size = ntohs(response_tcph->window);
                bool df_flag = (ntohs(response_iph->frag_off) & 0x4000) != 0;

                analyze_response_patterns(ttl, window_size, df_flag);
            }
        }
    }

    close(sock);
}
/* Detect OS End */

int nmap_main(nmap_context* ctx)
{
    target_t *tmp = ctx->dst;
    struct timespec start, end;
    double elapsed;
    char *source_ip = malloc(INET_ADDRSTRLEN);
    bool first_time = true;
    worker_count = ctx->speedup;
    initialize_workers();

    if (ctx->flags & FLAG_MXRATE)
        max_rate = ctx->max_rate * 1000;

    if (ctx->flags & FLAG_MNRATE)
        min_rate = ctx->min_rate * 1000;

    while (tmp)
    {
        if (!first_time)
        {
            printf("############################################################\n\n");
        }
        first_time = false;

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
                tmp = FT_LIST_GET_NEXT(&ctx->dst, tmp);
                continue;
            }
        }

        if (worker_count > 0)
        {
            if (ctx->scans & FLAG_SYN)
            {
                task_param *param_syn = (task_param*)malloc(sizeof(task_param));
                create_task_param(param_syn, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1], S_SYN);
                assign_task_to_worker(param_syn);
            }

            if (ctx->scans & FLAG_NULL)
            {
                task_param *param_null = (task_param*)malloc(sizeof(task_param));
                create_task_param(param_null, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1], S_NULL);
                assign_task_to_worker(param_null);
            }

            if (ctx->scans & FLAG_FIN)
            {
                task_param *param_fin = (task_param*)malloc(sizeof(task_param));
                create_task_param(param_fin, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1], S_FIN);
                assign_task_to_worker(param_fin);
            }

            if (ctx->scans & FLAG_XMAS)
            {
                task_param *param_xmas = (task_param*)malloc(sizeof(task_param));
                create_task_param(param_xmas, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1], S_XMAS);
                assign_task_to_worker(param_xmas);
            }

            if (ctx->scans & FLAG_ACK)
            {
                task_param *param_ack = (task_param*)malloc(sizeof(task_param));
                create_task_param(param_ack, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1], S_ACK);
                assign_task_to_worker(param_ack);
            }

            if (ctx->scans & FLAG_UDP)
            {
                task_param *param_udp = (task_param*)malloc(sizeof(task_param));
                create_task_param(param_udp, source_ip, resolved_ip, ctx->port_range[0], ctx->port_range[1], S_UDP);
                assign_task_to_worker(param_udp);
            }
            
            /* wait all workers to be done. */
            while (!(all_workers_ready()))
            {
                usleep(100000);
            }
        }
        else
        {
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

            if (ctx->scans & FLAG_UDP)
                udp(resolved_ip, ctx->port_range[0], ctx->port_range[1]);
        }
       
        for (int port = ctx->port_range[0]; port <= ctx->port_range[1]; port++)
        {
            if (results[port].any_open == true)
            {
                banner_grab(resolved_ip, port);
                if (ctx->flags & FLAG_OS)
                    os_detection(resolved_ip, port, source_ip);
            }
        }

        /* time */
        clock_gettime(CLOCK_MONOTONIC, &end);

        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        print_result(ctx, target_ip);

        printf("\nScan took %.5f secs\n", elapsed);

        tmp = FT_LIST_GET_NEXT(&ctx->dst, tmp);
    }

    shutdown_workers();

    free(source_ip);
    return 0;
}

