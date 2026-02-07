#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

#define MULTICAST_ADDR "239.0.0.1"
#define PORT 12345
#define CTRL_PORT 12346
#define PACKET_SIZE 1024
#define MAX_PACKETS 2000000 // Upto 2M packets per 5s interval
#define HELLO_INTERVAL_S 0.5

// For qsort
int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

int main(int argc, char **argv) {
    int sockfd;
    int ctrlfd;
    struct sockaddr_in local_addr;
    struct ip_mreq mreq;
    struct sockaddr_in ctrl_srv;
    char packet[PACKET_SIZE];
    long long total_bytes_received = 0;
    struct timeval start_time, current_time, last_packet_time, last_hello_time;
    int first_packet = 1;
    double hello_interval_s = HELLO_INTERVAL_S;
    const char *ctrl_ip_arg = NULL;
    int ctrl_port = CTRL_PORT;
    int data_port = PORT;
    const char *mcast_addr_str = MULTICAST_ADDR;
    const char *join_iface_ip = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ctrl-ip") == 0 && i + 1 < argc) {
            ctrl_ip_arg = argv[++i];
        } else if (strcmp(argv[i], "--hello-interval") == 0 && i + 1 < argc) {
            hello_interval_s = atof(argv[++i]);
        } else if (strcmp(argv[i], "--ctrl-port") == 0 && i + 1 < argc) {
            ctrl_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--data-port") == 0 && i + 1 < argc) {
            data_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--mcast-addr") == 0 && i + 1 < argc) {
            mcast_addr_str = argv[++i];
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            join_iface_ip = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--ctrl-ip IP] [--hello-interval SECONDS] [--ctrl-port PORT] [--data-port PORT] [--mcast-addr ADDR] [--iface IFACE_IP]\n", argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            fprintf(stderr, "Usage: %s [--ctrl-ip IP] [--hello-interval SECONDS] [--ctrl-port PORT] [--data-port PORT] [--mcast-addr ADDR] [--iface IFACE_IP]\n", argv[0]);
            return 1;
        }
    }

    double *inter_arrival_times = malloc(MAX_PACKETS * sizeof(double));
    if (inter_arrival_times == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    long packet_count = 0;


    // Create a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Control socket for HELLOs
    if ((ctrlfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket (control)");
        exit(EXIT_FAILURE);
    }

    const char *server_ip = ctrl_ip_arg;
    if (server_ip == NULL) {
        server_ip = getenv("CTRL_SERVER_IP");
    }
    if (server_ip == NULL) {
        server_ip = "127.0.0.1";
    }
    memset(&ctrl_srv, 0, sizeof(ctrl_srv));
    ctrl_srv.sin_family = AF_INET;
    ctrl_srv.sin_addr.s_addr = inet_addr(server_ip);
    ctrl_srv.sin_port = htons(ctrl_port);

    // Allow multiple sockets to use the same port
    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt (SO_REUSEADDR)");
        exit(EXIT_FAILURE);
    }

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt (SO_REUSEPORT)");
        exit(EXIT_FAILURE);
    }
#endif

    // Bump receive buffer to reduce drops under load
    {
        int rcvbuf = 4 * 1024 * 1024; // 4MB
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }

    // Set up the local address
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(data_port);

    // Bind to the local address
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Join the multicast group
    mreq.imr_multiaddr.s_addr = inet_addr(mcast_addr_str);
    if (join_iface_ip) {
        mreq.imr_interface.s_addr = inet_addr(join_iface_ip);
    } else {
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    }
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt (IP_ADD_MEMBERSHIP)");
        exit(EXIT_FAILURE);
    }

    printf("Client listening on %s:%d\n", mcast_addr_str, data_port);
    printf("Control sending to %s:%d (set CTRL_SERVER_IP to override)\n", server_ip, ctrl_port);

    // Get the start time
    gettimeofday(&start_time, NULL);
    last_hello_time = start_time;

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        struct timeval tv = {0, 200000}; // 200ms
        int rv = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) {
            perror("select");
            exit(EXIT_FAILURE);
        }

        if (rv > 0 && FD_ISSET(sockfd, &rfds)) {
            // Receive the packet
            struct sockaddr_in src_addr;
            socklen_t src_len = sizeof(src_addr);
            ssize_t nbytes = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&src_addr, &src_len);
            if (nbytes < 0) {
                perror("recvfrom");
                exit(EXIT_FAILURE);
            }
            
            struct timeval arrival_time;
            gettimeofday(&arrival_time, NULL);

            total_bytes_received += nbytes;

            if (!first_packet && packet_count < MAX_PACKETS) {
                double inter_arrival_time = (arrival_time.tv_sec - last_packet_time.tv_sec) * 1e3;
                inter_arrival_time += (arrival_time.tv_usec - last_packet_time.tv_usec) / 1e3;
                inter_arrival_times[packet_count++] = inter_arrival_time;
            }

            last_packet_time = arrival_time;
            first_packet = 0;
        }

        struct timeval now;
        gettimeofday(&now, NULL);
        double since_hello = (now.tv_sec - last_hello_time.tv_sec) +
                             (now.tv_usec - last_hello_time.tv_usec) / 1e6;
        if (since_hello >= hello_interval_s) {
            const char *msg = "HELLO";
            ssize_t sn = sendto(ctrlfd, msg, strlen(msg), 0, (struct sockaddr *)&ctrl_srv, sizeof(ctrl_srv));
            if (sn < 0) {
                perror("sendto (HELLO)");
            }
            last_hello_time = now;
        }

        // Get the current time
        gettimeofday(&current_time, NULL);

        // Calculate the elapsed time
        double elapsed_time = (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1e6;

        if (elapsed_time >= 5.0) { // Report every 5 seconds
            double throughput_mbps = (total_bytes_received * 8) / (elapsed_time * 1e6);
            printf("Throughput: %.2f Mbps\n", throughput_mbps);

            if (packet_count > 0) {
                qsort(inter_arrival_times, packet_count, sizeof(double), compare_doubles);
                size_t idx50 = (size_t)((packet_count - 1) * 0.50);
                size_t idx95 = (size_t)((packet_count - 1) * 0.95);
                size_t idx99 = (size_t)((packet_count - 1) * 0.99);
                double p50 = inter_arrival_times[idx50];
                double p95 = inter_arrival_times[idx95];
                double p99 = inter_arrival_times[idx99];
                printf("Inter-packet arrival (ms): p50: %.2f, p95: %.2f, p99: %.2f\n", p50, p95, p99);
            }

            // Reset counters
            total_bytes_received = 0;
            packet_count = 0;
            first_packet = 1;
            gettimeofday(&start_time, NULL);
        }
    }

    free(inter_arrival_times);
    close(sockfd);
    close(ctrlfd);
    return 0;
}
