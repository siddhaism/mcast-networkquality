#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h> // Added for errno and ERANGE

#define MULTICAST_ADDR "239.0.0.1"
#define PORT 12345
#define CTRL_PORT 12346
#define PACKET_SIZE 1024
#define MAX_PACKETS 2000000 // Upto 2M packets per 5s interval
#define HELLO_INTERVAL_S 0.5
#include "common.h" // Include common.h
#include <limits.h> // For LONG_MIN, LONG_MAX

static long parse_long(const char *s, const char *arg_name, int *error_flag) {
    char *endptr;
    long val = strtol(s, &endptr, 10);

    if (endptr == s || *endptr != '\0') {
        fprintf(stderr, "Error: Invalid number for %s: %s\n", arg_name, s);
        *error_flag = 1;
        return 0; // Or some other appropriate error value
    }

    if ((val == LONG_MIN || val == LONG_MAX) && errno == ERANGE) {
        fprintf(stderr, "Error: Value out of range for %s: %s\n", arg_name, s);
        *error_flag = 1;
        return 0;
    }
    return val;
}
int main(int argc, char **argv) {
    int ret = 0;
    int sockfd = -1;
    int ctrlfd = -1;
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
    int rcvbuf_cli = -1; // optional CLI override
    int parse_error = 0; // Flag to indicate parsing errors
    double *inter_arrival_times = NULL; // Declared and initialized here


    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ctrl-ip") == 0 && i + 1 < argc) {
            ctrl_ip_arg = argv[++i];
        } else if (strcmp(argv[i], "--hello-interval") == 0 && i + 1 < argc) {
            hello_interval_s = strtod(argv[++i], NULL);
            if (hello_interval_s <= 0) {
                fprintf(stderr, "Error: --hello-interval must be a positive number.\n");
                parse_error = 1;
            }
        } else if (strcmp(argv[i], "--ctrl-port") == 0 && i + 1 < argc) {
            ctrl_port = (int)parse_long(argv[++i], "--ctrl-port", &parse_error);
            if (ctrl_port <= 0 || ctrl_port > 65535) {
                fprintf(stderr, "Error: --ctrl-port must be between 1 and 65535.\n");
                parse_error = 1;
            }
        } else if (strcmp(argv[i], "--data-port") == 0 && i + 1 < argc) {
            data_port = (int)parse_long(argv[++i], "--data-port", &parse_error);
            if (data_port <= 0 || data_port > 65535) {
                fprintf(stderr, "Error: --data-port must be between 1 and 65535.\n");
                parse_error = 1;
            }
        } else if (strcmp(argv[i], "--mcast-addr") == 0 && i + 1 < argc) {
            mcast_addr_str = argv[++i];
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            join_iface_ip = argv[++i];
        } else if (strcmp(argv[i], "--rcvbuf") == 0 && i + 1 < argc) {
            rcvbuf_cli = (int)parse_long(argv[++i], "--rcvbuf", &parse_error);
            if (rcvbuf_cli < 0) { // rcvbuf can be 0, but generally not useful
                fprintf(stderr, "Error: --rcvbuf must be a non-negative number.\n");
                parse_error = 1;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--ctrl-ip IP] [--hello-interval SECONDS] [--ctrl-port PORT] [--data-port PORT] [--mcast-addr ADDR] [--iface IFACE_IP] [--rcvbuf BYTES]\n", argv[0]);
            ret = 0;
            goto cleanup;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            parse_error = 1;
        }
    }

    if (parse_error) {
        fprintf(stderr, "Usage: %s [--ctrl-ip IP] [--hello-interval SECONDS] [--ctrl-port PORT] [--data-port PORT] [--mcast-addr ADDR] [--iface IFACE_IP] [--rcvbuf BYTES]\n", argv[0]);
        ret = 1;
        goto cleanup;
    }

    inter_arrival_times = malloc(MAX_PACKETS * sizeof(double));
    if (inter_arrival_times == NULL) {
        perror("malloc");
        ret = 1;
        goto cleanup;
    }
    long packet_count = 0;



    // Create a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        ret = 1;
        goto cleanup;
    }

    // Control socket for HELLOs
    if ((ctrlfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket (control)");
        ret = 1;
        goto cleanup;
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
        ret = 1;
        goto cleanup;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse)) < 0) {
        fprintf(stderr, "Warning: setsockopt (SO_REUSEPORT) failed: %s. Continuing without it.\n", strerror(errno));
    }
#endif

    // Configure receive buffer
    {
        int rcvbuf = (rcvbuf_cli > 0) ? rcvbuf_cli : (4 * 1024 * 1024); // default 4MB
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
            perror("setsockopt (SO_RCVBUF)");
        }
        socklen_t optlen = sizeof(rcvbuf);
        if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen) == 0) {
            printf("Effective SO_RCVBUF: %d bytes\n", rcvbuf);
        }
    }

    // Set up the local address
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(data_port);

    // Bind to the local address
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind");
        ret = 1;
        goto cleanup;
    }

    // Join the multicast group
    struct in_addr maddr;
    if (inet_aton(mcast_addr_str, &maddr) == 0) {
        fprintf(stderr, "Invalid multicast address: %s\n", mcast_addr_str);
        ret = 1;
        goto cleanup;
    }
    mreq.imr_multiaddr = maddr;
    if (join_iface_ip) {
        mreq.imr_interface.s_addr = inet_addr(join_iface_ip);
    } else {
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    }
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt (IP_ADD_MEMBERSHIP)");
        ret = 1;
        goto cleanup;
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

        struct timeval now;
        gettimeofday(&now, NULL);
        double since_hello = (now.tv_sec - last_hello_time.tv_sec) +
                             (now.tv_usec - last_hello_time.tv_usec) / 1e6;
        double time_to_next_hello = hello_interval_s - since_hello;

        struct timeval tv;
        if (time_to_next_hello <= 0) {
            tv.tv_sec = 0;
            tv.tv_usec = 0; // Send hello immediately
        } else {
            tv.tv_sec = (time_t)time_to_next_hello;
            tv.tv_usec = (suseconds_t)((time_to_next_hello - tv.tv_sec) * 1e6);
        }

        // Ensure a minimum timeout to avoid busy-waiting if time_to_next_hello is very small
        if (tv.tv_sec == 0 && tv.tv_usec == 0) {
            tv.tv_usec = 10000; // 10ms minimum timeout
        }

        int rv = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) {
            perror("select");
            ret = 1;
            goto cleanup;
        }

        if (rv > 0 && FD_ISSET(sockfd, &rfds)) {
            // Receive the packet
            struct sockaddr_in src_addr;
            socklen_t src_len = sizeof(src_addr);
            ssize_t nbytes = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&src_addr, &src_len);
            if (nbytes < 0) {
                perror("recvfrom");
                ret = 1;
                goto cleanup;
            }
            
            struct timeval arrival_time;
            gettimeofday(&arrival_time, NULL);

            total_bytes_received += nbytes;

            if (!first_packet && packet_count < MAX_PACKETS) {
                double inter_arrival_time = (arrival_time.tv_sec - last_packet_time.tv_sec) * 1e3;
                inter_arrival_time += (arrival_time.tv_usec - last_packet_time.tv_usec) / 1e3;
                inter_arrival_times[packet_count++] = inter_arrival_time;
            } else if (packet_count >= MAX_PACKETS) {
                fprintf(stderr, "Warning: MAX_PACKETS reached for inter-arrival times. Some data will not be recorded.\n");
            }

            last_packet_time = arrival_time;
            first_packet = 0;
        }

        // Recompute now after select to avoid stale timing
        gettimeofday(&now, NULL);
        since_hello = (now.tv_sec - last_hello_time.tv_sec) +
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
            if (total_bytes_received > 0 || packet_count > 0) {
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
            }

            // Reset counters
            total_bytes_received = 0;
            packet_count = 0;
            first_packet = 1;
            gettimeofday(&start_time, NULL);
        }
    }

cleanup:
    if (inter_arrival_times) free(inter_arrival_times);
    if (sockfd >= 0) close(sockfd);
    if (ctrlfd >= 0) close(ctrlfd);
    return ret;
}
