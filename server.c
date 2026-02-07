#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define MULTICAST_ADDR "239.0.0.1"
#define PORT 12345
#define CTRL_PORT 12346
#define PACKET_SIZE 1024
#define SEND_INTERVAL_S 5 // 5 seconds
#define CLIENT_TIMEOUT_S 1.5
#define MAX_CLIENTS 128
#define MAX_PACKETS 2000000 // Up to 2M packets per 5s interval
#define LOOP_SLEEP_NS 100000 // 100us
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



struct client_entry {
    in_addr_t ip;
    struct timeval last_seen;
};

static int find_client(struct client_entry *clients, int count, in_addr_t ip) {
    for (int i = 0; i < count; i++) {
        if (clients[i].ip == ip) {
            return i;
        }
    }
    return -1;
}

static double elapsed_since(const struct timeval *now, const struct timeval *then) {
    return (now->tv_sec - then->tv_sec) + (now->tv_usec - then->tv_usec) / 1e6;
}

int main(int argc, char **argv) {
    int ret = 0;
    int sockfd = -1;
    int ctrlfd = -1;
    struct sockaddr_in multicast_addr;
    struct sockaddr_in ctrl_addr;
    char packet[PACKET_SIZE];
    long long total_bytes_sent = 0;
    struct timeval start_time, current_time;
    struct client_entry clients[MAX_CLIENTS];
    int client_count = 0;
    double client_timeout_s = CLIENT_TIMEOUT_S;
    int ctrl_port = CTRL_PORT;
    int data_port = PORT;
    const char *mcast_addr_str = MULTICAST_ADDR;
    int mcast_ttl = 1;
    int mcast_loop = 1;
    const char *mcast_iface_ip = NULL; // optional interface IP
    double *inter_send_times = malloc(MAX_PACKETS * sizeof(double));
    if (inter_send_times == NULL) {
        perror("malloc");
        ret = 1;
        goto cleanup;
    }
    long send_count = 0;
    struct timeval last_send_time;
    int first_send = 1;
    int parse_error = 0; // Flag to indicate parsing errors

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--client-timeout") == 0 && i + 1 < argc) {
            client_timeout_s = strtod(argv[++i], NULL);
            if (client_timeout_s <= 0) {
                fprintf(stderr, "Error: --client-timeout must be a positive number.\n");
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
        } else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
            mcast_ttl = (int)parse_long(argv[++i], "--ttl", &parse_error);
            if (mcast_ttl < 0 || mcast_ttl > 255) {
                fprintf(stderr, "Error: --ttl must be between 0 and 255.\n");
                parse_error = 1;
            }
        } else if (strcmp(argv[i], "--loop") == 0 && i + 1 < argc) {
            mcast_loop = (int)parse_long(argv[++i], "--loop", &parse_error);
            if (mcast_loop != 0 && mcast_loop != 1) {
                fprintf(stderr, "Error: --loop must be 0 or 1.\n");
                parse_error = 1;
            }
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            mcast_iface_ip = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--client-timeout SECONDS] [--ctrl-port PORT] [--data-port PORT] [--mcast-addr ADDR] [--ttl N] [--loop 0|1] [--iface IFACE_IP]\n", argv[0]);
            ret = 0;
            goto cleanup;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            parse_error = 1;
        }
    }

    if (parse_error) {
        fprintf(stderr, "Usage: %s [--client-timeout SECONDS] [--ctrl-port PORT] [--data-port PORT] [--mcast-addr ADDR] [--ttl N] [--loop 0|1] [--iface IFACE_IP]\n", argv[0]);
        ret = 1;
        goto cleanup;
    }


    // Create a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        ret = 1;
        goto cleanup;
    }

    // Create control socket
    if ((ctrlfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket (control)");
        ret = 1;
        goto cleanup;
    }

    memset(&ctrl_addr, 0, sizeof(ctrl_addr));
    ctrl_addr.sin_family = AF_INET;
    ctrl_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ctrl_addr.sin_port = htons(ctrl_port);
    if (bind(ctrlfd, (struct sockaddr *)&ctrl_addr, sizeof(ctrl_addr)) < 0) {
        perror("bind (control)");
        ret = 1;
        goto cleanup;
    }

    // Make control socket non-blocking so it doesn't rate-limit sends
    int flags = fcntl(ctrlfd, F_GETFL, 0);
    if (flags < 0 || fcntl(ctrlfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl (O_NONBLOCK)");
        ret = 1;
        goto cleanup;
    }

    // Initialize packet payload to a fixed pattern
    memset(packet, 0, sizeof(packet));

    // Set up the multicast address
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    struct in_addr maddr;
    if (inet_aton(mcast_addr_str, &maddr) == 0) {
        fprintf(stderr, "Invalid multicast address: %s\n", mcast_addr_str);
        ret = 1;
        goto cleanup;
    }
    multicast_addr.sin_addr = maddr;
    multicast_addr.sin_port = htons(data_port);

    printf("Server sending to %s:%d\n", mcast_addr_str, data_port);
    printf("Control listening on 0.0.0.0:%d\n", ctrl_port);

    // Configure multicast options
    {
        unsigned char ttl_uc = (unsigned char)(mcast_ttl < 0 ? 0 : (mcast_ttl > 255 ? 255 : mcast_ttl));
        if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl_uc, sizeof(ttl_uc)) < 0) {
            perror("setsockopt (IP_MULTICAST_TTL)");
            ret = 1;
            goto cleanup;
        }
        unsigned char loop_uc = (unsigned char)(mcast_loop ? 1 : 0);
        if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop_uc, sizeof(loop_uc)) < 0) {
            perror("setsockopt (IP_MULTICAST_LOOP)");
            ret = 1;
            goto cleanup;
        }
        if (mcast_iface_ip) {
            struct in_addr ifaddr;
            if (inet_aton(mcast_iface_ip, &ifaddr) == 0) {
                fprintf(stderr, "Invalid iface IP: %s\n", mcast_iface_ip);
                ret = 1;
                goto cleanup;
            }
            if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr)) < 0) {
                perror("setsockopt (IP_MULTICAST_IF)");
                ret = 1;
                goto cleanup;
            }
        }
    }

    // Get the start time
    gettimeofday(&start_time, NULL);

    while (1) {
        for (;;) {
            char buf[16];
            struct sockaddr_in src_addr;
            socklen_t src_len = sizeof(src_addr);
            ssize_t n = recvfrom(ctrlfd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &src_len);
            if (n >= 0) {
                struct timeval now;
                gettimeofday(&now, NULL);
                int idx = find_client(clients, client_count, src_addr.sin_addr.s_addr);
                if (idx >= 0) {
                    clients[idx].last_seen = now;
                } else if (client_count < MAX_CLIENTS) {
                    clients[client_count].ip = src_addr.sin_addr.s_addr;
                    clients[client_count].last_seen = now;
                    client_count++;
                } else {
                    // Optionally, log that max clients has been reached
                    fprintf(stderr, "Max clients reached, ignoring new client from %s\n", inet_ntoa(src_addr.sin_addr));
                }
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }

            perror("recvfrom (control)");
            ret = 1;
            goto cleanup;
        }

        // Check for active clients and remove timed out ones
        struct timeval now;
        gettimeofday(&now, NULL);
        int active = 0;
        int i = 0;
        while (i < client_count) {
            if (elapsed_since(&now, &clients[i].last_seen) <= client_timeout_s) {
                active++;
                i++;
            } else {
                // Client timed out, remove it by shifting subsequent elements
                fprintf(stderr, "Client %s timed out.\n", inet_ntoa((struct in_addr){clients[i].ip}));
                client_count--;
                for (int j = i; j < client_count; j++) {
                    clients[j] = clients[j+1];
                }
            }
        }

        if (active > 0) {
            if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&multicast_addr, sizeof(multicast_addr)) < 0) {
                perror("sendto");
                ret = 1;
                goto cleanup;
            }
            total_bytes_sent += PACKET_SIZE;

            struct timeval send_time;
            gettimeofday(&send_time, NULL);
            if (!first_send && send_count < MAX_PACKETS) {
                double inter_send_ms = (send_time.tv_sec - last_send_time.tv_sec) * 1e3;
                inter_send_ms += (send_time.tv_usec - last_send_time.tv_usec) / 1e3;
                inter_send_times[send_count++] = inter_send_ms;
            } else if (send_count >= MAX_PACKETS) {
                // Handle the case where MAX_PACKETS is reached, e.g., log a warning
                fprintf(stderr, "Warning: MAX_PACKETS reached for inter-send times. Some data will not be recorded.\n");
            }
            last_send_time = send_time;
            first_send = 0;
        }

        // Avoid busy-spin; keep sleep small to preserve throughput
        struct timespec ts = {0, LOOP_SLEEP_NS};
        nanosleep(&ts, NULL);

        // Get the current time
        gettimeofday(&current_time, NULL);

        // Calculate the elapsed time
        double elapsed_time = (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1e6;

        if (elapsed_time >= SEND_INTERVAL_S) {
            if (total_bytes_sent > 0 || send_count > 0) {
                double throughput_mbps = (total_bytes_sent * 8) / (elapsed_time * 1e6);
                printf("Throughput: %.2f Mbps\n", throughput_mbps);

                if (send_count > 0) {
                    qsort(inter_send_times, send_count, sizeof(double), compare_doubles);
                    size_t idx50 = (size_t)((send_count - 1) * 0.50);
                    size_t idx95 = (size_t)((send_count - 1) * 0.95);
                    size_t idx99 = (size_t)((send_count - 1) * 0.99);
                    double p50 = inter_send_times[idx50];
                    double p95 = inter_send_times[idx95];
                    double p99 = inter_send_times[idx99];
                    printf("Inter-packet send (ms): p50: %.2f, p95: %.2f, p99: %.2f\n", p50, p95, p99);
                }
            }

            // Reset counters regardless
            total_bytes_sent = 0;
            send_count = 0;
            first_send = 1;
            gettimeofday(&start_time, NULL);
        }
    }

cleanup:
    if (inter_send_times) free(inter_send_times);
    if (sockfd >= 0) close(sockfd);
    if (ctrlfd >= 0) close(ctrlfd);
    return ret;
}
