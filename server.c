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
#include <net/if.h>

#define MULTICAST_ADDR "239.0.0.1"
#define PORT 12345
#define CTRL_PORT 12346
#define PACKET_SIZE 1024
#define SEND_INTERVAL_S 5 // 5 seconds
#define CLIENT_TIMEOUT_S 1.5
#define MAX_CLIENTS 128
#define MAX_PACKETS 2000000 // Up to 2M packets per 5s interval
#define LOOP_SLEEP_NS 100000 // 100us
#define LOG_THROTTLE_S 5.0 // Rate limit logs to once per 5 seconds
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
    struct sockaddr_storage addr;  // store IPv4 or IPv6 address
    socklen_t addrlen;
    struct timeval last_seen;
};

static int sockaddr_equal_addronly(const struct sockaddr *a, const struct sockaddr *b) {
    if (a->sa_family != b->sa_family) return 0;
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *ia = (const struct sockaddr_in *)a;
        const struct sockaddr_in *ib = (const struct sockaddr_in *)b;
        return ia->sin_addr.s_addr == ib->sin_addr.s_addr;
    } else if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *ia6 = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *ib6 = (const struct sockaddr_in6 *)b;
        return memcmp(&ia6->sin6_addr, &ib6->sin6_addr, sizeof(struct in6_addr)) == 0;
    }
    return 0;
}

static int find_client(struct client_entry *clients, int count, const struct sockaddr *addr) {
    for (int i = 0; i < count; i++) {
        if (sockaddr_equal_addronly((const struct sockaddr *)&clients[i].addr, addr)) {
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
    int sockfd = -1;   // data socket (IPv4 or IPv6)
    int ctrlfd = -1;   // control socket (prefer dual-stack IPv6)
    struct sockaddr_storage multicast_addr;
    int mcast_family = AF_UNSPEC;
    struct sockaddr_in6 ctrl6_addr;
    struct sockaddr_in ctrl4_addr;
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
    const char *mcast_iface_ip = NULL; // optional interface (IPv4 addr for v4, ifname for v6)
    int always_send = 0; // if set, bypass control-plane and send unconditionally
    int verbose = 0; // verbose diagnostics
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
    struct timeval last_max_clients_log = {0, 0};
    struct timeval last_timeout_log = {0, 0};

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
        } else if (strcmp(argv[i], "--always-send") == 0) {
            always_send = 1;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--client-timeout SECONDS] [--ctrl-port PORT] [--data-port PORT] [--mcast-addr ADDR] [--ttl N] [--loop 0|1] [--iface IFACE] [--always-send] [--verbose|-v]\n", argv[0]);
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


    // Create control socket: prefer IPv6 dual-stack (unless always_send)
    if (!always_send) {
        int v6only = 0;
        ctrlfd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (ctrlfd >= 0) {
            if (setsockopt(ctrlfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
                // If disabling v6only fails, we still continue with pure v6
            }
            memset(&ctrl6_addr, 0, sizeof(ctrl6_addr));
            ctrl6_addr.sin6_family = AF_INET6;
            ctrl6_addr.sin6_addr = in6addr_any;
            ctrl6_addr.sin6_port = htons(ctrl_port);
            if (bind(ctrlfd, (struct sockaddr *)&ctrl6_addr, sizeof(ctrl6_addr)) < 0) {
                // Fallback to IPv4 control
                close(ctrlfd);
                ctrlfd = -1;
            }
        }
        if (ctrlfd < 0) {
            ctrlfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (ctrlfd < 0) {
                perror("socket (control)");
                ret = 1;
                goto cleanup;
            }
            int reuse = 1;
            setsockopt(ctrlfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
            memset(&ctrl4_addr, 0, sizeof(ctrl4_addr));
            ctrl4_addr.sin_family = AF_INET;
            ctrl4_addr.sin_addr.s_addr = htonl(INADDR_ANY);
            ctrl4_addr.sin_port = htons(ctrl_port);
            if (bind(ctrlfd, (struct sockaddr *)&ctrl4_addr, sizeof(ctrl4_addr)) < 0) {
                perror("bind (control)");
                ret = 1;
                goto cleanup;
            }
        }
    }

    // Make control socket non-blocking so it doesn't rate-limit sends
    if (!always_send && ctrlfd >= 0) {
        int flags = fcntl(ctrlfd, F_GETFL, 0);
        if (flags < 0 || fcntl(ctrlfd, F_SETFL, flags | O_NONBLOCK) < 0) {
            perror("fcntl (O_NONBLOCK)");
            ret = 1;
            goto cleanup;
        }
    }

    // Initialize packet payload to a fixed pattern
    memset(packet, 0, sizeof(packet));

    // Determine multicast address family and configure socket/options
    {
        struct in_addr maddr4;
        struct in6_addr maddr6;
        // Support IPv6 zone-id in mcast addr, e.g., ff15::1234%en0
        char addrbuf[INET6_ADDRSTRLEN + IFNAMSIZ + 4];
        strncpy(addrbuf, mcast_addr_str, sizeof(addrbuf) - 1);
        addrbuf[sizeof(addrbuf) - 1] = '\0';
        char *zone = NULL;
        char *percent = strchr(addrbuf, '%');
        if (percent) { *percent = '\0'; zone = percent + 1; }
        if (inet_pton(AF_INET, addrbuf, &maddr4) == 1) {
            mcast_family = AF_INET;
            if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("socket");
                ret = 1;
                goto cleanup;
            }
            struct sockaddr_in *dst4 = (struct sockaddr_in *)&multicast_addr;
            memset(dst4, 0, sizeof(*dst4));
            dst4->sin_family = AF_INET;
            dst4->sin_addr = maddr4;
            dst4->sin_port = htons(data_port);

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
                    fprintf(stderr, "Invalid IPv4 iface IP: %s\n", mcast_iface_ip);
                    ret = 1;
                    goto cleanup;
                }
                if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr)) < 0) {
                    perror("setsockopt (IP_MULTICAST_IF)");
                    ret = 1;
                    goto cleanup;
                }
            }
        } else if (inet_pton(AF_INET6, addrbuf, &maddr6) == 1) {
            mcast_family = AF_INET6;
            if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
                perror("socket");
                ret = 1;
                goto cleanup;
            }

            // Bind to local address to ensure socket is associated with interface
            struct sockaddr_in6 bind_addr;
            memset(&bind_addr, 0, sizeof(bind_addr));
            bind_addr.sin6_family = AF_INET6;
            bind_addr.sin6_addr = in6addr_any;
            bind_addr.sin6_port = 0; // Let OS choose ephemeral port
            if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
                perror("bind (IPv6 data socket)");
                ret = 1;
                goto cleanup;
            }

            struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&multicast_addr;
            memset(dst6, 0, sizeof(*dst6));
            dst6->sin6_family = AF_INET6;
            dst6->sin6_addr = maddr6;
            dst6->sin6_port = htons(data_port);

            int hops = mcast_ttl;
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0) {
                perror("setsockopt (IPV6_MULTICAST_HOPS)");
                ret = 1;
                goto cleanup;
            }
            unsigned int loop_uc = (unsigned int)(mcast_loop ? 1 : 0);
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop_uc, sizeof(loop_uc)) < 0) {
                perror("setsockopt (IPV6_MULTICAST_LOOP)");
                ret = 1;
                goto cleanup;
            }
            if (zone || mcast_iface_ip) {
                unsigned int ifindex = 0;
                if (zone) {
                    // zone may be numeric or ifname
                    char *endp = NULL; unsigned long z = strtoul(zone, &endp, 10);
                    if (zone[0] != '\0' && *endp == '\0') {
                        ifindex = (unsigned int)z;
                    } else {
                        ifindex = if_nametoindex(zone);
                    }
                }
                if (ifindex == 0 && mcast_iface_ip) {
                    ifindex = if_nametoindex(mcast_iface_ip);
                }
                if (ifindex == 0) {
                    fprintf(stderr, "Invalid IPv6 interface (zone '%s', iface '%s')\n", zone ? zone : "", mcast_iface_ip ? mcast_iface_ip : "");
                    ret = 1;
                    goto cleanup;
                }
                char ifname[IF_NAMESIZE];
                if (if_indextoname(ifindex, ifname)) {
                    printf("Using IPv6 multicast interface: %s (index %u)\n", ifname, ifindex);
                } else {
                    fprintf(stderr, "Warning: Could not resolve interface index %u to name\n", ifindex);
                }
                if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
                    perror("setsockopt (IPV6_MULTICAST_IF)");
                    ret = 1;
                    goto cleanup;
                }
                ((struct sockaddr_in6 *)&multicast_addr)->sin6_scope_id = ifindex; // helpful for link-local
            }
        } else {
            fprintf(stderr, "Invalid multicast address (not IPv4 or IPv6): %s\n", mcast_addr_str);
            ret = 1;
            goto cleanup;
        }
    }

    printf("Server sending to %s:%d (%s)\n", mcast_addr_str, data_port, mcast_family == AF_INET6 ? "IPv6" : "IPv4");
    if (!always_send && ctrlfd >= 0) {
        if (((struct sockaddr *)&ctrl6_addr)->sa_family == AF_INET6) {
            printf("Control listening on [::]:%d (dual-stack if supported)\n", ctrl_port);
        } else {
            printf("Control listening on 0.0.0.0:%d\n", ctrl_port);
        }
    }

    if (verbose) {
        printf("[VERBOSE] Configuration:\n");
        printf("[VERBOSE]   Client timeout: %.1f seconds\n", client_timeout_s);
        printf("[VERBOSE]   Multicast TTL/Hops: %d\n", mcast_ttl);
        printf("[VERBOSE]   Multicast loopback: %d\n", mcast_loop);
        if (always_send) {
            printf("[VERBOSE]   Mode: Always send (no control plane)\n");
        } else {
            printf("[VERBOSE]   Mode: Send only when clients connected\n");
        }
    }

    // Get the start time
    gettimeofday(&start_time, NULL);

    while (1) {
        for (;;) {
            if (always_send) break; // skip control-plane when always_send
            char buf[16];
            struct sockaddr_storage src_addr;
            socklen_t src_len = sizeof(src_addr);
            ssize_t n = recvfrom(ctrlfd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &src_len);
            if (n >= 0) {
                struct timeval now;
                gettimeofday(&now, NULL);
                int idx = find_client(clients, client_count, (struct sockaddr *)&src_addr);
                if (idx >= 0) {
                    clients[idx].last_seen = now;
                    if (verbose) {
                        char ip_str[INET6_ADDRSTRLEN];
                        int af = ((struct sockaddr *)&src_addr)->sa_family;
                        void *aptr = NULL;
                        if (af == AF_INET) aptr = &((struct sockaddr_in *)&src_addr)->sin_addr;
                        else if (af == AF_INET6) aptr = &((struct sockaddr_in6 *)&src_addr)->sin6_addr;
                        if (aptr && inet_ntop(af, aptr, ip_str, sizeof(ip_str))) {
                            printf("[VERBOSE] HELLO from existing client %s\n", ip_str);
                        }
                    }
                } else if (client_count < MAX_CLIENTS) {
                    clients[client_count].addrlen = src_len;
                    memcpy(&clients[client_count].addr, &src_addr, src_len);
                    clients[client_count].last_seen = now;
                    client_count++;
                    if (verbose) {
                        char ip_str[INET6_ADDRSTRLEN];
                        int af = ((struct sockaddr *)&src_addr)->sa_family;
                        void *aptr = NULL;
                        if (af == AF_INET) aptr = &((struct sockaddr_in *)&src_addr)->sin_addr;
                        else if (af == AF_INET6) aptr = &((struct sockaddr_in6 *)&src_addr)->sin6_addr;
                        if (aptr && inet_ntop(af, aptr, ip_str, sizeof(ip_str))) {
                            printf("[VERBOSE] New client connected: %s (total: %d)\n", ip_str, client_count);
                        }
                    }
                } else {
                    // Rate-limited logging when max clients reached
                    if (elapsed_since(&now, &last_max_clients_log) >= LOG_THROTTLE_S) {
                        char ip_str[INET6_ADDRSTRLEN];
                        void *aptr = NULL; int af = ((struct sockaddr *)&src_addr)->sa_family;
                        if (af == AF_INET) aptr = &((struct sockaddr_in *)&src_addr)->sin_addr;
                        else if (af == AF_INET6) aptr = &((struct sockaddr_in6 *)&src_addr)->sin6_addr;
                        inet_ntop(af, aptr, ip_str, sizeof(ip_str));
                        fprintf(stderr, "Max clients (%d) reached, ignoring new connections (e.g., %s)\n",
                                MAX_CLIENTS, ip_str);
                        last_max_clients_log = now;
                    }
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
        int active = always_send ? 1 : 0;
        int i = 0;
        while (i < client_count) {
            if (elapsed_since(&now, &clients[i].last_seen) <= client_timeout_s) {
                active++;
                i++;
            } else {
                // Client timed out, remove it by shifting subsequent elements
                // Rate-limited logging to avoid spam during mass disconnects
                if (elapsed_since(&now, &last_timeout_log) >= LOG_THROTTLE_S) {
                    char ip_str[INET6_ADDRSTRLEN];
                    int af = ((struct sockaddr *)&clients[i].addr)->sa_family;
                    void *aptr = NULL;
                    if (af == AF_INET) aptr = &((struct sockaddr_in *)&clients[i].addr)->sin_addr;
                    else if (af == AF_INET6) aptr = &((struct sockaddr_in6 *)&clients[i].addr)->sin6_addr;
                    inet_ntop(af, aptr, ip_str, sizeof(ip_str));
                    fprintf(stderr, "Client %s timed out (future timeouts throttled for %.0fs).\n",
                            ip_str, LOG_THROTTLE_S);
                    last_timeout_log = now;
                }
                client_count--;
                for (int j = i; j < client_count; j++) {
                    clients[j] = clients[j+1];
                }
            }
        }

        if (active > 0) {
            socklen_t dlen = (mcast_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
            if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&multicast_addr, dlen) < 0) {
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
                printf("Connected clients: %d\n", client_count);
                if (client_count > 0) {
                    printf("Client list:\n");
                    for (int i = 0; i < client_count; i++) {
                        char ip_str[INET6_ADDRSTRLEN];
                        int af = ((struct sockaddr *)&clients[i].addr)->sa_family;
                        void *aptr = NULL;
                        if (af == AF_INET) {
                            aptr = &((struct sockaddr_in *)&clients[i].addr)->sin_addr;
                        } else if (af == AF_INET6) {
                            aptr = &((struct sockaddr_in6 *)&clients[i].addr)->sin6_addr;
                        }
                        if (aptr && inet_ntop(af, aptr, ip_str, sizeof(ip_str))) {
                            printf("  [%d] %s\n", i + 1, ip_str);
                        }
                    }
                }
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
