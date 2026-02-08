#if defined(__linux__)
#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h> // Added for errno and ERANGE
#include <net/if.h>
#include <netdb.h>

#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

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
    int data_family = AF_UNSPEC;
    struct sockaddr_storage local_addr;
    struct ip_mreq mreq;
    struct ipv6_mreq mreq6;
    struct sockaddr_storage ctrl_dst;
    socklen_t ctrl_dst_len = 0;
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
    int verbose = 0; // verbose diagnostics
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
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--ctrl-ip IP] [--hello-interval SECONDS] [--ctrl-port PORT] [--data-port PORT] [--mcast-addr ADDR] [--iface IFACE_IP] [--rcvbuf BYTES] [--verbose|-v]\n", argv[0]);
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

    // defer creating data socket until we know address family

    // Resolve control destination and create control socket
    {
        const char *server_ip = ctrl_ip_arg;
        if (server_ip == NULL) server_ip = getenv("CTRL_SERVER_IP");
        if (server_ip == NULL) server_ip = "127.0.0.1";

        char portstr[16];
        snprintf(portstr, sizeof(portstr), "%d", ctrl_port);
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = AI_NUMERICHOST; // literal only to avoid DNS
        int gai = getaddrinfo(server_ip, portstr, &hints, &res);
        if (gai != 0) {
            fprintf(stderr, "Invalid --ctrl-ip literal '%s': %s\n", server_ip, gai_strerror(gai));
            ret = 1;
            goto cleanup;
        }
        ctrlfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (ctrlfd < 0) {
            perror("socket (control)");
            freeaddrinfo(res);
            ret = 1;
            goto cleanup;
        }
        memcpy(&ctrl_dst, res->ai_addr, res->ai_addrlen);
        ctrl_dst_len = (socklen_t)res->ai_addrlen;
        char addrbuf[INET6_ADDRSTRLEN];
        void *aptr = NULL; const char *fam = res->ai_family == AF_INET6 ? "IPv6" : "IPv4";
        if (res->ai_family == AF_INET) aptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
        else aptr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
        inet_ntop(res->ai_family, aptr, addrbuf, sizeof(addrbuf));
        printf("Control sending to %s:%d (%s)\n", addrbuf, ctrl_port, fam);
        freeaddrinfo(res);
    }

    // data socket options will be applied after creating it below (per family)

    // Determine multicast family and configure socket, bind, and join
    {
        struct in_addr maddr4; struct in6_addr maddr6;
        char addrbuf[INET6_ADDRSTRLEN + IF_NAMESIZE + 4];
        strncpy(addrbuf, mcast_addr_str, sizeof(addrbuf) - 1);
        addrbuf[sizeof(addrbuf) - 1] = '\0';
        char *zone = NULL; char *percent = strchr(addrbuf, '%');
        if (percent) { *percent = '\0'; zone = percent + 1; }
        if (inet_pton(AF_INET, addrbuf, &maddr4) == 1) {
            data_family = AF_INET;
            if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { perror("socket"); ret = 1; goto cleanup; }
            // Allow multiple sockets and configure rcvbuf
            int reuse = 1;
            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) { perror("setsockopt (SO_REUSEADDR)"); ret = 1; goto cleanup; }
#ifdef SO_REUSEPORT
            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse)) < 0) {
                fprintf(stderr, "Warning: setsockopt (SO_REUSEPORT) failed: %s. Continuing without it.\n", strerror(errno));
            }
#endif
            {
                int rcvbuf = (rcvbuf_cli > 0) ? rcvbuf_cli : (4 * 1024 * 1024);
                if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) { perror("setsockopt (SO_RCVBUF)"); }
                socklen_t optlen = sizeof(rcvbuf);
                if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen) == 0) {
                    printf("Effective SO_RCVBUF: %d bytes\n", rcvbuf);
                }
            }
            struct sockaddr_in *la = (struct sockaddr_in *)&local_addr;
            memset(la, 0, sizeof(*la));
            la->sin_family = AF_INET;
            la->sin_addr.s_addr = htonl(INADDR_ANY);
            la->sin_port = htons(data_port);
            if (bind(sockfd, (struct sockaddr *)la, sizeof(*la)) < 0) { perror("bind"); ret = 1; goto cleanup; }

            mreq.imr_multiaddr = maddr4;
            if (join_iface_ip) {
                mreq.imr_interface.s_addr = inet_addr(join_iface_ip);
            } else {
                mreq.imr_interface.s_addr = htonl(INADDR_ANY);
            }
            if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
                perror("setsockopt (IP_ADD_MEMBERSHIP)"); ret = 1; goto cleanup;
            }
        } else if (inet_pton(AF_INET6, addrbuf, &maddr6) == 1) {
            data_family = AF_INET6;

            // Resolve interface index first (needed for bind on macOS)
            unsigned int ifindex = 0;
            if (zone) {
                char *endp = NULL; unsigned long z = strtoul(zone, &endp, 10);
                if (zone[0] != '\0' && *endp == '\0') ifindex = (unsigned int)z;
                else ifindex = if_nametoindex(zone);
            }
            if (ifindex == 0 && join_iface_ip) {
                ifindex = if_nametoindex(join_iface_ip);
            }
            if (ifindex == 0) {
                fprintf(stderr, "Error: No interface specified for IPv6 multicast. Use --iface or zone ID (%%ifname) in multicast address.\n");
                ret = 1; goto cleanup;
            }
            char ifname[IF_NAMESIZE];
            if (if_indextoname(ifindex, ifname)) {
                printf("Using interface for IPv6 multicast: %s (index %u)\n", ifname, ifindex);
            }

            if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) { perror("socket"); ret = 1; goto cleanup; }

            // Set IPV6_V6ONLY to avoid dual-stack issues
            int v6only = 1;
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
                perror("setsockopt (IPV6_V6ONLY)");
            }

            // Allow multiple sockets and configure rcvbuf
            int reuse = 1;
            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) { perror("setsockopt (SO_REUSEADDR)"); ret = 1; goto cleanup; }
#ifdef SO_REUSEPORT
            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse)) < 0) {
                fprintf(stderr, "Warning: setsockopt (SO_REUSEPORT) failed: %s. Continuing without it.\n", strerror(errno));
            }
#endif
            {
                int rcvbuf = (rcvbuf_cli > 0) ? rcvbuf_cli : (4 * 1024 * 1024);
                if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) { perror("setsockopt (SO_RCVBUF)"); }
                socklen_t optlen = sizeof(rcvbuf);
                if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen) == 0) {
                    printf("Effective SO_RCVBUF: %d bytes\n", rcvbuf);
                }
            }

            // Bind to wildcard address on the specific port
            struct sockaddr_in6 *la6 = (struct sockaddr_in6 *)&local_addr;
            memset(la6, 0, sizeof(*la6));
            la6->sin6_family = AF_INET6;
            la6->sin6_addr = in6addr_any;  // Could try maddr6 here for multicast-specific bind
            la6->sin6_port = htons(data_port);
            la6->sin6_scope_id = 0;  // Use 0 for wildcard (will be specified in multicast join)
            if (bind(sockfd, (struct sockaddr *)la6, sizeof(*la6)) < 0) { perror("bind"); ret = 1; goto cleanup; }
            printf("Bound to [::]:%d\n", data_port);

            // Join multicast group
            memset(&mreq6, 0, sizeof(mreq6));
            mreq6.ipv6mr_multiaddr = maddr6;
            mreq6.ipv6mr_interface = ifindex;
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) < 0) {
                perror("setsockopt (IPV6_ADD_MEMBERSHIP)"); ret = 1; goto cleanup;
            }
            printf("Joined IPv6 multicast group on interface: %s (index %u)\n", ifname, ifindex);

            if (verbose) {
                // Display socket options for diagnostics
                int v6only = 0;
                socklen_t optlen = sizeof(v6only);
                if (getsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &optlen) == 0) {
                    printf("[VERBOSE] IPV6_V6ONLY: %d\n", v6only);
                }
                char mcast_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &maddr6, mcast_str, sizeof(mcast_str));
                printf("[VERBOSE] Multicast group: %s\n", mcast_str);
                printf("[VERBOSE] Multicast interface index: %u (%s)\n", ifindex, ifname);
            }
        } else {
            fprintf(stderr, "Invalid multicast address (not IPv4 or IPv6): %s\n", mcast_addr_str);
            ret = 1; goto cleanup;
        }
    }

    printf("Client listening on %s:%d (%s)\n", mcast_addr_str, data_port, data_family == AF_INET6 ? "IPv6" : "IPv4");

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
            struct sockaddr_storage src_addr;
            socklen_t src_len = sizeof(src_addr);
            ssize_t nbytes = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&src_addr, &src_len);
            if (nbytes < 0) {
                perror("recvfrom");
                ret = 1;
                goto cleanup;
            }

            struct timeval arrival_time;
            gettimeofday(&arrival_time, NULL);

            if (verbose && first_packet) {
                char ip_str[INET6_ADDRSTRLEN];
                int af = ((struct sockaddr *)&src_addr)->sa_family;
                void *aptr = NULL;
                if (af == AF_INET) aptr = &((struct sockaddr_in *)&src_addr)->sin_addr;
                else if (af == AF_INET6) aptr = &((struct sockaddr_in6 *)&src_addr)->sin6_addr;
                if (aptr && inet_ntop(af, aptr, ip_str, sizeof(ip_str))) {
                    printf("[VERBOSE] First packet received from %s (%zd bytes)\n", ip_str, nbytes);
                }
            }

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
            ssize_t sn = sendto(ctrlfd, msg, strlen(msg), 0, (struct sockaddr *)&ctrl_dst, ctrl_dst_len);
            if (sn < 0) {
                perror("sendto (HELLO)");
            } else if (verbose) {
                printf("[VERBOSE] Sent HELLO to control server\n");
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
            } else {
                printf("No packets received in the last %.1f seconds\n", elapsed_time);
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
