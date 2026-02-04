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
#define PACKET_SIZE 1024
#define MAX_PACKETS 2000000 // Upto 2M packets per 5s interval

// For qsort
int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

int main() {
    int sockfd;
    struct sockaddr_in local_addr;
    struct ip_mreq mreq;
    char packet[PACKET_SIZE];
    long long total_bytes_received = 0;
    struct timeval start_time, current_time, last_packet_time;
    socklen_t addr_len = sizeof(local_addr);
    int first_packet = 1;

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

    // Allow multiple sockets to use the same port
    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt (SO_REUSEADDR)");
        exit(EXIT_FAILURE);
    }

    // Set up the local address
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(PORT);

    // Bind to the local address
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Join the multicast group
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt (IP_ADD_MEMBERSHIP)");
        exit(EXIT_FAILURE);
    }

    printf("Client listening on %s:%d\n", MULTICAST_ADDR, PORT);

    // Get the start time
    gettimeofday(&start_time, NULL);

    while (1) {
        // Receive the packet
        ssize_t nbytes = recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&local_addr, &addr_len);
        if (nbytes < 0) {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }
        
        struct timeval arrival_time;
        gettimeofday(&arrival_time, NULL);


        total_bytes_received += nbytes;

        if (!first_packet && packet_count < MAX_PACKETS) {
            double inter_arrival_time = (arrival_time.tv_sec - last_packet_time.tv_sec) * 1e6;
            inter_arrival_time += (arrival_time.tv_usec - last_packet_time.tv_usec);
            inter_arrival_times[packet_count++] = inter_arrival_time;
        }


        last_packet_time = arrival_time;
        first_packet = 0;


        // Get the current time
        gettimeofday(&current_time, NULL);

        // Calculate the elapsed time
        double elapsed_time = (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1e6;

        if (elapsed_time >= 5.0) { // Report every 5 seconds
            double throughput_mbps = (total_bytes_received * 8) / (elapsed_time * 1e6);
            printf("Throughput: %.2f Mbps\n", throughput_mbps);

            if (packet_count > 0) {
                qsort(inter_arrival_times, packet_count, sizeof(double), compare_doubles);
                double p50 = inter_arrival_times[(int)(packet_count * 0.50)];
                double p95 = inter_arrival_times[(int)(packet_count * 0.95)];
                double p99 = inter_arrival_times[(int)(packet_count * 0.99)];
                printf("Inter-packet arrival (us): p50: %.2f, p95: %.2f, p99: %.2f\n", p50, p95, p99);
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
    return 0;
}