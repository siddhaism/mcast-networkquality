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
#define SEND_INTERVAL_S 5 // 5 seconds

int main() {
    int sockfd;
    struct sockaddr_in multicast_addr;
    char packet[PACKET_SIZE];
    long long total_bytes_sent = 0;
    struct timeval start_time, current_time;

    // Create a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set up the multicast address
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_addr.s_addr = inet_addr(MULTICAST_ADDR);
    multicast_addr.sin_port = htons(PORT);

    printf("Server sending to %s:%d\n", MULTICAST_ADDR, PORT);

    // Get the start time
    gettimeofday(&start_time, NULL);

    while (1) {
        // Send the packet
        if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&multicast_addr, sizeof(multicast_addr)) < 0) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }

        total_bytes_sent += PACKET_SIZE;

        // Get the current time
        gettimeofday(&current_time, NULL);

        // Calculate the elapsed time
        double elapsed_time = (current_time.tv_sec - start_time.tv_sec) + (current_time.tv_usec - start_time.tv_usec) / 1e6;

        if (elapsed_time >= SEND_INTERVAL_S) {
            double throughput_mbps = (total_bytes_sent * 8) / (elapsed_time * 1e6);
            printf("Throughput: %.2f Mbps\n", throughput_mbps);

            // Reset counters
            total_bytes_sent = 0;
            gettimeofday(&start_time, NULL);
        }
    }

    close(sockfd);
    return 0;
}

