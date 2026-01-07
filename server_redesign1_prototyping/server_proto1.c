#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>

#define write_const(fd, const_str) write(fd, ""const_str"", sizeof(const_str)-1)

int main(void) {
    int ret;

    //
    // Set up server socket
    //
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) { return errno; }

    struct sockaddr server_addr = {AF_INET, {
        (8080 >> 8), (8080 & 255),
        127,0,0,1}};
    ret = bind(server_sock, &server_addr, sizeof(server_addr));
    if (ret == -1) { return errno; }

    int sockopt_on = 1;
    ret = setsockopt(server_sock, SOL_SOCKET,
                     SO_REUSEPORT, &sockopt_on, sizeof(sockopt_on));
    if (ret == -1) { return errno; }
    sockopt_on = 1;
    ret = setsockopt(server_sock, SOL_SOCKET,
                     SO_REUSEADDR, &sockopt_on, sizeof(sockopt_on));
    if (ret == -1) { return errno; }

    ret = listen(server_sock, 10);
    if (ret == -1) { return errno; }

    printf("Server started. URL: http://%d.%d.%d.%d:%d\n",
        (int)server_addr.sa_data[2], (int)server_addr.sa_data[3],
        (int)server_addr.sa_data[4], (int)server_addr.sa_data[5],
        ((int)server_addr.sa_data[0] & 255)<<8 | ((int)server_addr.sa_data[1] & 255));


    int epollfd = epoll_create1(0);
    if (epollfd == -1) { return errno; }

    ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, server_sock,
                    &(struct epoll_event){
                        .events = EPOLLIN,
                        .data   = { .fd = server_sock}});
    if (ret == -1) { return errno; }

    struct epoll_event epoll_events[1024];
    for (;;) {
        int nfds = epoll_wait(epollfd, epoll_events, 1024, -1);
        if (nfds == -1) { write_const(1, "epoll_wait"); return errno; }

        for (int i = 0; i < nfds; ++i) {
            struct epoll_event epoll_event = epoll_events[i];
            int fd = epoll_event.data.fd;

            if (fd == server_sock) {
                int conn_sock = accept4(server_sock, 0, 0, SOCK_NONBLOCK);
                if (conn_sock == -1) { write_const(1, "accept4"); return errno; }

                ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock,
                                &(struct epoll_event){
                                    .events = EPOLLOUT,

                                    .data   = { .fd = conn_sock }});
                if (ret == -1) { write_const(1, "epoll_ctl"); return errno; }

                write_const(0, "Accepted new connection.\n");
                continue;
            }

            if (epoll_event.events & EPOLLOUT) {
                ret = write(fd, "Hello!\n", 7);
                if (ret == -1) { write_const(1, "write"); return errno; }
                close(fd);
                write_const(0, "Closed connection.\n");
            }
        }
    }

    return 0;
}

