#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

//
// Assertion and Debug-Logging Toggles
//
// (`ifndef`s allow value to be overriden from the command line)
// (Search "dtog" or "dtogs" in editor to get back here)
#ifndef ASSERT_IN_PATH_PARSING
#   define ASSERT_IN_PATH_PARSING 0
#endif
#ifndef DEBUG_MIME_TYPES
#   define DEBUG_MIME_TYPES 0
#endif
#ifndef DEBUG_IO
#   define DEBUG_IO 0
#endif
#ifndef DEBUG_POLL_EVENTS
#   define DEBUG_POLL_EVENTS 0
#endif
#ifndef DEBUG_CLIENT_CONNECTIONS
#   define DEBUG_CLIENT_CONNECTIONS 0
#endif

//
// Logging Error Handling and Assertion Helpers
//
int info_log_fd = 1, error_log_fd = 2;

#define macro_arg_to_str(x) #x
#define expanded_macro_arg_to_str(x) macro_arg_to_str(x)

#define log(to_error_log, category, fmt, ...) \
    dprintf(to_error_log ? error_log_fd : info_log_fd, \
            category":"__FILE__":"expanded_macro_arg_to_str(__LINE__)":%s: " \
            fmt"\n", \
            __func__, ##__VA_ARGS__)

#define info(fmt, ...) log(0, "INFO", fmt, ##__VA_ARGS__)
#define warn(fmt, ...) log(0, "WARNING", fmt, ##__VA_ARGS__)
#define error(fmt, ...) log(1, "ERROR", fmt, ##__VA_ARGS__)
#define debug(what, fmt, ...) \
    (DEBUG_##what ? log(0, "DEBUG_"#what, fmt, ##__VA_ARGS__) : 0)

#define assert(toggle_suffix, expr, ...) \
    (ASSERT_##toggle_suffix \
        ? (expr ? 1 \
            : log(0, "ASSERT_"#toggle_suffix, \
                  "assert(..., "#expr", ...) failed! " __VA_ARGS__)) \
        : 0)

#define error_errno(fmt, ...) \
    error(fmt": %s(%d) %s", \
        ##__VA_ARGS__, \
        strerrorname_np(errno), errno, strerrordesc_np(errno))

#define error_errno_and_exit(fmt, ...) \
    (error_errno(fmt, ##__VA_ARGS__) && (_exit(errno), -1))

long syscall_ret;
#define syscall_expr_or_crash(syscall_expr) \
    ((syscall_ret = syscall_expr) < 0 \
        ? error_errno_and_exit("Syscall expression '"#syscall_expr"' failed!") \
        : syscall_ret)
#define socket_or_crash(domain, type, protocol) \
    syscall_expr_or_crash(socket(domain, type, protocol))
#define socket_or_crash(domain, type, protocol) \
    syscall_expr_or_crash(socket(domain, type, protocol))
#define setsockopt_or_crash(sockfd, level, optname, optval, optlen) \
    syscall_expr_or_crash(setsockopt(sockfd, level, optname, optval, optlen))
#define bind_or_crash(sockfd, addr, addrlen) \
    syscall_expr_or_crash(bind(sockfd, addr, addrlen))
#define listen_or_crash(sockfd, backlog) \
    syscall_expr_or_crash(listen(sockfd, backlog))

//
// Parsing File-Paths from HTTP-Requests
//
#define NOT_IN_SERVER_DIR   (-3)
#define HTTP_METHOD_NOT_GET (-22)
#define PATH_TRUNCATED      (-36)
_Static_assert(NOT_IN_SERVER_DIR   == -ESRCH, "");
_Static_assert(HTTP_METHOD_NOT_GET == -EINVAL, "");
_Static_assert(PATH_TRUNCATED      == -ENAMETOOLONG, "");

int parse_and_normalize_file_path_from_http_get_request(
    char* http_request, int http_request_len
) {
    http_request[http_request_len] = '\0';
    char *rp = http_request, *fp = http_request;

    int ret = HTTP_METHOD_NOT_GET;
    if (http_request_len < 4) { goto do_return; }
    if (*rp++ != 'G' || *rp++ != 'E' || *rp++ != 'T' || *rp++ != ' ')
        { goto do_return; }

    *fp++ = '/';

    while (rp - http_request < http_request_len) {
        char* component = rp;
        for (char c; rp - http_request < http_request_len &&
            (c = *rp) && (
                ('a' <= c && c <= 'z') ||
                ('A' <= c && c <= 'Z') ||
                ('0' <= c && c <= '9') ||
                (c == '_') || (c == '-') || (c == '.')
            ); ++rp);
        if (rp - http_request >= http_request_len) {
            ret = PATH_TRUNCATED;
            goto do_return;
        }

        _Bool component_ends_in_slash = *rp == '/';
        *rp++ = '/';

        int component_len = rp - component;

        if (component_len == 1) {
            assert(IN_PATH_PARSING, component[0] == '/');
            // Drop empty path components
        } else if (component_len == 2 && component[0] == '.') {
            assert(IN_PATH_PARSING, component[1] == '/');
            // Drop './' path components
        } else if (component_len == 3 &&
            component[0] == '.' && component[1] == '.'
        ) {
            assert(IN_PATH_PARSING, component[2] == '/', "");
            assert(IN_PATH_PARSING, fp[-1] == '/');
            // On '../', delete the previous path component
            --fp;
            while (fp > http_request && fp[-1] != '/') { --fp; }
            if (fp <= http_request) {
                fp = http_request;
                ret = NOT_IN_SERVER_DIR;
                goto do_return;
            }
        } else {
            // Otherwise, keep the path component
            for (int i = 0; i < component_len; ++i)
                { fp[i] = component[i]; }
            fp += component_len;
        }

        if (!component_ends_in_slash) { break; }
    }
    if (fp[-1] == '/') { --fp; }
    ret = fp - http_request;
do_return:
    *fp = '\0';
    return ret;
}

//
// MIME-Types Resolution
//
enum mime_type {
    MIME_TYPE_UNKNOWN = 0,
    TEXT_HTML,
    TEXT_JAVASCRIPT,
    TEXT_CSS,
    IMAGE_JPEG,
    IMAGE_PNG,
    IMAGE_SVG,
    IMAGE_WEBP,
    IMAGE_AVIF,
    IMAGE_GIF,
    IMAGE_APNG,
    MIME_TYPES_COUNT
};
enum mime_type DEFAULT_MIME_TYPE = TEXT_HTML;

const char*const mime_type_strings[MIME_TYPES_COUNT] = {
    [MIME_TYPE_UNKNOWN] = "(unknown)",
    [TEXT_HTML        ] = "text/html",
    [TEXT_JAVASCRIPT  ] = "text/javascript",
    [TEXT_CSS         ] = "text/css",
    [IMAGE_JPEG       ] = "image/jpeg",
    [IMAGE_PNG        ] = "image/png",
    [IMAGE_SVG        ] = "image/svg+xml",
    [IMAGE_WEBP       ] = "image/webp",
    [IMAGE_AVIF       ] = "image/avif",
    [IMAGE_GIF        ] = "image/gif",
    [IMAGE_APNG       ] = "image/apng"
};

#define ENCODE_FILE_EXTENSION4(a,b,c,d) (\
    ((unsigned int)a)<<24 | ((unsigned int)b)<<16 | \
    ((unsigned int)c)<< 8 | ((unsigned int)d))
_Static_assert(sizeof(unsigned int) == 4, "");

enum mime_type get_mime_type_from_file_extension(
    char* file_path, int file_path_len
) {
    char* path = file_path;
    int   len  = file_path_len;
    unsigned int encoded_extension;
    if (len > 2 && path[len-3] == '.') {
        encoded_extension =
            ENCODE_FILE_EXTENSION4(0, 0, path[len-2], path[len-1]);
    } else if (len > 3 && path[len-4] == '.') {
        encoded_extension =
            ENCODE_FILE_EXTENSION4(0, path[len-3], path[len-2], path[len-1]);
    } else if (len > 4 && path[len-5] == '.') {
        encoded_extension =
            ENCODE_FILE_EXTENSION4(
                path[len-4], path[len-3], path[len-2], path[len-1]);
    } else {
        return MIME_TYPE_UNKNOWN;
    }
    switch (encoded_extension) {
        case ENCODE_FILE_EXTENSION4( 0,  0 ,'j','s'): return TEXT_JAVASCRIPT;
        case ENCODE_FILE_EXTENSION4( 0 ,'g','i','f'): return IMAGE_GIF;
        case ENCODE_FILE_EXTENSION4( 0 ,'c','s','s'): return TEXT_CSS;
        case ENCODE_FILE_EXTENSION4( 0 ,'j','p','g'): return IMAGE_JPEG;
        case ENCODE_FILE_EXTENSION4( 0 ,'p','n','g'): return IMAGE_PNG;
        case ENCODE_FILE_EXTENSION4( 0 ,'s','v','g'): return IMAGE_SVG;
        case ENCODE_FILE_EXTENSION4('a','p','n','g'): return IMAGE_APNG;
        case ENCODE_FILE_EXTENSION4('a','v','i','f'): return IMAGE_AVIF;
        case ENCODE_FILE_EXTENSION4('h','t','m','l'): return TEXT_HTML;
        case ENCODE_FILE_EXTENSION4('j','p','e','g'): return IMAGE_JPEG;
        case ENCODE_FILE_EXTENSION4('w','e','b','p'): return IMAGE_WEBP;
    }
    return MIME_TYPE_UNKNOWN;
}

//
// Main Web-Server Code
//

#define FD_OF_FILE_TO_BE_SENT                   0x0000FFFF
#define SEND_HTTP_ERROR_RESPONSE_FORBIDDEN      0x000F0000
#define SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND 0x00F00000
#define SENDFILE                                0x0F000000
#define FILE_SIZE                               0x00FFFFFF
#define MIME_TYPE_MASK                          0xFF000000
#define MIME_TYPE_SHIFT                             24

// Configuration
#define SERVE_DIR "srv"

#define SERVER_PORT 8080
#define SERVER_IPV4 127,0,0,1
const struct sockaddr server_addr = {AF_INET, {
    (SERVER_PORT >> 8) & 255, SERVER_PORT & 255,
    SERVER_IPV4}};
#define SERVER_LISTEN_BACKLOG 16

#define MAX_CLIENTS 256
#define MAX_FDS     512

int main(void) {
    // Preallocate memory
    const int on = 1;
    char         file_path[1024] = SERVE_DIR"\0";
    struct pollfd  pollfds[MAX_FDS];
    unsigned int fds_state[MAX_FDS];
    struct stat  file_stat;
    // Set up pointers into 
    int   serve_dir_path_len     = strlen(file_path);
    char* scratch_buf            =        file_path  + serve_dir_path_len;
    int   scratch_buf_size       = sizeof(file_path) - serve_dir_path_len;
    int   http_request_read_size = scratch_buf_size - sizeof("/index.html");
    // Initialize preallocated memory
    for (int fd = 0; fd < MAX_FDS; ++fd) {
        pollfds[fd].fd     = ~fd;
        pollfds[fd].events = POLLIN;
        fds_state[fd] = 0;
    }

    // Set up / start listening on server socket
    int server_sock = socket_or_crash(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
    pollfds[server_sock].fd = server_sock;
    setsockopt_or_crash(server_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    bind_or_crash      (server_sock, &server_addr, sizeof(server_addr));
    listen_or_crash    (server_sock, SERVER_LISTEN_BACKLOG);

    // Server Main-loop
    while (1) {
        int remaining_ready_fds_count = poll(pollfds, MAX_FDS, 0);
        for (int fd = 0; remaining_ready_fds_count && fd < MAX_FDS; ++fd) {
            int ready_events = pollfds[fd].revents;
            if (!ready_events) { continue; }
            --remaining_ready_fds_count;

            // Accept incoming client connections on the server socket
            if (fd == server_sock) {
                if (!(ready_events & POLLIN)) { continue; }
                debug(POLL_EVENTS, "POLLIN on server socket %d.", server_sock);

                int client_sock = accept4(server_sock, 0, 0, SOCK_NONBLOCK);
                debug(CLIENT_CONNECTIONS,
                      "Accepted client connection to socket %d",
                      client_sock);

                pollfds[client_sock].fd = client_sock;
                continue;
            }

            // Receive HTTP-GET requests for static files on the file system
            if (ready_events & POLLIN) {
                debug(POLL_EVENTS, "POLLIN on client socket %d.", fd);

                int len = read(fd, scratch_buf, http_request_read_size);

                int offset =
                    parse_and_normalize_file_path_from_http_get_request(
                        scratch_buf, len);
                if (offset == NOT_IN_SERVER_DIR) {
                    warn("Possibly malicious "
                         "attempted to access file "
                         "outside of server directory "
                         "file_path='%s'!\n", file_path);
                    fds_state[fd] = SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                } else if (offset == HTTP_METHOD_NOT_GET) {
                    info("HTTP-method not 'GET'.");
                    fds_state[fd] = SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                    break;
                } else if (offset == PATH_TRUNCATED) {
                    warn("Large HTTP-GET path '%s...' "
                         "not fully parsed to completion: "
                         "cannot service request!", file_path);
                    fds_state[fd] = SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND;
                } else {
                    int stat_ret = stat(file_path, &file_stat);
                    int orig_offset = offset;
                    if (!(file_stat.st_mode & S_IFREG)) {
                        if (stat_ret != -1 && (file_stat.st_mode & S_IFDIR)) {
                            scratch_buf[offset++] = '/';
                            scratch_buf[offset++] = 'i';
                            scratch_buf[offset++] = 'n';
                            scratch_buf[offset++] = 'd';
                            scratch_buf[offset++] = 'e';
                            scratch_buf[offset++] = 'x';
                        }
                        scratch_buf[offset++] = '.';
                        scratch_buf[offset++] = 'h';
                        scratch_buf[offset++] = 't';
                        scratch_buf[offset++] = 'm';
                        scratch_buf[offset++] = 'l';
                        scratch_buf[offset++] = '\0';
                        stat_ret = stat(file_path, &file_stat);
                    }
                    if (stat_ret == -1 || !(file_stat.st_mode & S_IFREG)) {
                        file_path[orig_offset] = '\0';
                        info("File '%s' not found.", file_path);
                        fds_state[fd] = SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND;
                    } else {
                        int file_fd = open(file_path, O_RDONLY, 0400);
                        debug(IO, "Opened file '%s'. File descriptor is %d.",
                                   file_path, file_fd);

                        enum mime_type mime_type =
                            get_mime_type_from_file_extension(
                                scratch_buf, offset);
                        debug(MIME_TYPES,
                              "Determined file '%.*s' to have MIME-type '%s'"
                              "(with index %d in mime_type_strings)",
                              len, scratch_buf,
                              mime_type_strings[mime_type], (int)mime_type);

                        info("Serving file '%s'.", file_path);
                        fds_state[fd] = file_fd;
                        fds_state[file_fd] =
                            (file_stat.st_size & FILE_SIZE) |
                            ((unsigned int)mime_type << MIME_TYPE_SHIFT);
                    }
                }
                shutdown(fd, SHUT_RD);
                pollfds[fd].events = POLLOUT;
                continue;
            }

            // HTTP-Reponse Handling
            if (ready_events & POLLOUT) {
                debug(POLL_EVENTS, "POLLOUT on client socket %d.", fd);

                int fd_state = fds_state[fd];
                if (fd_state & SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND) {
                    goto send_http_error_response_file_not_found;
                }
                if (fd_state & SEND_HTTP_ERROR_RESPONSE_FORBIDDEN) {
                    goto send_http_error_response_forbidden;
                }

                int file_fd = fd_state & FD_OF_FILE_TO_BE_SENT;
                if (fd_state & SENDFILE) {
                    int len =
                        sendfile(fd, file_fd,
                                 0, fds_state[file_fd] & FILE_SIZE);
                    if (len == -1) {
                        close(file_fd);
                        debug(IO, "Closed file with descriptor %d.", file_fd);

                        if (errno == EACCES) {
                            warn("Access denied to file with descriptor %d.",
                                 file_fd);
                            goto send_http_error_response_forbidden;
                        } else {
                            error_errno("'sendfile' to file with descriptor %d"
                                        "failed unexpectedly", file_fd);
                            goto send_http_error_response_internal_server_error;
                        }
                    }
                    debug(IO, "'sendfile' Sent file chunk of size %d "
                              "from file with descriptor %d "
                              "to client socket %d.", len, file_fd, fd);
                    if (((fds_state[file_fd] -= len) & FILE_SIZE) <= 0) {
                        debug(IO, "'sendfile' Completed sending full file "
                                  "from file with descriptor %d "
                                  "to client socket %d.", file_fd, fd);
                        fds_state[fd] = 0;

                        close(file_fd);
                        debug(IO, "Closed file with descriptor %d.", file_fd);

                        goto close_client_sock;
                    }
                    continue;
                } else {
                    unsigned int file_fd_state = fds_state[file_fd];
                    unsigned int file_size     = file_fd_state & FILE_SIZE;
                    enum mime_type mime_type = (enum mime_type)
                        ((file_fd_state & MIME_TYPE_MASK) >> MIME_TYPE_SHIFT);
                    if (mime_type == MIME_TYPE_UNKNOWN)
                        { mime_type = DEFAULT_MIME_TYPE; }

                    dprintf(fd,
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %d\r\n"
                        "\r\n",
                        mime_type_strings[mime_type],
                        file_size);
                    fds_state[fd] |= SENDFILE;
                    debug(IO, "Wrote HTTP-response header to client socket %d "
                              "before sending file with descriptor %d.",
                              fd, file_fd);
                    continue;
                }
            }
        send_http_error_response_internal_server_error: {
            const char response[] =
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 75\r\n"
                "\r\n"
                "<!DOCTYPE HTML>"
                "<html><body>"
                "ERROR: Internal Server Error (500)"
                "</body></html>";
            write(fd, response, sizeof(response));
            goto close_client_sock;
        }
        send_http_error_response_forbidden: {
            const char response[] =
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 63\r\n"
                "\r\n"
                "<!DOCTYPE HTML>"
                "<html><body>"
                "ERROR: Forbidden (403)"
                "</body></html>";
            write(fd, response, sizeof(response));
            goto close_client_sock;
        }
        send_http_error_response_file_not_found: {
            const char response[] =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 63\r\n"
                "\r\n"
                "<!DOCTYPE HTML>"
                "<html><body>"
                "ERROR: Not Found (404)"
                "</body></html>";
            write(fd, response, sizeof(response));
            goto close_client_sock;
        }
        close_client_sock:
            debug(CLIENT_CONNECTIONS,
                  "Closing client connection to socket %d", fd);

            shutdown(fd, SHUT_WR);
            close(fd);

            pollfds[fd].fd    ^= -1;
            pollfds[fd].events = POLLIN;
        }
    }
}

