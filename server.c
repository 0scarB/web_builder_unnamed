#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

//
// Parsing File-Paths from HTTP-Requests
//
#define FILE_NOT_FOUND      (-2)
#define NOT_IN_SERVER_DIR   (-3)
#define HTTP_METHOD_NOT_GET (-22)
#define PATH_TRUNCATED      (-36)
_Static_assert(FILE_NOT_FOUND      == -ENOENT, "");
_Static_assert(NOT_IN_SERVER_DIR   == -ESRCH, "");
_Static_assert(HTTP_METHOD_NOT_GET == -EINVAL, "");
_Static_assert(PATH_TRUNCATED      == -ENAMETOOLONG, "");

int find_file_from_http_get_request(
    char* in_out_buf, int* in_out_len, struct stat* file_stat
) {
    const int SUCCESS = 0;
    int ret = FILE_NOT_FOUND;
    int http_request_len = *in_out_len;

    // Parse HTTP 'GET' method at start of HTTP request
    int i = 0;
    if (http_request_len < 4   ||
        in_out_buf[i++] != 'G' ||
        in_out_buf[i++] != 'E' ||
        in_out_buf[i++] != 'T' ||
        in_out_buf[i++] != ' '
    ) { return HTTP_METHOD_NOT_GET; }

    // Parse path to file after 'GET ' in HTTP request
    int file_path_len = 0;
    if (in_out_buf[i] == '/') {
        in_out_buf[file_path_len++] = '.';
    }
    char c;
    while (i < http_request_len && (c = in_out_buf[i]) && (
        ('a' <= c && c <= 'z') ||
        ('A' <= c && c <= 'Z') ||
        ('0' <= c && c <= '9') ||
        c == '/' || c == '-' || c == '_' || c == '.'
    )) { in_out_buf[file_path_len++] = c; ++i; }
    if (in_out_buf[file_path_len-1] == '/') {
        --file_path_len;
        --i;
    }
    int orig_file_path_len = file_path_len;

    // Disallow '..' and '//' in paths that could allow access to files
    // outside the server's directory
    for (int j = 1; j < file_path_len; ++j) {
        if ((in_out_buf[j-1] == '.' && in_out_buf[j] == '.') ||
            (in_out_buf[j-1] == '/' && in_out_buf[j] == '/')
        ) { ret = NOT_IN_SERVER_DIR; goto do_return; }
    }

    if (i >= http_request_len) {
        // TODO: Better handling of very long paths
        ret = PATH_TRUNCATED; goto do_return;
    }

    // Return if the file path points to regular file
    in_out_buf[file_path_len] = '\0';
    int stat_result = stat(in_out_buf, file_stat);
    if (stat_result != -1 && (file_stat->st_mode & S_IFREG))
        { ret = SUCCESS; goto do_return; }

    // Try again with implicit extensions, for HTML-files, to the file path.
    // Return if the extended file path points to a regular file.
    // The implicit file path extensions are '/index.html' or '.html'.
    // '/index.html' is chosen if the original file path pointed to a directory.
    if (file_stat->st_mode & S_IFDIR) {
        in_out_buf[file_path_len++] = '/';
        in_out_buf[file_path_len++] = 'i';
        in_out_buf[file_path_len++] = 'n';
        in_out_buf[file_path_len++] = 'd';
        in_out_buf[file_path_len++] = 'e';
        in_out_buf[file_path_len++] = 'x';
    }
    in_out_buf[file_path_len++] = '.';
    in_out_buf[file_path_len++] = 'h';
    in_out_buf[file_path_len++] = 't';
    in_out_buf[file_path_len++] = 'm';
    in_out_buf[file_path_len++] = 'l';
    in_out_buf[file_path_len] = '\0';
    stat_result = stat(in_out_buf, file_stat);
    if (stat_result != -1 && (file_stat->st_mode & S_IFREG))
        { ret = SUCCESS; goto do_return; }

do_return:
    if (ret < 0) { file_path_len = orig_file_path_len; }
    *in_out_len = file_path_len;
    in_out_buf[file_path_len] = '\0';
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
    [TEXT_HTML      ] = "text/html",
    [TEXT_JAVASCRIPT] = "text/javascript",
    [TEXT_CSS       ] = "text/css",
    [IMAGE_JPEG     ] = "image/jpeg",
    [IMAGE_PNG      ] = "image/png",
    [IMAGE_SVG      ] = "image/svg+xml",
    [IMAGE_WEBP     ] = "image/webp",
    [IMAGE_AVIF     ] = "image/avif",
    [IMAGE_GIF      ] = "image/gif",
    [IMAGE_APNG     ] = "image/apng"
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
#define SERVER_PORT           8080
#define SERVER_IPV4           127,0,0,1
#define SERVER_LISTEN_BACKLOG 16

#define MAX_CLIENTS 256
#define MAX_FDS     512

#define FD_OF_FILE_TO_BE_SENT                   0x0000FFFF
#define SEND_HTTP_ERROR_RESPONSE_FORBIDDEN      0x000F0000
#define SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND 0x00F00000
#define SENDFILE                                0x0F000000
#define FILE_SIZE                               0x00FFFFFF
#define MIME_TYPE_MASK                          0xFF000000
#define MIME_TYPE_SHIFT                             24

// Scratch buffer declared here, at file scope, so it will by allocated in the
// .bss or .data section, making it unlikely to clobber the stack in most
// compilation configurations, making overflow bugs less likely to be exploited
// to produce malicious behaviour... better to crash than let clients get pwned
static char scratch_buf[2048];

int main(void) {
    struct pollfd  pollfds[MAX_FDS];
    unsigned int fds_state[MAX_FDS];
    struct stat  file_stat;

    const int HTTP_REQUEST_READ_SIZE = sizeof(scratch_buf)>>1;

    // Initialize state
    for (int fd = 0; fd < MAX_FDS; ++fd) {
        pollfds[fd].fd     = ~fd;
        pollfds[fd].events = POLLIN;
        fds_state[fd] = 0;
    }

    // Set up server socket
    int server_sock = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
    setsockopt(server_sock, SOL_SOCKET,
               SO_REUSEADDR, &(int[1]){1}, sizeof(int));
    struct sockaddr server_addr = {AF_INET, {
        (SERVER_PORT >> 8) & 255, SERVER_PORT & 255,
        SERVER_IPV4}};
    bind(server_sock, &server_addr, sizeof(server_addr));
    listen(server_sock, SERVER_LISTEN_BACKLOG);
    pollfds[server_sock].fd = server_sock;

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
                printf("INFO: POLLIN on server socket %d.\n", server_sock);
                int client_sock = accept4(server_sock, 0, 0, SOCK_NONBLOCK);
                printf("INFO: Accepted client connection to socket %d.\n",
                        client_sock);
                pollfds[client_sock].fd = client_sock;
                continue;
            }

            // Receive HTTP-GET requests for static files on the file system
            if (ready_events & POLLIN) {
                printf("INFO: POLLIN on client socket %d.\n", fd);
                int len = read(fd, scratch_buf, HTTP_REQUEST_READ_SIZE);
                switch (find_file_from_http_get_request(
                            scratch_buf, &len, &file_stat)
                ) {
                    case FILE_NOT_FOUND:
                        printf("INFO: File '%.*s' not found.\n",
                                len, scratch_buf);
                        fds_state[fd] = SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND;
                        break;
                    case NOT_IN_SERVER_DIR:
                        fprintf(stderr,
                                "WARNING: Possibly malicious "
                                "attempted to access file "
                                "outside of server directory "
                                "file_path='%.*s'!\n", len, scratch_buf);
                        fds_state[fd] = SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                        break;
                    case HTTP_METHOD_NOT_GET:
                        printf("INFO: Invalid HTTP-GET request.\n");
                        fds_state[fd] = SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                        break;
                    case PATH_TRUNCATED:
                        fprintf(stderr,
                            "WARNING: Large HTTP-GET path '%.*s...' "
                            "not fully parsed to completion: "
                            "cannot service request!", len, scratch_buf);
                        fds_state[fd] = SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND;
                        break;
                    default:
                        printf("INFO: Parsed file path '%.*s' "
                                "from HTTP-GET request.\n",
                                len, scratch_buf);
                        int file_fd = open(scratch_buf, O_RDONLY, 0400);
                        fds_state[fd] = file_fd;
                        fds_state[file_fd] =
                            (file_stat.st_size & FILE_SIZE) |
                            ((unsigned int)get_mime_type_from_file_extension(
                                                scratch_buf, len)
                                << MIME_TYPE_SHIFT);
                }
                shutdown(fd, SHUT_RD);
                pollfds[fd].events = POLLOUT;
                continue;
            }

            // HTTP-Reponse Handling
            if (ready_events & POLLOUT) {
                printf("INFO: POLLOUT on client socket %d.\n", fd);
                int fd_state = fds_state[fd];
                if (fd_state & SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND) {
                    goto send_http_error_response_file_not_found;
                }
                if (fd_state & SEND_HTTP_ERROR_RESPONSE_FORBIDDEN) {
                    goto send_http_error_response_forbidden;
                }

                int file_fd = fd_state & FD_OF_FILE_TO_BE_SENT;
                if (fd_state & SENDFILE) {
                    printf("INFO: 'sendfile' from file descriptor %d "
                            "to client socket %d.\n", file_fd, fd);

                    int len =
                        sendfile(fd, file_fd,
                                 0, fds_state[file_fd] & FILE_SIZE);
                    if (len == -1) {
                        fprintf(stderr,
                                "WARNING: 'sendfile' from client socket %d "
                                "failed with errno=%d!\n", fd, errno);
                        close(file_fd);
                        if (errno == EACCES) {
                            goto send_http_error_response_forbidden;
                        } else {
                            goto send_http_error_response_internal_server_error;
                        }
                    }

                    if (((fds_state[file_fd] -= len) & FILE_SIZE) <= 0) {
                        printf("INFO: 'sendfile' from client socket %d "
                                "complete.\n", fd);
                        fds_state[fd] = 0;
                        close(file_fd);
                        goto close_client_sock;
                    }
                    continue;
                } else {
                    printf("INFO: Sending HTTP-response header, "
                            "before sendfile, "
                            "to client socket %d.\n", file_fd);

                    unsigned int file_fd_state = fds_state[file_fd];
                    unsigned int file_size     = file_fd_state & FILE_SIZE;
                    enum mime_type mime_type = (enum mime_type)
                        ((file_fd_state & MIME_TYPE_MASK) >> MIME_TYPE_SHIFT);
                    if (mime_type == MIME_TYPE_UNKNOWN)
                        { mime_type = DEFAULT_MIME_TYPE; }

                    int len = snprintf(
                        scratch_buf, sizeof(scratch_buf)-1,
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %d\r\n"
                        "\r\n",
                        mime_type_strings[mime_type],
                        file_size
                    );
                    write(fd, scratch_buf, len);
                    fds_state[fd] |= SENDFILE;
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
            shutdown(fd, SHUT_WR);
            close(fd);

            pollfds[fd].fd    ^= -1;
            pollfds[fd].events = POLLIN;
        }
    }
}

