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
#ifndef DEBUG_HTTP_REQUEST_PARSING
#   define DEBUG_HTTP_REQUEST_PARSING 1
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
            category""__FILE__":"expanded_macro_arg_to_str(__LINE__)":%s: " \
            fmt"\n", \
            __func__, ##__VA_ARGS__)

#define info(fmt, ...) log(0, "INFO:", fmt, ##__VA_ARGS__)
#define warn(fmt, ...) log(0, "WARNING:", fmt, ##__VA_ARGS__)
#define error(fmt, ...) log(1, "ERROR:", fmt, ##__VA_ARGS__)
#define debug(what, fmt, ...) \
    (DEBUG_##what ? log(0, "DEBUG_"#what":", fmt, ##__VA_ARGS__) : 0)
/* Use this to output messages for print-debugging that should visually
 * stand-out from the rest of the log-output. */
#define scream(fmt, ...) log(1, "", "!!!!! "fmt" !!!!!", ##__VA_ARGS__)

#define not_implemented(...) \
    (log(1, "", "NOT IMPLEMENTED! " __VA_ARGS__) && (_exit(errno), -1))

#define assert(toggle_suffix, expr, ...) \
    (ASSERT_##toggle_suffix \
        ? (expr ? 1 \
            : log(0, "ASSERT_"#toggle_suffix":", \
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
#define GET  1
#define PUT  2
#define POST 3

int parse_http_request_method(char** request, int* request_len) {
    char* r = *request; int l = *request_len;
    if (l >= 4 && r[0] == 'G' && r[1] == 'E' && r[2] == 'T' && r[3] == ' ') {
        *request += 4; *request_len -= 4;
        return GET;
    }
    if (l >= 4 && r[0] == 'P' && r[1] == 'U' && r[2] == 'T' && r[3] == ' ') {
        *request += 4; *request_len -= 4;
        return PUT;
    }
    if (l >= 5 &&
        r[0] == 'P' && r[1] == 'O' && r[2] == 'S' && r[3] == 'T' && r[4] == ' '
    ) {
        *request += 5; *request_len -= 5;
        return POST;
    }
    return -1;
}

#define NOT_IN_SERVER_DIR (-3)
#define PATH_TRUNCATED    (-36)
_Static_assert(NOT_IN_SERVER_DIR == -ESRCH, "");
_Static_assert(PATH_TRUNCATED    == -ENAMETOOLONG, "");

int parse_http_request_path(char* path_dst, char** request, int* request_len) {
    int ret = -1;

    char *rp = *request, *fp = path_dst;
    *fp++ = '/';

    while (rp - *request < *request_len) {
        char* component = rp;
        for (char c; rp - *request < *request_len &&
            (c = *rp) && (
                ('a' <= c && c <= 'z') ||
                ('A' <= c && c <= 'Z') ||
                ('0' <= c && c <= '9') ||
                (c == '_') || (c == '-') || (c == '.')
            ); ++rp);
        if (rp - *request >= *request_len) {
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
            while (fp > *request && fp[-1] != '/') { --fp; }
            if (fp <= *request) {
                fp = *request;
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
    ret = fp - path_dst;
do_return:
    *request_len -= rp - *request;
    *request      = rp;
    *fp = '\0';
    return ret;
}

int parse_only_content_length_from_http_headers(char** request, int* request_len) {
    char* r = *request; int l = *request_len;

    // Find start of HTTP-request body
    unsigned int sliding_window = 0;
    unsigned int start_of_body_sliding_window_match =
        (((unsigned int)'\r') << 24) |
        (((unsigned int)'\n') << 16) |
        (((unsigned int)'\r') <<  8) |
        (((unsigned int)'\n') <<  0);
    int body_offset = 0;
    for (; body_offset < l &&
            sliding_window != start_of_body_sliding_window_match
         ;++body_offset
    ) { sliding_window = sliding_window<<8 | (unsigned int)(r[body_offset]); }

    int ret = -1;
    if (body_offset < sizeof("Content-Length:")-1) { goto do_return; }

    int i = sizeof("Content-Length")-1;
    for (; i < body_offset && (
            r[i-14] != 'C' || r[i-13] != 'o' && r[i-12] != 'n' ||
            r[i-11] != 't' || r[i-10] != 'e' && r[i- 9] != 'n' ||
            r[i- 8] != 't' || r[i- 7] != '-' && r[i- 6] != 'L' ||
            r[i- 5] != 'e' || r[i- 4] != 'n' && r[i- 3] != 'g' ||
            r[i- 2] != 't' || r[i- 1] != 'h')
         ;++i);
    if (i >= body_offset) { goto do_return; }

    for (; i < body_offset && r[i] == ' ' || r[i] == '\t'; ++i);
    if (i >= body_offset || r[i++] != ':') { goto do_return; }

    for (; i < body_offset && r[i] == ' ' || r[i] == '\t'; ++i);
    if (i >= body_offset) { goto do_return; }

    ret = (int)(r[i++] - '0');
    if (ret < 0 || 9 < ret) { ret = -1; goto do_return; }
    for (char c; (c = r[i]) && '0' <= c && c <= '9'; ++i)
        { ret = 10*ret + (int)(c - '0'); }
do_return:
    *request     += body_offset;
    *request_len -= body_offset;
    return ret;
}

int stat_file_path_or_extended_html_file_path(
    struct stat* file_stat,
    char* file_path, int* file_path_len
) {
    int ret = stat(file_path, file_stat);
    int adjusted_len = *file_path_len;
    if (!(file_stat->st_mode & S_IFREG)) {
        if (ret != -1 && (file_stat->st_mode & S_IFDIR)) {
            file_path[adjusted_len++] = '/';
            file_path[adjusted_len++] = 'i';
            file_path[adjusted_len++] = 'n';
            file_path[adjusted_len++] = 'd';
            file_path[adjusted_len++] = 'e';
            file_path[adjusted_len++] = 'x';
        }
        file_path[adjusted_len++] = '.';
        file_path[adjusted_len++] = 'h';
        file_path[adjusted_len++] = 't';
        file_path[adjusted_len++] = 'm';
        file_path[adjusted_len++] = 'l';
        file_path[adjusted_len++] = '\0';
        ret = stat(file_path, file_stat);
    }
    if ((ret != -1) && (file_stat->st_mode & S_IFREG)) {
        *file_path_len = adjusted_len;
    } else {
        file_path[*file_path_len] = '\0';
    }
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
    IMAGE_MIME_TYPE = 0x10,
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
    [TEXT_HTML        ] = "text/html;charset=UTF-8",
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

#define FD_OF_FILE_TO_BE_SENT                          0x0000FFFF
#define SEND_HTTP_ERROR_RESPONSE_FORBIDDEN             0x01000000
#define SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND        0x02000000
#define SEND_HTTP_ERROR_RESPONSE_INTERNAL_SERVER_ERROR 0x04000000
#define SEND_HTTP_SUCCESS_RESPONSE_CREATED             0x08000000
#define SENDFILE                                       0x10000000
#define OVERWRITE_FILE_FROM_REQUEST                    0x20000000
#define FILE_SIZE                                      0x00FFFFFF
#define MIME_TYPE_MASK                                 0x7F000000
_Static_assert(                     MIME_TYPES_COUNT < 0x7F,
               "MIME_TYPE_MASK too few bits");
#define MIME_TYPE_SHIFT                                    24
#define NO_HTTP_CONTENT_LENGTH_HEADER                  0x7FFFFFFF

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

#define MIN(a, b) ((a) > (b) ? (b) : (a))

unsigned char INVALID_PTR__DONT_CRASH_ON_ACCESS[4096] = {0};
char request[1024];

void handle_client_poll_event(
    struct pollfd* pollfds, unsigned int* files_state_array, int fd
) {
    struct pollfd pollfd     =           pollfds[fd];
    unsigned int  file_state = files_state_array[fd];

    if (pollfd.revents & POLLIN) {
        int   http_method         = -1;
        char* http_method_str     = (char*)INVALID_PTR__DONT_CRASH_ON_ACCESS;
        int   http_method_str_len = -1;
        char* http_request_path     = (char*)INVALID_PTR__DONT_CRASH_ON_ACCESS;
        int   http_request_path_len = -1;
        char  http_major_version = 0;
        char  http_minor_version = 0;
        int   http_headers__content_length = -1;
        _Bool http_headers__not_fully_parsed__more_in_next_packet = (_Bool)0;
        char* http_request_body__1st_chunk_in_initial_packet =
            (char*)INVALID_PTR__DONT_CRASH_ON_ACCESS;
        int   http_request_body__1st_chunk_in_initial_packet_size = -1;

        int i = 0;

        // Read 1st Request Chunk
        //
        //  The code operates under the assumption that it is large enough to
        //  contain the full HTTP-method, HTTP-path and relevant HTTP-headers
        //
        int request_bytes_count = read(fd, request, sizeof(request)-1);
        if (request_bytes_count < -1) {
            error_errno("'read' from client socket failed!");
            close(fd);
            return;
        }
        int request_size = MIN(request_bytes_count, sizeof(request)-1);
        request[request_size     ] = '\0';
        request[sizeof(request)-1] = '\0';

        info("Request:\n%.*s", request_size, request);

        // Parse HTTP-Request Method
        http_method_str = request + i;
        const int _GET  = 0;
        const int _PUT  = 1;
        const int _POST = 2;
        if (i + 3 < request_size &&
            request[i+0] == 'G' && request[i+1] == 'E' &&
            request[i+2] == 'T' && request[i+3] == ' '
        ) {
            http_method = _GET;
            i += 4;
        } else if (i + 3 < request_size &&
            request[i+0] == 'P' && request[i+1] == 'U' &&
            request[i+2] == 'T' && request[i+3] == ' '
        ) {
            http_method = _PUT;
            i += 4;
        } else if (i + 4 < request_size &&
            request[i+0] == 'P' && request[i+1] == '0' && request[i+2] == 'S' &&
            request[i+3] == 'T' && request[i+4] == ' '
        ) {
            http_method = _POST;
            i += 5;
        } else {
            for (; i < request_size && request[i] != ' '; ++i);
            if (i != request_size)
                { http_method_str_len = (request + i) - http_method_str; }
        }

        // Parse HTTP-Request Path
        http_request_path = request + i;
        for (char c; i < request_size && (c = request[i]) && (
                ('a' <= c && c <= 'z') ||
                ('A' <= c && c <= 'Z') ||
                ('0' <= c && c <= '9') ||
                c == '/' || c == '.' || c == '-' || c == '_')
             ;++i);
        if (request[i] != ' ' && request[i] != '\r')
            { goto end_of_request_parsing; }
        http_request_path_len = (request + i) - http_request_path;
        // NOTE: This modifies the request, which may come as an unexpected
        //       side-effect. We don't loose much information because we're
        //       overwriting a space character (see path-ending condition above)
        request[i++] = '\0';
        for (;i < request_size &&
                (request[i] == ' ' || request[i] == '\r' || request[i] == '\n')
             ;++i);

        // Parse "HTTP/X[.Y]" Substring
        if (i + 5 < request_size &&
            request[i+0] == 'H' && request[i+1] == 'T' &&
            request[i+2] == 'T' && request[i+3] == 'P' &&
            request[i+4] == '/' &&
            '0' <= request[i+5] && request[i+5] <= '9'
        ) {
            i += 6;
            http_major_version = request[i-1];
            if (http_major_version == '0') {
                warn("Got HTTP-Request with major version '0', e.g. 'HTTP/0.9'. "
                     "This code is untested with this HTTP-version and many not "
                     "work!");
            } else if (http_major_version == '1') {
                // Expected case: No warnings
            } else if (http_major_version == '2' || http_major_version == '3') {
                warn("Got HTTP-Request with major version '%c'. "
                     "This code is untested with HTTP-versions above 1.1 "
                     "and may not work!", http_major_version);
            } else if (http_major_version > '3' && http_major_version <= '9') {
                warn("Got HTTP-Request with major version '%c'. "
                     "This code was written before this HTTP-version existed "
                     "and may not work!", http_major_version);
            } else {
                warn("Got invalid HTTP-Request-major-version '%c'!",
                        http_major_version);
                --i;
                http_major_version = 0;
            }

            if (i + 1 < request_size &&
                request[i+0] == '.' &&
                '0' <= request[i+1] && request[i+1] <= '9'
            ) {
                i += 2;
                http_minor_version = request[i-1];
            } else if ('0' <= http_major_version && http_major_version <= '1') {
                warn("HTTP-%c-Request missing HTTP-protocol-minor-version "
                     "Y in 'HTTP/%c.Y' (protocol/version) substring!",
                     http_major_version, http_major_version);
                // TODO: Check in RFCs, for HTTP/0.9, HTTP/1.0 and HTTP/1.1,
                //       whether omission of the minor-version is actually
                //       allowed (and should not trigger a warning in this code)
            }

            for (;i < request_size && (request[i] == ' '  ||
                                       request[i] == '\r' || request[i] == '\n')
                 ;++i);
        } else {
            warn("HTTP-Request missing 'HTTP/X[.Y]' "
                 "(protocol/version) substring!");
        }

        // Parse HTTP-Request Headers
        unsigned int sliding_window = 0;
        _Static_assert(sizeof(unsigned int) == 4,
            "'unsigned int' type has wrong size to be used for sliding window!");
        _Static_assert(
            (((unsigned int)0xFFFFFFFF) << 8) == (unsigned int)0xFFFFFF00,
            "'unsigned int' type has incorrect left-shift behavior to be used "
            "for sliding window!");
        const unsigned int END_OF_HEADERS =
            (((unsigned int)'\r') << 24) | (((unsigned int)'\n') << 16) |
            (((unsigned int)'\r') <<  8) |  ((unsigned int)'\n');
        const unsigned int CONTENT_LENGTH_HEADER_START =
            (((unsigned int)'C') << 24) | (((unsigned int)'o') << 16) |
            (((unsigned int)'n') <<  8) |  ((unsigned int)'t');
        // TODO: Check in HTTP RFCs, whether 'content-length' with lowercase 'c'
        //       is also valid and/or some browser-clients send a lowercase 'c'
        for (;i < request_size && sliding_window != END_OF_HEADERS
             ;sliding_window =
                (sliding_window << 8) | (unsigned int)(request[i++])
        ) {
            if (sliding_window == CONTENT_LENGTH_HEADER_START &&
                i + 9 < request_size &&
                request[i+0] == 'e' && request[i+1] == 'n' &&
                request[i+2] == 't' && request[i+3] == '-' &&
                request[i+4] == 'L' && request[i+5] == 'e' &&
                request[i+6] == 'n' && request[i+7] == 'g' &&
                request[i+8] == 't' && request[i+9] == 'h'
            ) {
                i += 10;
                for (;i < request_size && request[i] == ' '; ++i);
                if (i >= request_size) { break; }
                if (request[i] != ':') {
                    warn("Did not get ':' after 'Content-Length' "
                         "HTTP-header name... "
                         "Skipping 'Content-Length' header!");
                    continue;
                }
                ++i;
                for (;i < request_size && request[i] == ' '; ++i);
                if (i >= request_size) { break; }
                if (!('0' <= request[i] && request[i] <= '9')) {
                    warn("HTTP-header-value XXX in 'Content-Length: XXX' "
                         "is not an integer... "
                         "Skipping 'Content-Length' header!");
                    continue;
                }
                http_headers__content_length =
                    (unsigned int)(request[i++] - '0');
                for (char c; i < request_size && (c = request[i]) &&
                        '0' <= c && c <= '9'
                    ;++i, http_headers__content_length =
                            10*http_headers__content_length
                            + (unsigned int)(c - '0'));
            }
        }
        if (sliding_window != END_OF_HEADERS) {
            http_headers__not_fully_parsed__more_in_next_packet = (_Bool)1;
            warn("All HTTP-Headers did not fully fit into the 1st packet "
                 "(chunk read). This is NOT taken into consideration when "
                 "handling the next, subsequent packet. This may lead to "
                 "bugs!");
        }

        // Set variable values relating to the HTTP-Body's 1st chunk,
        // at the end of this request's 1st chunk, read into buffer, in above code
        if (!http_headers__not_fully_parsed__more_in_next_packet) {
            http_request_body__1st_chunk_in_initial_packet      = request + i;
            http_request_body__1st_chunk_in_initial_packet_size =
                request_size - i;
        }

    end_of_request_parsing:

        switch (http_method) {
            case _GET : debug(HTTP_REQUEST_PARSING, "HTTP-Method: GET" ); break;
            case _PUT : debug(HTTP_REQUEST_PARSING, "HTTP-Method: PUT" ); break;
            case _POST: debug(HTTP_REQUEST_PARSING, "HTTP-Method: POST"); break;
            default:
                if (http_method_str_len == -1) {
                    warn("Invalid, unterminated HTTP-Method '%.*s...'!",
                            3, http_method_str);
                } else {
                    warn("Unhandled HTTP-Method '%.*s'!",
                            http_method_str_len, http_method_str);
                }
                break;
        }
        if (http_request_path_len == -1) {
            warn("Could not parse HTTP-Request-Path '%.*s...'!",
                    100, http_request_path);
        } else {
            debug(HTTP_REQUEST_PARSING, "HTTP-Request-Path: %s",
                    http_request_path);
        }
        if (http_major_version) {
            if (http_minor_version) {
                debug(HTTP_REQUEST_PARSING, "HTTP-Version: %c.%c",
                        http_major_version, http_minor_version);
            } else {
                debug(HTTP_REQUEST_PARSING, "HTTP-Version: %c",
                        http_major_version);
            }
        }
        if (!http_headers__not_fully_parsed__more_in_next_packet) {
            if (http_request_body__1st_chunk_in_initial_packet_size < 100) {
                debug(HTTP_REQUEST_PARSING,
                      "HTTP-Body 1st chunk at end of packet: '%.*s'",
                      http_request_body__1st_chunk_in_initial_packet_size,
                      http_request_body__1st_chunk_in_initial_packet);
            } else {
                debug(HTTP_REQUEST_PARSING,
                      "HTTP-Body 1st chunk at end of packet: '%.*s'",
                      100,
                      http_request_body__1st_chunk_in_initial_packet);
            }
        }
        if (http_headers__content_length != -1) {
            debug(HTTP_REQUEST_PARSING, "HTTP 'Content-Length' Header Value: %d",
                    http_headers__content_length);
        }
    }
}

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

            handle_client_poll_event(pollfds, fds_state, fd);

            int fd_state = fds_state[fd];

            // Handle inital HTTP requests packets
            if (!fd_state && (ready_events & POLLIN)) {
                debug(POLL_EVENTS, "POLLIN on client socket %d.", fd);

                // Read first chunk of HTTP-request
                char* http_request     = scratch_buf;
                int   http_request_len =
                    read(fd, http_request, http_request_read_size);

                // Parse the HTTP-request method
                int http_request_method =
                    parse_http_request_method(&http_request, &http_request_len);
                if (http_request_method == -1) {
                    shutdown(fd, SHUT_RD);

                    info("Invalid HTTP-method!");
                    pollfds  [fd].events = POLLOUT;
                    fds_state[fd]        = SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                    continue;
                }

                // Parse the path in the HTTP-request
                int file_path_len =
                    parse_http_request_path(scratch_buf,
                                            &http_request, &http_request_len);
                if (file_path_len >= 0) {
                    file_path_len += sizeof(SERVE_DIR)-1;
                }

                if (file_path_len == NOT_IN_SERVER_DIR) {
                    shutdown(fd, SHUT_RD);

                    warn("Possibly malicious "
                         "attempted to access file "
                         "outside of server directory "
                         "file_path='%s'!\n", file_path);
                    pollfds  [fd].events = POLLOUT;
                    fds_state[fd]        = SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                    continue;
                } else if (file_path_len == PATH_TRUNCATED) {
                    shutdown(fd, SHUT_RD);

                    warn("Large HTTP-GET path '%s...' "
                         "not fully parsed to completion: "
                         "cannot service request!", file_path);
                    pollfds  [fd].events = POLLOUT;
                    fds_state[fd]        =
                        SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND;
                    continue;
                } else if (http_request_method == GET) {
                    shutdown(fd, SHUT_RD);

                    int stat_ret =
                        stat_file_path_or_extended_html_file_path(
                            &file_stat, file_path, &file_path_len);
                    if (stat_ret == -1) {
                        info("File '%s' not found.", file_path);
                        pollfds  [fd].events = POLLOUT;
                        fds_state[fd]        =
                            SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND;
                        continue;
                    }

                    enum mime_type mime_type =
                        get_mime_type_from_file_extension(
                            file_path, file_path_len);
                    debug(MIME_TYPES,
                          "Determined file '%.*s' to have MIME-type '%s'"
                          "(with index %d in mime_type_strings)",
                          file_path_len, file_path,
                          mime_type_strings[mime_type], (int)mime_type);
                    info("Serving file '%s'.", file_path);

                    int file_fd = open(file_path, O_RDONLY, 0400);
                    debug(IO, "Opened file '%s'. File descriptor is %d.",
                               file_path, file_fd);
                    fds_state[fd] = file_fd;
                    fds_state[file_fd] =
                        (file_stat.st_size & FILE_SIZE) |
                        ((unsigned int)mime_type << MIME_TYPE_SHIFT);
                    pollfds[fd].events = POLLOUT;
                    continue;
                } else if (http_request_method == PUT) {
                    int http_content_length =
                        parse_only_content_length_from_http_headers(
                            &http_request, &http_request_len);
                    debug(HTTP_REQUEST_PARSING, "http_content_length = %d",
                                                 http_content_length);

                    int stat_ret =
                        stat_file_path_or_extended_html_file_path(
                            &file_stat, file_path, &file_path_len);
                    if (stat_ret == -1) {
                        shutdown(fd, SHUT_RD);

                        info("File '%s' not found.", file_path);
                        pollfds  [fd].events = POLLOUT;
                        fds_state[fd]        =
                            SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND;
                        continue;
                    }

                    if (http_content_length == -1) {
                        warn("PUT HTTP-request to save to file '%s' "
                             "does not contain Content-Length header!",
                             file_path);
                    }

                    int file_fd = open(file_path, O_WRONLY|O_TRUNC, 0600);
                    debug(IO, "Opened file '%s'. File descriptor is %d.",
                               file_path, file_fd);
                    int len = write(file_fd, http_request, http_request_len);
                    if (len != http_request_len) {
                        shutdown(fd, SHUT_RD);

                        fds_state[file_fd] = 0;
                        close(file_fd);
                        debug(IO, "Closed file with descriptor %d.", file_fd);

                        if (errno == EACCES) {
                            warn("Access denied to file with descriptor %d.",
                                 file_fd);
                            pollfds  [fd].events = POLLOUT;
                            fds_state[fd]        =
                                SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                        } else {
                            error_errno("'write' to file with descriptor %d "
                                        "failed unexpectedly", file_fd);
                            pollfds  [fd].events = POLLOUT;
                            fds_state[fd]        =
                                SEND_HTTP_ERROR_RESPONSE_INTERNAL_SERVER_ERROR;
                        }
                        continue;
                    }

                    info("Saving edited file '%s'.", file_path);

                    debug(IO, "'write' Wrote chunk of size %d "
                              "to file with descriptor %d.", len, file_fd);
                    if ((http_content_length == -1 &&
                            http_request + len <
                            scratch_buf  + http_request_read_size
                        ) || len >= http_content_length
                    ) {
                        shutdown(fd, SHUT_RD);
                        fds_state[file_fd] = 0;
                        close(file_fd);
                        debug(IO, "Closed file with descriptor %d.", file_fd);
                        debug(IO, "'write' Completed overwriting "
                                  "file with descriptor %d "
                                  "from content received on client socket %d.",
                                  file_fd, fd);
                        pollfds  [fd].events = POLLOUT;
                        fds_state[fd]        =
                            SEND_HTTP_SUCCESS_RESPONSE_CREATED;
                        continue;
                    }

                    fds_state[fd] = file_fd;
                    if (http_content_length == -1) {
                        fds_state[file_fd] = NO_HTTP_CONTENT_LENGTH_HEADER;
                    } else {
                        fds_state[file_fd] =
                            (http_content_length - len) & FILE_SIZE;
                    }
                    continue;
                } else if (http_request_method == POST) {
                    enum mime_type mime_type =
                        get_mime_type_from_file_extension(
                            file_path, file_path_len);
                    debug(MIME_TYPES,
                          "Determined file '%.*s' to have MIME-type '%s'"
                          "(with index %d in mime_type_strings)",
                          file_path_len, file_path,
                          mime_type_strings[mime_type], (int)mime_type);
                    if (!(mime_type & IMAGE_MIME_TYPE)) {
                        warn("File '%s' has an invalid MIME-type to be created by a "
                             "HTTP-POST request. Expected an image MIME-type!",
                             file_path);
                        shutdown(fd, SHUT_RD);
                        pollfds  [fd].events = POLLOUT;
                        fds_state[fd]        =
                            SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                    }

                    int http_content_length =
                        parse_only_content_length_from_http_headers(
                            &http_request, &http_request_len);
                    debug(HTTP_REQUEST_PARSING, "http_content_length = %d",
                                                 http_content_length);

                    int file_fd = open(file_path, O_CREAT|O_WRONLY, 0600);
                    debug(IO, "Opened file '%s'. File descriptor is %d.",
                               file_path, file_fd);
                    int len = write(file_fd, http_request, http_request_len);
                    if (len != http_request_len) {
                        shutdown(fd, SHUT_RD);

                        fds_state[file_fd] = 0;
                        close(file_fd);
                        debug(IO, "Closed file with descriptor %d.", file_fd);

                        if (errno == EACCES) {
                            warn("Access denied to file with descriptor %d.",
                                 file_fd);
                            pollfds  [fd].events = POLLOUT;
                            fds_state[fd]        =
                                SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                        } else {
                            error_errno("'write' to file with descriptor %d "
                                        "failed unexpectedly", file_fd);
                            pollfds  [fd].events = POLLOUT;
                            fds_state[fd]        =
                                SEND_HTTP_ERROR_RESPONSE_INTERNAL_SERVER_ERROR;
                        }
                        continue;
                    }

                    info("Saving edited file '%s'.", file_path);

                    debug(IO, "'write' Wrote chunk of size %d "
                              "to file with descriptor %d.", len, file_fd);
                    if ((http_content_length == -1 &&
                            http_request + len <
                            scratch_buf  + http_request_read_size
                        ) || len >= http_content_length
                    ) {
                        shutdown(fd, SHUT_RD);
                        fds_state[file_fd] = 0;
                        close(file_fd);
                        debug(IO, "Closed file with descriptor %d.", file_fd);
                        debug(IO, "'write' Completed overwriting "
                                  "file with descriptor %d "
                                  "from content received on client socket %d.",
                                  file_fd, fd);
                        pollfds  [fd].events = POLLOUT;
                        fds_state[fd]        =
                            SEND_HTTP_SUCCESS_RESPONSE_CREATED;
                        continue;
                    }

                    fds_state[fd] = file_fd;
                    if (http_content_length == -1) {
                        fds_state[file_fd] = NO_HTTP_CONTENT_LENGTH_HEADER;
                    } else {
                        fds_state[file_fd] =
                            (http_content_length - len) & FILE_SIZE;
                    }
                    continue;
                } else {
                    shutdown(fd, SHUT_RD);
                    error("Unexpected case in HTTP-request handling!");
                    pollfds  [fd].events = POLLOUT;
                    fds_state[fd]        = SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                    continue;
                }
            }

            // Handle subsequent HTTP request packets, after the first
            if (fd_state && (ready_events & POLLIN)) {
                debug(POLL_EVENTS, "POLLIN on client socket %d.", fd);

                int          file_fd       = fd_state;
                unsigned int file_fd_state = fds_state[file_fd];
                int unknown_content_len =
                    file_fd_state == NO_HTTP_CONTENT_LENGTH_HEADER;

                int read_size;
                if (file_fd_state == NO_HTTP_CONTENT_LENGTH_HEADER) {
                    read_size = 1024;
                } else {
                    read_size = fds_state[file_fd] & FILE_SIZE;
                }

                int len = copy_file_range(fd, 0, file_fd, 0, read_size, 0);
                if (len == -1) {
                    shutdown(fd, SHUT_RD);
                    fds_state[file_fd] = 0;
                    close(file_fd);
                    debug(IO, "Closed file with descriptor %d.", file_fd);

                    if (errno == EACCES) {
                        warn("Access denied to file with descriptor %d.",
                             file_fd);
                        pollfds  [fd].events = POLLOUT;
                        fds_state[fd]        =
                            SEND_HTTP_ERROR_RESPONSE_FORBIDDEN;
                    } else {
                        error_errno("'copy_file_range' from client socket %d "
                                    "to file with descriptor %d "
                                    "failed unexpectedly", fd, file_fd);
                        pollfds  [fd].events = POLLOUT;
                        fds_state[fd]        =
                            SEND_HTTP_ERROR_RESPONSE_INTERNAL_SERVER_ERROR;
                    }
                    continue;
                }

                debug(IO, "'copy_file_range' Wrote chunk of size %d "
                          "to file with descriptor %d "
                          "from client socket %d.", len, file_fd, fd);
                if (len == 0 ||
                    (!unknown_content_len && (len < read_size))
                ) {
                    if (len == 0 && !unknown_content_len) {
                        warn("Client connection was closed before the number "
                             "of bytes matching the value of the HTTP "
                             "Content-Length header was received!");
                        // TODO: We should backup files at the start of PUT
                        //       requests, before we start overwriting them,
                        //       and restore the file from the backup in
                        //       situations such as these!
                    }

                    fds_state[file_fd] = 0;
                    close(file_fd);
                    debug(IO, "Closed file with descriptor %d.", file_fd);
                    debug(IO, "'copy_file_range' Completed overwriting "
                              "file with descriptor %d "
                              "from content received on client socket %d.",
                              file_fd, fd);
                    pollfds  [fd].events = POLLOUT;
                    fds_state[fd]        =
                        SEND_HTTP_SUCCESS_RESPONSE_CREATED;
                    continue;
                }

                if (!unknown_content_len) { fds_state[file_fd] -= len; }
                continue;
            }

            // HTTP-Reponse Handling
            if (ready_events & POLLOUT) {
                debug(POLL_EVENTS, "POLLOUT on client socket %d.", fd);

                if (fd_state & SEND_HTTP_ERROR_RESPONSE_FILE_NOT_FOUND) {
                    goto send_http_error_response_file_not_found;
                }
                if (fd_state & SEND_HTTP_ERROR_RESPONSE_FORBIDDEN) {
                    goto send_http_error_response_forbidden;
                }
                if (fd_state & SEND_HTTP_ERROR_RESPONSE_INTERNAL_SERVER_ERROR) {
                    goto send_http_error_response_forbidden;
                }
                if (fd_state & SEND_HTTP_SUCCESS_RESPONSE_CREATED) {
                    goto send_http_success_response_created;
                }

                int file_fd = fd_state & FD_OF_FILE_TO_BE_SENT;
                if (fd_state & SENDFILE) {
                    int len =
                        sendfile(fd, file_fd,
                                 0, fds_state[file_fd] & FILE_SIZE);
                    if (len == -1) {
                        fds_state[file_fd] = 0;
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
                        fds_state[file_fd] = 0;
                        close(file_fd);
                        debug(IO, "'sendfile' Completed sending full file "
                                  "from file with descriptor %d "
                                  "to client socket %d.", file_fd, fd);
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
                        "Connection: close\r\n"
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
                "Connection: close\r\n"
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
                "Connection: close\r\n"
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
                "Connection: close\r\n"
                "\r\n"
                "<!DOCTYPE HTML>"
                "<html><body>"
                "ERROR: Not Found (404)"
                "</body></html>";
            write(fd, response, sizeof(response));
            goto close_client_sock;
        }
        send_http_success_response_created: {
            const char response[] =
                "HTTP/1.1 201 Created\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 63\r\n"
                "Connection: close\r\n"
                "\r\n"
                "<!DOCTYPE HTML>"
                "<html><body>"
                "SUCCESS: Created (201)"
                "</body></html>";
            write(fd, response, sizeof(response));
            goto close_client_sock;
        }
        close_client_sock:
            debug(CLIENT_CONNECTIONS,
                  "Closing client connection to socket %d", fd);

            shutdown(fd, SHUT_WR);
            close(fd);

            fds_state[fd]        =  0;
            pollfds  [fd].fd    ^= -1;
            pollfds  [fd].events = POLLIN;
        }
    }
}

