#include "clamav.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <arpa/inet.h>

#ifndef CLAMAV_SOCKET_PATH
#define CLAMAV_SOCKET_PATH "/var/run/clamav/clamd.ctl"
#endif

#define CLAMAV_CHUNK_SIZE (256 * 1024)

#define CLAMAV_MAX_SCAN_SIZE (2ULL * 1024 * 1024 * 1024)

static int send_all(int fd, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static ssize_t recv_line(int fd, char *buf, size_t cap)
{
    size_t off = 0;
    while (off + 1 < cap) {
        char c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r == 0) break;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (c == '\n' || c == '\0') break;
        buf[off++] = c;
    }
    buf[off] = '\0';
    return (ssize_t)off;
}

clamav_verdict_t clamav_scan_buffer(
    const unsigned char *data, size_t len,
    char *signature_out, size_t signature_out_size)
{
    if (signature_out && signature_out_size > 0) {
        signature_out[0] = '\0';
    }

    if (!data && len > 0) {
        return CLAMAV_VERDICT_ERROR;
    }
    if (len > CLAMAV_MAX_SCAN_SIZE) {
        return CLAMAV_VERDICT_TOO_LARGE;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return CLAMAV_VERDICT_UNAVAILABLE;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CLAMAV_SOCKET_PATH);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return CLAMAV_VERDICT_UNAVAILABLE;
    }

    static const char CMD[] = "nINSTREAM\n";
    if (send_all(fd, CMD, sizeof(CMD) - 1) != 0) {
        close(fd);
        return CLAMAV_VERDICT_ERROR;
    }

    size_t off = 0;
    while (off < len) {
        size_t this_chunk = len - off;
        if (this_chunk > CLAMAV_CHUNK_SIZE) {
            this_chunk = CLAMAV_CHUNK_SIZE;
        }
        uint32_t nlen = htonl((uint32_t)this_chunk);
        if (send_all(fd, &nlen, 4) != 0 ||
            send_all(fd, data + off, this_chunk) != 0) {
            close(fd);
            return CLAMAV_VERDICT_ERROR;
        }
        off += this_chunk;
    }

    uint32_t zero = 0;
    if (send_all(fd, &zero, 4) != 0) {
        close(fd);
        return CLAMAV_VERDICT_ERROR;
    }

    char line[512];
    ssize_t n = recv_line(fd, line, sizeof(line));
    close(fd);
    if (n < 0 || line[0] == '\0') {
        return CLAMAV_VERDICT_ERROR;
    }

    if (strstr(line, " FOUND") != NULL) {
        if (signature_out && signature_out_size > 0) {
            const char *start = strchr(line, ':');
            const char *end   = strstr(line, " FOUND");
            if (start && end && end > start) {
                start++;
                while (*start == ' ') start++;
                size_t slen = (size_t)(end - start);
                if (slen >= signature_out_size) {
                    slen = signature_out_size - 1;
                }
                memcpy(signature_out, start, slen);
                signature_out[slen] = '\0';
            }
        }
        return CLAMAV_VERDICT_INFECTED;
    }
    if (strstr(line, " OK") != NULL) {
        return CLAMAV_VERDICT_CLEAN;
    }
    if (strstr(line, "size limit exceeded") != NULL) {
        return CLAMAV_VERDICT_TOO_LARGE;
    }
    return CLAMAV_VERDICT_ERROR;
}

struct clamav_stream {
    int fd;
    size_t bytes_sent;
    int broken;
    int oversize;
};

clamav_stream_t *clamav_stream_begin(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CLAMAV_SOCKET_PATH);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return NULL;
    }

    static const char CMD[] = "nINSTREAM\n";
    if (send_all(fd, CMD, sizeof(CMD) - 1) != 0) {
        close(fd);
        return NULL;
    }

    clamav_stream_t *s = malloc(sizeof(*s));
    if (!s) {
        close(fd);
        return NULL;
    }
    s->fd = fd;
    s->bytes_sent = 0;
    s->broken = 0;
    s->oversize = 0;
    return s;
}

int clamav_stream_feed(clamav_stream_t *s, const unsigned char *data, size_t len)
{
    if (!s || s->broken) return -1;
    if (len == 0) return 0;

    if (s->bytes_sent + len > CLAMAV_MAX_SCAN_SIZE) {
        s->broken = 1;
        s->oversize = 1;
        return -1;
    }

    uint32_t nlen = htonl((uint32_t)len);
    if (send_all(s->fd, &nlen, 4) != 0 ||
        send_all(s->fd, data, len) != 0) {
        s->broken = 1;
        return -1;
    }
    s->bytes_sent += len;
    return 0;
}

clamav_verdict_t clamav_stream_finish(clamav_stream_t *s,
                                     char *signature_out, size_t signature_out_size)
{
    if (signature_out && signature_out_size > 0) signature_out[0] = '\0';
    if (!s) return CLAMAV_VERDICT_ERROR;

    clamav_verdict_t verdict = CLAMAV_VERDICT_ERROR;

    if (s->broken) {
        verdict = s->oversize ? CLAMAV_VERDICT_TOO_LARGE : CLAMAV_VERDICT_UNAVAILABLE;
        goto done;
    }

    uint32_t zero = 0;
    if (send_all(s->fd, &zero, 4) != 0) {
        verdict = CLAMAV_VERDICT_ERROR;
        goto done;
    }

    char line[512];
    ssize_t n = recv_line(s->fd, line, sizeof(line));
    if (n < 0 || line[0] == '\0') {
        verdict = CLAMAV_VERDICT_ERROR;
        goto done;
    }

    if (strstr(line, " FOUND") != NULL) {
        if (signature_out && signature_out_size > 0) {
            const char *start = strchr(line, ':');
            const char *end   = strstr(line, " FOUND");
            if (start && end && end > start) {
                start++;
                while (*start == ' ') start++;
                size_t slen = (size_t)(end - start);
                if (slen >= signature_out_size) slen = signature_out_size - 1;
                memcpy(signature_out, start, slen);
                signature_out[slen] = '\0';
            }
        }
        verdict = CLAMAV_VERDICT_INFECTED;
    } else if (strstr(line, " OK") != NULL) {
        verdict = CLAMAV_VERDICT_CLEAN;
    } else if (strstr(line, "size limit exceeded") != NULL) {
        verdict = CLAMAV_VERDICT_TOO_LARGE;
    }

done:
    close(s->fd);
    free(s);
    return verdict;
}
