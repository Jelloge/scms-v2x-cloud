#include "storage.h"
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

int ensure_cert_store(const char *dir) {
#ifdef _WIN32
    if (mkdir(dir) == 0 || errno == EEXIST) {
#else
    if (mkdir(dir, 0700) == 0 || errno == EEXIST) {
#endif
        return 0;
    }
    perror("mkdir cert_store");
    return -1;
}

int write_text_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    size_t len = strlen(content);
    int ok = fwrite(content, 1, len, f) == len ? 0 : -1;
    fclose(f);
    return ok;
}

char *read_text_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    char *buf = calloc((size_t) sz + 1, 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t) sz, f);
    if (n != (size_t) sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    return buf;
}
