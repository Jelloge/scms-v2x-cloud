#ifndef STORAGE_H
#define STORAGE_H

int ensure_cert_store(void);
int write_text_file(const char *path, const char *content);
char *read_text_file(const char *path);

#endif
