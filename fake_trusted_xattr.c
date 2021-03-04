#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>

static ssize_t (*libc_getxattr)(const char *path, const char *name,
                                 void *value, size_t size) = NULL;
static ssize_t (*libc_lgetxattr)(const char *path, const char *name,
                                 void *value, size_t size) = NULL;
static ssize_t (*libc_fgetxattr)(int fd, const char *name,
                                 void *value, size_t size) = NULL;
static int (*libc_setxattr)(const char *path, const char *name,
                            const void *value, size_t size, int flags) = NULL;
static int (*libc_lsetxattr)(const char *path, const char *name,
                             const void *value, size_t size, int flags) = NULL;
static int (*libc_fsetxattr)(int fd, const char *name,
                             const void *value, size_t size, int flags) = NULL;
static int (*libc_removexattr)(const char *path, const char *name) = NULL;
static int (*libc_lremovexattr)(const char *path, const char *name) = NULL;
static int (*libc_fremovexattr)(int fd, const char *name) = NULL;
static ssize_t (*libc_listxattr)(const char *path, char *list, size_t size) = NULL;
static ssize_t (*libc_llistxattr)(const char *path, char *list, size_t size) = NULL;
static ssize_t (*libc_flistxattr)(int fd, char *list, size_t size) = NULL;

void __attribute__ ((constructor)) overridexattr_init(void);

void overridexattr_init() {
  if (libc_fgetxattr)
    return;
  libc_fgetxattr = dlsym(RTLD_NEXT, "fgetxattr");
  libc_getxattr = dlsym(RTLD_NEXT, "getxattr");
  libc_lgetxattr = dlsym(RTLD_NEXT, "lgetxattr");
  libc_fsetxattr = dlsym(RTLD_NEXT, "fsetxattr");
  libc_setxattr = dlsym(RTLD_NEXT, "setxattr");
  libc_lsetxattr = dlsym(RTLD_NEXT, "lsetxattr");
  libc_fremovexattr = dlsym(RTLD_NEXT, "fremovexattr");
  libc_removexattr = dlsym(RTLD_NEXT, "removexattr");
  libc_lremovexattr = dlsym(RTLD_NEXT, "lremovexattr");
  libc_flistxattr = dlsym(RTLD_NEXT, "flistxattr");
  libc_listxattr = dlsym(RTLD_NEXT, "listxattr");
  libc_llistxattr = dlsym(RTLD_NEXT, "llistxattr");
  if (libc_fgetxattr == NULL || libc_getxattr == NULL ||
      libc_lgetxattr == NULL || libc_fsetxattr == NULL ||
      libc_setxattr == NULL || libc_lsetxattr == NULL ||
      libc_fremovexattr == NULL || libc_removexattr == NULL ||
      libc_lremovexattr == NULL || libc_flistxattr == NULL ||
      libc_listxattr == NULL || libc_llistxattr == NULL) {
    puts("override_xattr: Couldn't load xattr symbols\n");
    exit(1);
  }
}

#define SOURCE_MATCH "trusted."
/* CHANGE_TO must be the same length */
#define CHANGE_TO    "user.tr."

static void fix_name_inplace(char* name, int reverse) {
  if (!strncmp(name, reverse ? CHANGE_TO : SOURCE_MATCH,
               sizeof(SOURCE_MATCH) - 1)) {
    memcpy(name, reverse ? SOURCE_MATCH : CHANGE_TO, sizeof(SOURCE_MATCH) - 1);
  }
}

static char* fix_name_dup(const char *name) {
  char* buf = strdup(name);
  fix_name_inplace(buf, 0);
  return buf;
}

ssize_t getxattr(const char *path, const char *name,
                 void *value, size_t size) {
  char * fixed_name = fix_name_dup(name);
  ssize_t ret = libc_getxattr(path, fixed_name, value, size);
  free(fixed_name);
  return ret;
}

ssize_t lgetxattr(const char *path, const char *name,
                         void *value, size_t size) {
  char * fixed_name = fix_name_dup(name);
  ssize_t ret = libc_lgetxattr(path, fixed_name, value, size);
  free(fixed_name);
  return ret;
}

ssize_t fgetxattr(int fd, const char *name,
                  void *value, size_t size) {
  char * fixed_name = fix_name_dup(name);
  ssize_t ret = libc_fgetxattr(fd, fixed_name, value, size);
  free(fixed_name);
  return ret;
}

int setxattr(const char *path, const char *name,
             const void *value, size_t size, int flags) {
  char * fixed_name = fix_name_dup(name);
  int ret = libc_setxattr(path, fixed_name, value, size, flags);
  free(fixed_name);
  return ret;
}

int lsetxattr(const char *path, const char *name,
              const void *value, size_t size, int flags) {
  char * fixed_name = fix_name_dup(name);
  int ret = libc_lsetxattr(path, fixed_name, value, size, flags);
  free(fixed_name);
  return ret;
}

int fsetxattr(int fd, const char *name,
              const void *value, size_t size, int flags) {
  char * fixed_name = fix_name_dup(name);
  int ret = libc_fsetxattr(fd, fixed_name, value, size, flags);
  free(fixed_name);
  return ret;
}

int removexattr(const char *path, const char *name) {
  char * fixed_name = fix_name_dup(name);
  int ret = libc_removexattr(path, fixed_name);
  free(fixed_name);
  return ret;
}

int lremovexattr(const char *path, const char *name) {
  char * fixed_name = fix_name_dup(name);
  int ret = libc_lremovexattr(path, fixed_name);
  free(fixed_name);
  return ret;
}

int fremovexattr(int fd, const char *name) {
  char * fixed_name = fix_name_dup(name);
  int ret = libc_fremovexattr(fd, fixed_name);
  free(fixed_name);
  return ret;
}

static void fix_all_names_inplace_reverse(char *list, size_t size) {
  char* end = list + size;
  while (list < end) {
    fix_name_inplace(list, 1);
    list += strlen(list) + 1;
  }
}

ssize_t listxattr(const char *path, char *list, size_t size) {
  ssize_t ret = libc_listxattr(path, list, size);
  if (size == 0 || ret < 0)
    return ret;
  fix_all_names_inplace_reverse(list, ret);
  return ret;
}
ssize_t llistxattr(const char *path, char *list, size_t size) {
  ssize_t ret = libc_llistxattr(path, list, size);
  if (size == 0 || ret < 0)
    return ret;
  fix_all_names_inplace_reverse(list, ret);
  return ret;
}
ssize_t flistxattr(int fd, char *list, size_t size) {
  ssize_t ret = libc_flistxattr(fd, list, size);
  if (size == 0 || ret < 0)
    return ret;
  fix_all_names_inplace_reverse(list, ret);
  return ret;
}
