#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <assert.h>
#include <string.h>

// should be last
#include <cmocka.h>

int __real_open(const char *pathname, int flags, int mode);
int __real_close(int fd);
ssize_t __real_read(int fd, void *buf, size_t count);
void *__real__test_malloc(size_t size);
void *__real__test_free(void *ptr);
void *__real__test_calloc(size_t nmemb, size_t size);
void *__real__test_realloc(void *ptr, size_t size);

#define MAX_GCDA_FDS 16
static int gcda_fds[MAX_GCDA_FDS];
static int gcda_fd_count = 0;

static void gcda_fd_add(int fd)
{
	if (gcda_fd_count < MAX_GCDA_FDS)
		gcda_fds[gcda_fd_count++] = fd;
}

static int gcda_fd_remove(int fd)
{
	for (int i = 0; i < gcda_fd_count; i++) {
		if (gcda_fds[i] == fd) {
			gcda_fds[i] = gcda_fds[--gcda_fd_count];
			return 1;
		}
	}
	return 0;
}

int __attribute__((weak)) __wrap_open(const char *pathname, int flags, int mode)
{
	if (strlen(pathname) > 5 &&
	    !strcmp(pathname + strlen(pathname) - 5, ".gcda")) {
		int fd = __real_open(pathname, flags, mode);
		if (fd >= 0)
			gcda_fd_add(fd);
		return fd;
	}

	assert_non_null(pathname);
	assert_true(flags >= 0);

	int ret = mock_type(int);
	if (ret < 0) {
		errno = mock_type(int);
	}

	return ret;
}

void *__attribute__((weak)) __wrap__test_malloc(size_t size)
{
	assert_true(size > 0);

	bool check_size = mock_type(bool);
	if (check_size) {
		size_t max_size = mock_type(int);
		assert_true(size <= max_size);
	}

	bool real_alloc = mock_type(bool);
	if (real_alloc) {
		return __real__test_malloc(size);
	} else {
		return mock_type(void *);
	}
}

void *__attribute__((weak)) __wrap__test_calloc(size_t nmemb, size_t size)
{
	assert_true(size > 0);
	assert_true(nmemb > 0);
	bool check_size = mock_type(bool);
	if (check_size) {
		size_t max_size = mock_type(size_t);
		assert_true(nmemb * size <= max_size);
	}

	bool real_alloc = mock_type(bool);
	if (real_alloc) {
		return __real__test_calloc(nmemb, size);
	} else {
		return mock_type(void *);
	}
}

void *__attribute__((weak)) __wrap__test_realloc(void *ptr, size_t size)
{

	assert_true(size >= 0);

	/* if size is 0, realloc behavior like free(ptr) */
	if (size == 0) {
		assert_non_null(ptr);
	}

	bool check_size = mock_type(bool);
	if (check_size) {
		size_t max_size = mock_type(size_t);
		assert_true(size <= max_size);
	}

	bool real_alloc = mock_type(bool);
	if (real_alloc) {
		return __real__test_realloc(ptr, size);
	} else {
		return mock_type(void *);
	}
}

ssize_t __attribute__((weak)) __wrap_read(int fd, void *buf, size_t count)
{
	if (gcda_fd_remove(fd)) {
		ssize_t ret = __real_read(fd, buf, count);
		gcda_fd_add(fd);
		return ret;
	}

	assert_true(fd > 0);
	assert_true(buf != NULL);
	assert_true(count >= 0);

	int ret = mock_type(size_t);
	if (ret < 0)
		errno = mock_type(int);

	return ret;
}

int __attribute__((weak)) __wrap_close(int fd)
{
	if (gcda_fd_remove(fd))
		return __real_close(fd);

	assert_true(fd > 0);

	int ret = mock_type(int);

	if (ret < 0)
		errno = mock_type(int);

	return ret;
}

void __attribute__((weak)) __wrap__test_free(void *ptr)
{
	bool check = mock_type(bool);
	if (check) {
		void *expected_ptr = mock_type(void *);
		assert_true(ptr == expected_ptr);
	} else {
		__real__test_free(ptr);
	}
}

int __attribute__((weak)) wrap_printf(const char *format, ...)
{
	return 0;
}

int __attribute__((weak)) wrap_fprintf(FILE *stream, const char *format, ...)
{
	return 0;
}

int __attribute__((weak)) __wrap_ioctl(int fd, unsigned long request, ...)
{
	assert_true(fd >= 0);

	int ret = mock_type(int);
	if (ret < 0) {
		errno = mock_type(int);
	}
	return ret;
}

char *__attribute__((weak)) __wrap_strdup(const char *s)
{
	assert_non_null(s);
	int check = mock_type(int);
	if (check)
		check_expected(s);
	char *result = mock_type(char *);

	if (!result) {
		errno = ENOMEM;
	}

	return result;
}
