#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <assert.h>

// should be last
#include <cmocka.h>
#include <netlink/netlink.h>
#include <netlink/handlers.h>

extern struct nl_cb *__real_nl_cb_alloc(enum nl_cb_kind);
extern struct nl_sock *__real_nl_socket_alloc_cb(struct nl_cb *);
extern struct nl_sock *__real_nl_socket_alloc(void);

int __attribute__((weak)) __wrap_nl_connect(struct nl_sock *sk, int prot)
{
	assert_non_null(sk);
	check_expected(prot);
	int ret = mock_type(int);
	return ret;
}

struct nl_cb *__attribute__((weak)) __wrap_nl_cb_alloc(enum nl_cb_kind kind)
{
	int test_null = mock_type(int);
	if (test_null) {
		return NULL;
	} else {
		return __real_nl_cb_alloc(kind);
	}
}

struct nl_sock *__attribute__((weak))
__wrap_nl_socket_alloc_cb(struct nl_cb *cb)
{
	assert_non_null(cb);

	int test_null = mock_type(int);
	if (test_null) {
		return NULL;
	} else {
		return __real_nl_socket_alloc_cb(cb);
	}
}

int __attribute__((weak))
__wrap_nl_send_auto(struct nl_sock *sk, struct nl_msg *msg)
{
	assert_non_null(sk);
	assert_non_null(msg);
	int ret = mock_type(int);
	return ret;
}

nl_recvmsg_msg_cb_t CB_VALID = NULL;
void *CB_VALID_DATA = NULL;
nl_recvmsg_msg_cb_t CB_ACK = NULL;
void *CB_ACK_DATA = NULL;

int __attribute__((weak)) __wrap_nl_recvmsgs_default(struct nl_sock *sk)
{
	assert_non_null(sk);

	int do_valid = mock_type(int);
	if (do_valid && CB_VALID) {
		struct nl_msg *msg = mock_ptr_type(struct nl_msg *);
		CB_VALID(msg, CB_VALID_DATA);
	}

	int do_ack = mock_type(int);
	if (do_ack && CB_ACK) {
		struct nl_msg *msg = mock_ptr_type(struct nl_msg *);
		CB_ACK(msg, CB_ACK_DATA);
	}

	int ret = mock_type(int);
	return ret;
}

int __attribute__((weak))
__wrap_nl_cb_set(struct nl_cb *cb, enum nl_cb_type type, enum nl_cb_kind kind,
		 nl_recvmsg_msg_cb_t cb_func, void *data)
{
	assert_non_null(cb);
	assert_non_null(data);
	if (type == NL_CB_VALID) {
		CB_VALID = cb_func;
		CB_VALID_DATA = data;
	}

	if (type == NL_CB_ACK) {
		CB_ACK = cb_func;
		CB_ACK_DATA = data;
	}

	return 0;
}
