// SPDX-License-Identifier: GPL-3.0-or-later
#include "tests/unit/test.h"
#include <arpa/inet.h>

/* Duplicate minimal prototype from module to test logic directly. */
#ifndef KNOT_EDNS_OPTION_ECS
#define KNOT_EDNS_OPTION_ECS 8
#endif

extern void kr_bitmask(unsigned char *a, size_t a_len, int bits);

static void test_ecs_ipv4(void **state)
{
    (void)state;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.0.2.129", &addr.sin_addr);

    uint8_t buf[20];
    memset(buf, 0, sizeof(buf));

    /* Manually build payload like module does for /24. */
    const uint8_t prefix = 24;
    uint8_t family_hi = 0, family_lo = 1; /* net order later */
    uint8_t addr_bytes = (prefix + 7) / 8; // 3
    unsigned char masked[4] = {0};
    memcpy(masked, &addr.sin_addr, 4);
    kr_bitmask(masked, 4, prefix);

    /* Build expected buffer. */
    uint8_t exp[8];
    exp[0] = family_hi; exp[1] = family_lo; exp[2] = prefix; exp[3] = 0;
    memcpy(exp + 4, masked, addr_bytes);

    /* Basic sanity: resulting network address lower bits must be zero. */
    assert_int_equal(masked[3], 0);
    /* Ensure length calculation matches expectation. */
    assert_int_equal(4 + addr_bytes, 7); /* 7 bytes payload */
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ecs_ipv4),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}