/*
 * EDNS Client Subnet (ECS) module for Knot Resolver
 * Adds support for sending ECS option upstream according to RFC 7871.
 *
 * Copyright (C) 2024 <Your Organization>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <arpa/inet.h>
#include <string.h>
#include <libknot/packet/pkt.h>
#include <libknot/rrtype/opt.h>

#include "lib/module.h"
#include "lib/utils.h"
#include "lib/layer.h"

/* EDNS option code for Client Subnet (RFC 7871) */
#ifndef KNOT_EDNS_OPTION_ECS
#define KNOT_EDNS_OPTION_ECS 8
#endif

/* Default prefix lengths as suggested in RFC 7871, section 7. */
static uint8_t ecs_prefix4 = 24;   /* /24 for IPv4 */
static uint8_t ecs_prefix6 = 56;   /* /56 for IPv6 */

/* ------------------------------------------------------------------ */
/* Helper that builds ECS option payload into @buf. Returns size or 0. */
static size_t build_ecs_option(const struct sockaddr *src, uint8_t buf[20])
{
    if (!src) {
        return 0;
    }

    uint16_t family = 0;
    uint8_t src_prefix = 0;
    uint8_t scope_prefix = 0; /* We use 0 → cache for any scope. */
    uint8_t addr_bytes = 0;
    uint8_t addr_raw[16] = {0};

    if (src->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)src;
        family = 1; /* IPv4 */
        src_prefix = ecs_prefix4;
        memcpy(addr_raw, &in->sin_addr, 4);
        addr_bytes = (src_prefix + 7) / 8;
    } else if (src->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src;
        family = 2; /* IPv6 */
        src_prefix = ecs_prefix6;
        memcpy(addr_raw, &in6->sin6_addr, 16);
        addr_bytes = (src_prefix + 7) / 8;
    } else {
        return 0; /* Unsupported */
    }

    /* Mask address to prefix length. */
    kr_bitmask(addr_raw, sizeof(addr_raw), src_prefix);

    /* Compose option payload: FAMILY | SRC_PREFIX | SCOPE_PREFIX | ADDRESS */
    knot_wire_write_u16(buf, family);
    buf[2] = src_prefix;
    buf[3] = scope_prefix;
    memcpy(buf + 4, addr_raw, addr_bytes);

    return 4 + addr_bytes; /* payload length */
}

/* ------------------------------------------------------------------ */
/* Property callbacks (prefix4 / prefix6 setters) -------------------- */
static char *set_prefix4(void *env, struct kr_module *module, const char *input)
{
    if (!input) return NULL;
    long val = strtol(input, NULL, 10);
    if (val < 0 || val > 32) {
        return NULL;
    }
    ecs_prefix4 = (uint8_t)val;
    return strdup(input);
}

static char *set_prefix6(void *env, struct kr_module *module, const char *input)
{
    if (!input) return NULL;
    long val = strtol(input, NULL, 10);
    if (val < 0 || val > 128) {
        return NULL;
    }
    ecs_prefix6 = (uint8_t)val;
    return strdup(input);
}

/* ------------------------------------------------------------------ */
/* Layer callback: checkout ----------------------------------------- */
static int ecs_checkout(kr_layer_t *ctx, knot_pkt_t *packet, struct sockaddr *dst, int type)
{
    (void)dst; /* Unused */
    (void)type;

    struct kr_request *req = ctx->req;
    if (!req || !packet || !packet->opt_rr || !req->qsource.addr) {
        return ctx->state;
    }

    /* Build ECS payload. */
    uint8_t ecs_buf[20];
    size_t ecs_len = build_ecs_option(req->qsource.addr, ecs_buf);
    if (ecs_len == 0) {
        return ctx->state; /* Unsupported family or error */
    }

    /* Remove any pre-existing ECS option to avoid duplicates. */
    knot_edns_remove_options(packet->opt_rr, KNOT_EDNS_OPTION_ECS);

    int ret = knot_edns_add_option(packet->opt_rr, KNOT_EDNS_OPTION_ECS,
                                   ecs_len, ecs_buf, &packet->mm);
    if (ret != KNOT_EOK) {
        ctx->state = KR_STATE_FAIL;
    }
    return ctx->state;
}

/* ------------------------------------------------------------------ */
/* Module initialization -------------------------------------------- */
KR_EXPORT int ecs_init(struct kr_module *module)
{
    static const struct kr_prop props[] = {
        { &set_prefix4, "prefix4", "Set IPv4 ECS prefix length (0-32)" },
        { &set_prefix6, "prefix6", "Set IPv6 ECS prefix length (0-128)" },
        { NULL, NULL, NULL },
    };
    module->props = props;

    static kr_layer_api_t layer = {
        .checkout = &ecs_checkout,
    };
    layer.data = module;
    module->layer = &layer;

    return kr_ok();
}

KR_EXPORT int ecs_deinit(struct kr_module *module)
{
    (void)module;
    return kr_ok();
}

KR_MODULE_EXPORT(ecs)