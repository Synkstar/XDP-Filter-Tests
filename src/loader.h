#pragma once

typedef struct xdpconfig
{
    const char *interface;
    unsigned int offload;
    unsigned int skb;

} xdpconfig_t;