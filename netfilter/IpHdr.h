
#include <arpa/inet.h>
#include "ip.h"

struct IpHdr final
{
    uint8_t ip_v:4;     /* header length *//* version */
    uint8_t ip_hl:4;       /* version */
                   /* header length */
    uint8_t ip_tos;       /* type of service */

    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;

    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    Ip ip_src;
    Ip ip_dst;   /* source and dest address */
};
typedef IpHdr *PIHdr ;

