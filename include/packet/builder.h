#ifndef NYNG_PACKET_BUILDER_H
#define NYNG_PACKET_BUILDER_H

#include "packet/packet.h"
#include "utils/config.h"

#include <stddef.h>
#include <stdint.h>

#define MD5_DIGEST_SIZE 16

// TODO: enum instead of int maybe
#define FIELD_DST_MAC (1 << 0)
#define FIELD_SRC_MAC (1 << 1)
#define FIELD_ETH_PROTO (1 << 2)

typedef struct _packet_builder {
  void (*set_eth_field)(struct _packet_builder *this, int field,
                        const uint8_t *val);

  void (*set_eap_fields)(struct _packet_builder *this, EapolType eapol_type,
                         EapCode eap_code, EapType eap_type, uint8_t id,
                         AuthConfig *config);

  void (*set_eap_md5_seed)(struct _packet_builder *this, uint8_t *md5_seed,
                           size_t seed_len);

  size_t (*build_packet)(struct _packet_builder *this, uint8_t *buffer);

  void *priv;
} PacketBuilder;

PacketBuilder *packet_builder_get();
void free_packet_builder();

#endif // !NYNG_PACKET_BUILDER_H
