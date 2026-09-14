#include "packet/builder.h"
#include "md5.h"
#include "packet/packet.h"
#include "utils/config.h"
#include "utils/log.h"
#include "utils/misc.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static PacketBuilder *g_builder = NULL;

typedef struct _packet_builder_priv {
  PacketHeader header;
  AuthConfig *config;
  uint8_t *md5_seed;
  size_t seed_len;
} PacketBuilderPriv;

#define PRIV ((PacketBuilderPriv *)this->priv)

static void set_eth_field(struct _packet_builder *this, int field,
                          const uint8_t *val) {
  switch (field) {
  case FIELD_SRC_MAC:
    memcpy(PRIV->header.eth_hdr.src_mac, val, 6);
    break;
  case FIELD_DST_MAC:
    memcpy(PRIV->header.eth_hdr.dst_mac, val, 6);
    break;
  case FIELD_ETH_PROTO:
    memcpy(PRIV->header.eth_hdr.protocol, val, 2);
    break;
  }
}

static void set_eap_fields(struct _packet_builder *this, EapolType eapol_type,
                           EapCode eap_code, EapType eap_type, uint8_t id,
                           AuthConfig *config) {
  PRIV->header.eapol_hdr.ver[0] = 1; // force EAPOL version = 1
  PRIV->header.eapol_hdr.type[0] = eapol_type;

  if (eapol_type != EAPOL_EAP) {
    PRIV->header.eapol_hdr.len[0] = 0;
    PRIV->header.eapol_hdr.len[1] = 0;
    return;
  }

  uint16_t eap_packet_len = sizeof(EapHeader) + strlen(config->username);
  if (eap_type == EAP_MD5_CHALLENGE) {
    eap_packet_len += MD5_DIGEST_SIZE + 1; // 1 = sizeof(MD5-Value-Size)
  }
  eap_packet_len = htons(eap_packet_len);

  PRIV->header.eap_hdr.id[0] = id;
  PRIV->header.eap_hdr.type[0] = eap_type;
  PRIV->header.eap_hdr.code[0] = eap_code;
  memcpy(PRIV->header.eap_hdr.len, &eap_packet_len, sizeof(uint16_t));
  memcpy(PRIV->header.eapol_hdr.len, &eap_packet_len, sizeof(uint16_t));

  PRIV->config = config;
}

static void set_eap_md5_seed(struct _packet_builder *this, uint8_t *md5_seed,
                             size_t seed_len) {
  if (seed_len < 0)
    return;

  free_ptr(&(PRIV->md5_seed));
  PRIV->md5_seed = calloc(seed_len, sizeof(uint8_t));
  if (PRIV->md5_seed == NULL) {
    return;
  }

  memcpy(PRIV->md5_seed, md5_seed, seed_len);
  PRIV->seed_len = seed_len;
}

static uint8_t *compute_hash(uint8_t *src, size_t len) {
  static uint8_t digest[MD5_DIGEST_SIZE];

  MD5Context ctx;
  md5Init(&ctx);
  md5Update(&ctx, src, len);
  md5Finalize(&ctx);

  return digest;
}

static uint8_t *hash_md5_password(uint8_t id, const uint8_t *md5_seed,
                                  size_t seed_len, const char *password) {
  size_t copied_bytes_len = 0;
  size_t password_len = strlen(password);
  uint8_t buffer[1 + password_len + seed_len];

  buffer[copied_bytes_len] = id;
  copied_bytes_len += 1;

  memcpy(buffer + copied_bytes_len, password, password_len);
  copied_bytes_len += password_len;

  memcpy(buffer + copied_bytes_len, md5_seed, seed_len);
  copied_bytes_len += seed_len;

  return compute_hash(buffer, copied_bytes_len);
}

static size_t build_packet(struct _packet_builder *this, uint8_t *buffer) {
  uint8_t eapol_type = PRIV->header.eapol_hdr.type[0];
  size_t copied_bytes_len = sizeof(EthernetHeader) + sizeof(EapolHeader);

  memcpy(buffer, &(PRIV->header), copied_bytes_len);
  if (eapol_type != EAPOL_EAP) {
    return copied_bytes_len;
  }

  memcpy(buffer + copied_bytes_len, &(PRIV->header.eap_hdr), sizeof(EapHeader));
  copied_bytes_len += sizeof(EapHeader);

  uint8_t eap_type = PRIV->header.eap_hdr.type[0];
  if (eap_type == EAP_MD5_CHALLENGE) {
    if (PRIV->md5_seed == NULL || PRIV->seed_len == 0 || PRIV->config == NULL) {
      return -1;
    }

    buffer[copied_bytes_len] = MD5_DIGEST_SIZE;
    copied_bytes_len += 1;
    memcpy(buffer + copied_bytes_len,
           hash_md5_password(PRIV->header.eap_hdr.id[0], PRIV->md5_seed,
                             PRIV->seed_len, PRIV->config->password),
           MD5_DIGEST_SIZE);
    copied_bytes_len += MD5_DIGEST_SIZE;
  }

  size_t username_len = strlen(PRIV->config->username);
  memcpy(buffer + copied_bytes_len, PRIV->config->username, username_len);
  copied_bytes_len += username_len;

  return copied_bytes_len;
}

PacketBuilder *packet_builder_new() {
  PacketBuilder *this = calloc(1, sizeof(PacketBuilder));
  if (this == NULL) {
    return NULL;
  }

  this->priv = calloc(1, sizeof(PacketBuilderPriv));
  if (this->priv == NULL) {
    free_ptr(&this);
    return NULL;
  }

  this->set_eth_field = set_eth_field;
  this->set_eap_fields = set_eap_fields;
  this->set_eap_md5_seed = set_eap_md5_seed;
  this->build_packet = build_packet;

  return this;
}

PacketBuilder *packet_builder_get() {
  if (g_builder != NULL)
    return g_builder;

  g_builder = packet_builder_new();
  if (g_builder == NULL) {
    log_errorf("failed to allocate memory for packet builder");
    exit(EXIT_FAILURE);
  }

  return g_builder;
}

void packet_builder_free() {
  if (g_builder == NULL)
    return;

  free_ptr(&((PacketBuilderPriv *)g_builder->priv)->md5_seed);
  free_ptr(&g_builder->priv);
  free_ptr(&g_builder);
}
