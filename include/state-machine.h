#ifndef ZZZ_STATE_MACH_H
#define ZZZ_STATE_MACH_H

#include "utils/common.h"

typedef enum _eap_state {
  EAP_STATE_UNKNOWN = -1,
  EAP_STATE_PREPARING = 0,
  EAP_STATE_START_SENT = 1,
  EAP_STATE_CHALLENGE_SENT = 2,
  EAP_STATE_IDENTITY_SENT = 3,
  EAP_STATE_SUCCESS = 4,
  EAP_STATE_FAILURE = 5,
} EapState;

Result state_machine_init();
void state_machine_free();

Result switch_to_state(EapState state);

#endif // !ZZZ_STATE_MACH_H
