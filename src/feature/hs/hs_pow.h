/* Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_pow.h
 * \brief Header file containing PoW denial of service defenses for the HS
 *        subsystem for all versions.
 **/

#ifndef TOR_HS_POW_H
#define TOR_HS_POW_H

typedef unsigned __int128 uint128_t;

#include <stdint.h>
#include "ext/equix/include/equix.h"
/* HRPR TODO For event in state, which im not sure on */
#include "lib/evloop/compat_libevent.h"

/** HRPR State and parameters of PoW defenses, stored in the service state. */
typedef struct hs_service_pow_state_t {
  /* HRPR If PoW defenses are enabled this is a priority queue containing
   * acceptable requests that are awaiting rendezvous circuits to built, where
   * priority is based on the amount of effort that was exerted in the PoW. */
  smartlist_t *rend_circuit_pqueue;

  /* HRPR TODO Is this cursed? Including compat_libevent for this. feb 24 */
  /* When PoW defenses are enabled, this event pops rendezvous requests from
   * the service's priority queue. */
  mainloop_event_t *pop_pqueue_ev;

  // HRPR TODO
  uint8_t seed_current[HS_POW_SEED_LEN];

  uint8_t seed_previous[HS_POW_SEED_LEN];

  uint32_t min_effort;

  uint32_t suggested_effort;

  time_t expiration_time;

  // replaycache_t *replay_cache_pow_sol;
} hs_service_pow_state_t;

// N E C[:4](seed) S
typedef struct hs_pow_solution_t {
  /** TODO are we best off storing this as a byte array, as trunnel doesnt
   * support uint128 (?) */
  uint128_t nonce;

  /** - */
  uint32_t effort;

  /** - */
  uint32_t seed_head;

  /** HRPR TODO pointer? */
  equix_solution equix_solution;
} hs_pow_solution_t;

/* API HRPR TODO docs*/
int solve_pow(hs_desc_pow_params_t *pow_params,
              hs_pow_solution_t *pow_solution_out);

int verify_pow(hs_service_pow_state_t *pow_state, hs_pow_solution_t *pow_solution);

#endif /* !defined(TOR_HS_POW_H) */