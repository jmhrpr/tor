/* Copyright (c) 2017-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_pow.c
 * \brief Contains code to handle proof-of-work computations
 * when a hidden service is defending against DoS attacks.
 **/

typedef unsigned __int128 uint128_t;

#include <stdio.h>
#include "lib/crypt_ops/crypto_rand.h"
#include "ext/equix/include/equix.h"
#include "ext/libb2/src/blake2.h"
#include "feature/hs/hs_descriptor.h"
#include "feature/hs/hs_pow.h"

/** Length of random nonce (N) used in the PoW scheme. */
#define HS_POW_NONCE_LEN 16
/** Length of blake2b hash result (R) used in the PoW scheme. */
#define HS_POW_HASH_LEN 4
/** Number of bytes needed to store an equix solution. */
#define HS_POW_EQX_SOL_LEN 16

/** Helper function to print an EquiX solution */
static void
print_solution(const equix_solution *sol)
{
  log_err(LD_REND, "Printing EquiX solution:");
  for (int idx = 0; idx < EQUIX_NUM_IDX; ++idx) {
    log_err(LD_REND, "%#06x%s", sol->idx[idx],
            idx != EQUIX_NUM_IDX - 1 ? ", " : "");
  }
}

/** Solve the EquiX/blake2b PoW scheme using the parameters in pow_params, and
 * store the solution in pow_solution_out. Returns 0 on success and -1
 * otherwise. Called by a client. */
int
solve_pow(hs_desc_pow_params_t *pow_params,
          hs_pow_solution_t *pow_solution_out)
{
  int ret = -1;
  uint128_t nonce;

  /* Generate a random nonce so start with. */
  crypto_rand((char *)&nonce, HS_POW_NONCE_LEN);

  /* Select E (just using suggested for now) */
  uint32_t effort = pow_params->suggested_effort;

  /* Build EquiX challenge (C || N || INT_32(E)), following logic of
   * build_secret_input from hsdesc.c */
  size_t offset = 0;
  size_t challenge_len = HS_POW_SEED_LEN + HS_POW_NONCE_LEN + sizeof(uint32_t);
  uint8_t *challenge = NULL;

  challenge = tor_malloc_zero(challenge_len);

  memcpy(challenge, pow_params->seed, HS_POW_SEED_LEN);
  offset += sizeof(pow_params->seed);
  memcpy(challenge + offset, &nonce, HS_POW_NONCE_LEN);
  offset += HS_POW_NONCE_LEN;
  set_uint32(challenge + offset, tor_htonl(effort));
  offset += sizeof(uint32_t);
  tor_assert(challenge_len == offset);

  /* Temporary logging */
  log_err(LD_REND, "(C: %s)", hex_str(pow_params->seed, 32));
  char hex_nonce[HS_POW_NONCE_LEN * 2 + 1];
  memset(hex_nonce, 0, HS_POW_NONCE_LEN * 2 + 1);
  base16_encode(hex_nonce, HS_POW_NONCE_LEN * 2 + 1, &nonce, HS_POW_NONCE_LEN);
  log_err(LD_REND, "(N: %s)", hex_nonce);
  log_err(LD_REND, "(E: %u (%s))", effort, hex_str(&effort, 4));

  /* Initialise EquiX and blake2b. */
  uint8_t success = 0;
  uint64_t count = 0;

  equix_ctx *ctx = NULL;
  equix_solution solution[EQUIX_MAX_SOLS];
  ctx = equix_alloc(EQUIX_CTX_SOLVE); // TODO inside loop?

  uint8_t hash_result[HS_POW_HASH_LEN];
  blake2b_state S[1];

  /* Repeatedly increment the nonce in attempt to find a valid solution. */
  log_err(LD_REND, "Solving proof of work...");
  while (success == 0) {
    /* Calculate S = equix_solve(C || N || E) */

    int num_solutions = 0;

    num_solutions = equix_solve(ctx, challenge, challenge_len, solution);
    equix_result result =
        equix_verify(ctx, challenge, challenge_len, &solution[0]);
    if (!(result == EQUIX_OK)) {
      // log_err(LD_REND, "EquiX failed. Count: %u, Result: %u, Num sol: %u",
      // count, result, num_solutions);
      nonce++;
      count++;
      memcpy(challenge + sizeof(pow_params->seed), &nonce, HS_POW_NONCE_LEN);
      continue;
    }

    /* Calculate R = blake2b(C || N || E || S) */
    /* HRPR TODO: Does endianness of S matter? */

    // HRPR TODO check this is behaving correctly (i.e. concat above correct)
    if (blake2b_init(S, HS_POW_HASH_LEN) < 0)
      return -1;
    blake2b_update(S, challenge, challenge_len);
    blake2b_update(S, &solution[0], HS_POW_EQX_SOL_LEN);
    blake2b_final(S, hash_result, HS_POW_HASH_LEN);

    /* Check if R * E <= UINT32_MAX, succeed if so. */
    uint32_t hash_result_netorder =
        tor_htonl(get_uint32(hash_result)); // TODO
    if ((uint64_t)hash_result_netorder * effort <= UINT32_MAX) {
      success = 1;

      /* Temporary logging. */
      log_err(LD_REND, "Success after %u attempts. INT_32(R)*E = %lu <= %u.",
              count, (uint64_t)hash_result_netorder * effort, UINT32_MAX);
      char hex_challenge[2 * challenge_len + 1];
      memset(hex_challenge, 0, 2 * challenge_len + 1);
      base16_encode(hex_challenge, 2 * challenge_len + 1, challenge,
                    challenge_len);
      log_err(LD_REND, "C || N || INT_32(E): %s", hex_challenge);
      log_err(LD_REND, "S: %s", hex_str(&solution[0], 16));

      /* Store the information required in a solution */
      pow_solution_out->nonce = nonce;
      pow_solution_out->effort = effort;
      pow_solution_out->seed_head = get_uint32(pow_params->seed);
      pow_solution_out->equix_solution = solution[0];

      equix_free(ctx);
      ret = 0;
    } else {
      /* Did not pass the R * E <= UINT32_MAX check. Increment the nonce and try
      again. */
      nonce++;
      count++;
      memcpy(challenge + sizeof(pow_params->seed), &nonce, HS_POW_NONCE_LEN);
    }
  }

  return ret;
}

/** Verify the solution in pow_solution using the service's current PoW
 * parameters found in pow_state. Returns 0 on success and -1 otherwise. Called
 * by the service. */
int
verify_pow(hs_service_pow_state_t *pow_state, hs_pow_solution_t *pow_solution)
{
  int ret = -1;
  uint8_t *seed;

  /* Fail if E = POW_EFFORT is lower than the minimum effort. */
  if (pow_solution->effort < pow_state->min_effort) {
    log_err(LD_REND, "Effort used in solution is less than the minimum effort "
                     "required by the service.");
    goto done;
  }

  /* Find a valid seed C that starts with the seed head. Fail if no such seed
   * exists. */
  if (get_uint32(pow_state->seed_current) == pow_solution->seed_head) {
    log_err(LD_REND, "Seed head matched current seed.");
    seed = pow_state->seed_current;
  } else if (get_uint32(pow_state->seed_previous) == pow_solution->seed_head) {
    log_err(LD_REND, "Seed head matched previous seed.");
    seed = pow_state->seed_previous;
  } else {
    log_err(LD_REND, "Seed head didn't match either seed.");
    goto done;
  }

  /* HRPR TODO Fail if N = POW_NONCE is present in the replay cache. */

  /* Build EquiX challenge (C || N || INT_32(E)) */
  size_t offset = 0;
  size_t challenge_len = HS_POW_SEED_LEN + HS_POW_NONCE_LEN + sizeof(uint32_t);
  uint8_t *challenge = NULL;

  challenge = tor_malloc_zero(challenge_len);

  memcpy(challenge, seed, HS_POW_SEED_LEN);
  offset += HS_POW_SEED_LEN;
  memcpy(challenge + offset, &pow_solution->nonce, HS_POW_NONCE_LEN);
  offset += HS_POW_NONCE_LEN;
  set_uint32(challenge + offset, tor_htonl(pow_solution->effort));
  offset += sizeof(uint32_t);
  tor_assert(challenge_len == offset);

  /* Fail if R * E > UINT32_MAX. */
  uint8_t hash_result[HS_POW_HASH_LEN];
  blake2b_state S[1];

  if (blake2b_init(S, HS_POW_HASH_LEN) < 0)
    return -1; // TODO
  blake2b_update(S, challenge, challenge_len);
  blake2b_update(S, &pow_solution->equix_solution, HS_POW_EQX_SOL_LEN);
  blake2b_final(S, hash_result, HS_POW_HASH_LEN);

  uint32_t hash_result_netorder = tor_htonl(get_uint32(hash_result));
  if ((uint64_t)hash_result_netorder * pow_solution->effort > UINT32_MAX) {
    log_err(LD_REND, "Product of b2 hash and effort was too large.");
    goto done;
  }

  /* Fail if equix_verify(C || N || E, S) != EQUIX_OK */
  equix_ctx *ctx = NULL;
  equix_solution solution[EQUIX_MAX_SOLS];
  ctx = equix_alloc(EQUIX_CTX_SOLVE);

  int num_solutions = 0;
  equix_result result = equix_verify(ctx, challenge, challenge_len,
                                     &pow_solution->equix_solution);
  if (!(result == EQUIX_OK)) {
    // log_err(LD_REND, "EquiX solution: OK, %d solutions", num_solutions);
    log_err(LD_REND, "Verification of EquiX solution in PoW failed.");
    goto done;
  }

  /* PoW verified successfully. */
  ret = 0;

done:
  return ret;
}