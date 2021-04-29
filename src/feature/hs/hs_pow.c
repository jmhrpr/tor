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
#include "ext/libb2/src/blake2.h"
#include "feature/hs/hs_descriptor.h"
#include "feature/hs/hs_pow.h"
#include "ext/ht.h"

/** Replay cache set up */
/** Cache entry for (nonce, seed) replay protection. */
typedef struct nonce_cache_entry_t {
  HT_ENTRY(nonce_cache_entry_t) node;
  uint128_t nonce;
  uint32_t seed_head;
} nonce_cache_entry_t;

/** Return true if the two (nonce, seed) replay cache entries are the same */
static inline int
nonce_cache_entries_eq_(const struct nonce_cache_entry_t *entry1,
                        const struct nonce_cache_entry_t *entry2)
{
  return entry1->nonce == entry2->nonce &&
         entry1->seed_head == entry2->seed_head;
}

/** Hash function to hash the (nonce, seed) tuple entry. */
static inline unsigned
nonce_cache_entry_hash_(const struct nonce_cache_entry_t *ent)
{
  return (unsigned)siphash24g(&ent->nonce, HS_POW_NONCE_LEN) + ent->seed_head;
}

static HT_HEAD(nonce_cache_table, nonce_cache_entry_t) nonce_cache_table;

HT_PROTOTYPE(nonce_cache_table, nonce_cache_entry_t, node,
             nonce_cache_entry_hash_, nonce_cache_entries_eq_);

HT_GENERATE2(nonce_cache_table, nonce_cache_entry_t, node,
             nonce_cache_entry_hash_, nonce_cache_entries_eq_, 0.6,
             tor_reallocarray_, tor_free_);

/** We use this to check if an entry in the replay cache is for a particular
 * seed head, so we know to remove it once the seed is no longer in use. */
int
nonce_cache_entry_has_seed(nonce_cache_entry_t *ent, uint32_t seed_head)
{
  log_err(LD_REND,
          "Checking if replay cache entry matches seed: does %#06x == %#06x?",
          ent->seed_head, seed_head);
  /* Returning nonzero makes HT_FOREACH_FN remove the element from the HT */
  return ent->seed_head == seed_head;
}

/** Remove entries from the (nonce, seed) replay cache which are for the seed
 * beginning with seed_head. */
void
scrub_nonce_cache_for_seed(uint32_t seed_head)
{
  log_err(LD_REND, "Replay cache HT length before scrub: %u",
          HT_SIZE(&nonce_cache_table));
  HT_FOREACH_FN(nonce_cache_table, &nonce_cache_table,
                nonce_cache_entry_has_seed, seed_head);
  log_err(LD_REND, "Replay cache HT length after scrub: %u",
          HT_SIZE(&nonce_cache_table));
}

/** Temp helper function to print an EquiX solution. */
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
  log_err(LD_REND, "C: %s", hex_str(pow_params->seed, 32));
  char hex_nonce[HS_POW_NONCE_LEN * 2 + 1];
  memset(hex_nonce, 0, HS_POW_NONCE_LEN * 2 + 1);
  base16_encode(hex_nonce, HS_POW_NONCE_LEN * 2 + 1, &nonce, HS_POW_NONCE_LEN);
  log_err(LD_REND, "N: %s", hex_nonce);
  log_err(LD_REND, "E: %u | Hex: %s", effort, hex_str(&effort, 4));

  /* Initialise EquiX and blake2b. */
  uint8_t success = 0;
  uint64_t count = 1;

  equix_ctx *ctx = NULL;
  equix_solution solution[EQUIX_MAX_SOLS];
  ctx = equix_alloc(EQUIX_CTX_SOLVE); // TODO inside loop?

  uint8_t hash_result[HS_POW_HASH_LEN];
  blake2b_state S[1];

  /* Repeatedly increment the nonce until we find a valid solution. */
  log_err(LD_REND, "Solving proof of work...");
  while (success == 0) {
    /* Calculate S = equix_solve(C || N || E) */

    int num_solutions = 0;

    num_solutions = equix_solve(ctx, challenge, challenge_len, solution);
    equix_result result =
        equix_verify(ctx, challenge, challenge_len, &solution[0]);
    if (!(result == EQUIX_OK)) {
      nonce++;
      count++;
      memcpy(challenge + sizeof(pow_params->seed), &nonce, HS_POW_NONCE_LEN);
      continue;
    }

    /* Calculate R = blake2b(C || N || E || S) */
    /* HRPR TODO: Do we need to ensure endianness of S? */

    // HRPR TODO check this is behaving correctly (i.e. concat above correct)
    if (blake2b_init(S, HS_POW_HASH_LEN) < 0)
      return -1;
    blake2b_update(S, challenge, challenge_len);
    blake2b_update(S, &solution[0], HS_POW_EQX_SOL_LEN);
    blake2b_final(S, hash_result, HS_POW_HASH_LEN);

    /* Check if R * E <= UINT32_MAX, succeed if so. */
    uint32_t hash_result_netorder = tor_htonl(get_uint32(hash_result)); // TODO
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
      /* We only store the first 4 bytes of the seed */
      pow_solution_out->seed_head = get_uint32(pow_params->seed);
      pow_solution_out->equix_solution = solution[0];

      equix_free(ctx);
      ret = 0;
    } else {
      /* Did not pass the R * E <= UINT32_MAX check. Increment the nonce and
      try again. */
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
  nonce_cache_entry_t search;
  nonce_cache_entry_t *found;
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
  search.nonce = pow_solution->nonce;
  search.seed_head = pow_solution->seed_head;
  found = HT_FIND(nonce_cache_table, &nonce_cache_table, &search);
  if (found) {
    log_err(LD_REND, "Found (nonce, seed) tuple in the replay cache.");
    goto done;
  } else {
    log_err(LD_REND,
            "The (nonce, seed) tuple was not already in the replay cache.");
  }

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

  /* Add the (nonce, seed) tuple to the replay cache HRPR TODO move? */
  log_err(LD_REND, "Adding (nonce, seed) tuple to the replay cache.");
  found = tor_malloc_zero(sizeof(nonce_cache_entry_t));
  found->nonce = pow_solution->nonce;
  found->seed_head = pow_solution->seed_head;
  HT_INSERT(nonce_cache_table, &nonce_cache_table, found);

done:
  return ret;
}