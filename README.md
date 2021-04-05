**Key additions to structs/new structs:**

*hs_pow.h*:

- `hs_service_pow_state_t`: holds all the up-to-date parameters for/state of the PoW defenses, including the pqueue, the mainloop event to pop the pqueue, seeds, suggested effort, nonce/seed hash table replay cache...
- `hs_pow_solution_t`: stores a solution to the PoW puzzle (nonce, effort, first 4 bytes of seed, Equi-X solution)
- 

*hs_service.h*: 

- `hs_service_config_t`: now also contains `has_pow_defenses_enabled` flag, `pow_min_effort`, `pow_svc_bottom_capacity`
- `hs_service_state_t`: now also contains `hs_service_pow_state_t`, `pow_defenses_initialized` flag

*hs_descriptor.h*:

- `hs_desc_pow_params_t`: stores the PoW type, seed, suggested effort and expiration time (the params encoded in descriptors)
- `hs_desc_encrypted_data_t`: now also contains `hs_desc_pow_params_t`, `pow_params_present` flag



### Overview of Client/Service Interaction with PoW Defenses Enabled

**Service: Configuration**
*config.c*:

- new `VAR(HiddenServicePoWDefensesEnabled)` option for torrc

*hs_config.c*: 

- checks `HiddenServicePoWDefensesEnabled`, sets `config->has_pow_defenses_enabled`

*hs_service.c*:

- `set_service_default_config()` sets default values for config's `has_pow_defenses_enabled`, `pow_min_effort`, `pow_svc_bottom_capacity`, which are currently defined as constants in *hs_config.h*.

**Service: Initialising the defenses**

*hs_service.c:*

   - `run_housekeeping_event()`:
        - checks if both `config->has_pow_defenses_enabled` and the service's PoW state is not initialised, calls `+initialize_pow_defenses()` which initialises the service's ` pow_state`.
        - rotates the current seed if it has expired using `+rotate_pow_seeds()`, which rotates the seeds, updates expiration time and scrubs the (nonce, seed) replay cache for the previous seed that is being rotated out of memory. `+scrub_nonce_cache_for_seed()` (*hs_pow.c*) takes a `seed_head` (first 4 bytes of the seed) and uses `HT_FOREACH_FN` to iterate through the hash table entries calling `+nonce_cache_entry_has_seed()` on each one, returning true if the entry relates to the seed head so that the entry is removed from the HT.
        - updates the suggested effort every `HS_UPDATE_PERIOD` using `+update_suggested_effort()` (time period is currently implemented as a constant in *hs_pow*.h instead of being a consensus parameter)
- `run_build_descriptor_event()` now runs `update_all_descriptors_pow_params()` which checks if PoW defenses are enabled, or have just been enabled/disabled/refreshed via SIGHUP, and if the descriptors need to be updated to reflect the current PoW state.

**Service: Encoding PoW parameters in descriptors**
*hs_descriptor*:

   - new struct `hs_desc_pow_params_t` in *hs_descriptor.h* containing PoW scheme type, seed, suggested effort and expiration time

   - `hs_desc_encrypted_data_t` now stores a `hs_desc_pow_params_t` struct and a flag `pow_params_present` to signal if the encrypted data contains PoW parameters

   - new `'pow-params'` string/token rule `R3_POW_PARAMS`

   - `get_inner_encrypted_layer_plaintext()` now, if PoW params are present in the descriptor, encodes the type, seed, suggested effort and expiration time before the intro points in `"pow-params" SP type SP seed-b64 SP expiration-time NL` format.

        

**Client: Fetching & parsing descriptor**

*hs_descriptor.c*:

      - `desc_decode_encrypted_v3()` parses PoW params from the descriptor by detecting the `'pow-params'` keyword token and then calling `+decode_pow_params()` which handles decoding the type, seed, effort and expiration time into the output descriptor object, also sets `pow_params_present` flag in the descriptor.

*hs_client.c*:

  - `can_client_refetch_desc()` now marks a cached descriptor as unusable if PoW params are present and they have expired
  - similarly `client_desc_has_arrived()` marks the descriptor as unusable if the PoW params have expired, otherwise it flags the `entry_conn` with `hs_with_pow_conn`, a new flag in the `entry_connection_t` struct which is used to signal that we should not apply the normal SOCKS timeout to this connection in *connection_edge.c*'s `connection_ap_expire_beginning()` and *circuituse.c*'s `connection_ap_handshake_attach_circuit()`. this flag is also set in *connection_edge.c*'s `connection_ap_handle_onion()` when a usable cached descriptor is found.
  - in `send_introduce1()`, if the descriptor for the service contains PoW parameters then we create a `hs_pow_solution_t` (*hs_pow.h*) and call `+solve_pow()` (*hs_pow.c*) to populate it with a correct solution to the PoW puzzle with the parameters from the descriptor. the `rend_circ` is flagged with `hs_with_pow_circ`, a new addition to the `origin_circuit_t` struct which is used in *circuituse.c* to increase the timeout time for circuits which are waiting for the service to respond to their rendezvous request (i.e, waiting for the service to pop the rendezvous request from its priority queue, should the request have been accepted by the service)

**Client: Solve PoW puzzle**

*hs_pow.c*:

      - `+solve_pow()` generates a random nonce, currently just uses the service's suggested effort, builds the challenge by concatenating the seed, nonce and effort then begins attempting to solve the proof of work: solving the Equi-X problem then computing a 4 byte blake2b hash and checking that the product of the hash and the effort is less than equal to `UINT32_MAX`, incrementing the nonce and retrying if not. once a nonce is found the PoW solution is populated with the nonce, effort, first 4 bytes of the seed and the Equi-X solution that resulted in the valid PoW solution.

**Client: Build INTRODUCE1 cell extension**

*hs_client.c*:

      - `hs_circ_send_introduce1()` takes the PoW solution computed above as an argument, which in turn passes it to `hs_cell_build_introduce1()` in *hs_cell.c*.    

*hs_cell.c*:

  - `hs_cell_build_introduce1()` passes the PoW solution to `introduce1_set_encrypted()` which now builds cell extensions (like is currently done for `ESTABLISH_INTRO` cells), with `+build_introduce1_encrypted_extensions(pow_solution)` which, if the `pow_solution` is not null, passes the solution to `+build_introduce1_encrypted_pow_extension()` which builds the extension.
  - `+build_introduce1_encrypted_pow_extension()` uses Trunnel generated functions (from additions to *cell_introduce1.trunnel*) to build the extension.



**Service: Parsing INTRODUCE2**

*hs_cell.c*:

   - `hs_circ_handle_introduce2()` (*hs_circuit.c*) calls `hs_cell_parse_introduce2()` as usual, but now `hs_cell_parse_introduce2()` checks for cell extensions in the encrypted section with `+handle_introduce2_encrypted_cell_extensions()`, which in turn calls `+handle_introduce2_encrypted_cell_pow_extension()` if a PoW solution is present.
   - `+handle_introduce2_encrypted_cell_pow_extension()` is responsible for calling `+verify_pow()` (*hs_pow.c*) and fails if the PoW verification fails (and instantly stops dealing with the cell) otherwise the solution is brought out and the effort is stored in a new `pow_effort` field in the `hs_cell_introduce2_data_t` struct

**Service: Rendezvous request priority queue**

*hs_circuit.c*:

      - if the PoW defenses are enabled, at the end of `hs_circ_handle_introduce2()` instead of calling `launch_rendezvous_point_circuit(service, ip, data)`, we call `+enqueue_rend_request(service, ip, data, effort)` to add the rendezvous request to the service's priority queue with the effort being the priority. the "pending rendezvous request" is stored in a new struct `pending_rend_t` which stores the intropoint, data, effort and a index for the position of the request in the priority queue heap. the `pending_rend_t` object is then added to the service's `rend_request_pqueue`, a smartlist priority queue maintained in the service's PoW state, using the entry comparison function `+compare_rend_request_by_effort_()`. after the rendezvous request is added to the priority queue we activate (and initiate if it hasn't been initiated yet) a new mainloop event `pop_pqueue_ev`, also stored in the service's PoW state, which calls new callback function `+handle_rend_pqueue_cb()` with the service as being passed as the argument.
            - `+handle_rend_pqueue_cb()` is thus called from the mainloop and pops the rendezvous request from the front of the priority queue and finally calls `launch_rendezvous_point_circuit()` as normal to connect to the client. if the priority queue still contains pending rendezvous requests the `pop_pqueue_ev` event is activated again.