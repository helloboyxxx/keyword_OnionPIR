#include "test_query.h"
#include "utils.h"

#define EXPERIMENT_ITER 1

const size_t entry_idx = 1; // fixed index for testing


void run_query_test() {
  PirTest test;
  // test.gen_and_expand();
  // test.enc_then_add();
  // test.noise_budget_test();
}

std::unique_ptr<PirServer> PirTest::prepare_server(bool init_db, PirParams &pir_params, PirClient &client, const int client_id) {
  std::unique_ptr<PirServer> server = std::make_unique<PirServer>(pir_params);
  server->decryptor_ = client.get_decryptor();
  server->set_client_galois_key(client_id, client.create_galois_keys());
  server->set_client_gsw_key(client_id, client.generate_gsw_from_key());
  if (init_db) {
    server->gen_data();
  }
  return server;
}


void PirTest::gen_and_expand() {
  PRINT_BAR;
  DEBUG_PRINT("Running: " << __FUNCTION__);

  // ======================== Initialize the client and server
  PirParams pir_params{DB_SZ, NUM_DIM, NUM_ENTRIES, ENTRY_SZ, GSW_L, GSW_L_KEY};
  pir_params.print_values();
  PirClient client(pir_params);
  srand(time(0));
  const int client_id = rand();
  std::unique_ptr<PirServer> server = prepare_server(false, pir_params, client, client_id);

  // ======================== Start generating the query
  // size_t entry_idx = rand() % pir_params.get_num_entries();
  DEBUG_PRINT("Client ID: " << client_id << " Entry index: " << entry_idx);
  PirQuery query = client.generate_query(entry_idx);  // a single BFV ciphertext

  // ======================== server receives the query and expand it
  auto expanded_query = server->expand_query(client_id, query);  // a vector of BFV ciphertexts
  std::vector<uint64_t> dims = server->get_dims();

  // ======================== client decrypts the query vector and interprets the result
  std::vector<seal::Plaintext> decrypted_query = client.decrypt_result({query});
  std::cout << "Raw decrypted in hex: " << decrypted_query[0].to_string() << std::endl;

  std::vector<seal::Plaintext> dec_expanded = client.decrypt_result(expanded_query);

  // check the first dimension is the first dims[0] plaintext in decrypted_query
  for (size_t i = 0; i < dims[0]; i++) {
    if (dec_expanded[i].is_zero() == false) {
      DEBUG_PRINT("Dimension 0[" << i << "]: " << dec_expanded[i].to_string());
    }
  }

  // Here is an example of showing the decrypted RGSW won't look good because it is not scaling the message by delta.
  // However, with some luck, when the gadget value is close to delta, the decrypted RGSW will look like the original message.
  // But don't rely on that. We simply shouldn't decrypt RGSW ciphertexts.
  int ptr = dims[0];
  size_t gsw_l = pir_params.get_l();
  for (size_t dim_idx = 1; dim_idx < dims.size(); ++dim_idx) {
    std::cout << "Dim " << dim_idx << ": ";
    for (int k = 0; k < gsw_l; k++) {
      std::cout << "0x" << dec_expanded[ptr + k].to_string() << " ";
    }
    std::cout << std::endl;
    ptr += gsw_l;
  }


}

void PirTest::enc_then_add() {
  PRINT_BAR;
  DEBUG_PRINT("Running: " << __FUNCTION__);

  // ======================== Initialize the client and server
  PirParams pir_params{DB_SZ, NUM_DIM, NUM_ENTRIES, ENTRY_SZ, GSW_L, GSW_L_KEY};
  PirClient client(pir_params);

  // ======================== we try a simpler version of the client generate_query
  size_t plaintext_index = client.get_database_plain_index(entry_idx); // fixed index for testing
  std::vector<size_t> query_indexes = client.get_query_indexes(plaintext_index);

  auto context_data = client.context_->first_context_data();
  auto coeff_modulus = context_data->parms().coeff_modulus();
  auto plain_modulus = context_data->parms().plain_modulus().value();
  auto coeff_mod_count = coeff_modulus.size();  // 2
  auto l = pir_params.get_l();
  size_t coeff_count = pir_params.get_seal_params().poly_modulus_degree();

  DEBUG_PRINT("modulus 0: " << coeff_modulus[0].value());
  DEBUG_PRINT("modulus 1: " << coeff_modulus[1].value());

  const size_t pos = 3;
  __uint128_t bigger_mod = std::max(coeff_modulus[0].value(), coeff_modulus[1].value());
  __uint128_t smaller_mod = std::min(coeff_modulus[0].value(), coeff_modulus[1].value());
  size_t mod_diff = bigger_mod - smaller_mod;
  __uint128_t mod_mult = bigger_mod * smaller_mod;
  DEBUG_PRINT("mod_diff: " << mod_diff);

  std::vector<std::vector<__uint128_t>> gadget = gsw_gadget(l, pir_params.get_base_log2(), coeff_mod_count, coeff_modulus);

  auto gadget_diffs = std::vector<uint64_t>(l);
  for (int i = 0; i < l; i++) {
    gadget_diffs[i] = gadget[1][i] - gadget[0][i];
    if (gadget_diffs[i] != 0) {
      DEBUG_PRINT("gadget_diffs[" << i << "]: " << gadget_diffs[i]);
      DEBUG_PRINT("gadget_diffs[" << i << "] % mod_diff: " << gadget_diffs[i] % mod_diff);  
      DEBUG_PRINT("gadget_diffs[" << i << "] / mod_diff: " << gadget_diffs[i] / mod_diff);  
    }
  }

  // auto to_add = mod_diff * 4096 * 256;
  __uint128_t delta = mod_mult / plain_modulus;
  // __uint128_t delta = 1ULL << 48;
  __uint128_t message = 15;
  __uint128_t to_add = delta * message;
  DEBUG_PRINT("delta:    \t" << uint128_to_string(delta));
  DEBUG_PRINT("size_t max:\t" << std::numeric_limits<size_t>::max());


  PirQuery query;
  client.encryptor_->encrypt_zero_symmetric(query);

  // Say BFV(something) = (a, b), where a, b are two polynomials of size coeff_count * coeff_mod_count.
  // Conceptually, the degree should be coeff_count.
  auto a_head = query.data(0); 
  auto b_head = query.data(1);

  // try manipulating the x^3 coefficient
  for (int k = 0; k < coeff_mod_count; ++k) {
    __uint128_t mod = coeff_modulus[k].value();
    __uint128_t pad = k * coeff_count;
    a_head[pos + pad] = (a_head[pos + pad] + (to_add % mod)) % mod;
  }

  // ======================== Decrypt the query and interpret the result
  auto decrypted_query = seal::Plaintext{coeff_count};
  client.decryptor_->decrypt(query, decrypted_query);
  if (decrypted_query.is_zero()) {
    std::cout << "Decrypted query is zero." << std::endl;
  }
  if (decrypted_query.is_zero() == false) {
    std::cout << "Decrypted in hex: " << decrypted_query.to_string() << std::endl;
  }

}
