#include "test_query.h"
#include "utils.h"

#define DB_SZ             1 << 15       // Database size <==> Number of plaintexts in the database
#define NUM_ENTRIES       1 << 15       // Number of entries in the database
#define GSW_L             5             // Parameter for GSW scheme. 
#define GSW_L_KEY         15            // GSW for query expansion
#define FST_DIM_SZ        256           // Number of dimensions of the hypercube
#define PT_MOD_WIDTH      48            // Width of the plain modulus 
#define CT_MODS      {60, 60, 60}  // Coeff modulus for the BFV scheme


#define EXPERIMENT_ITER 1

const size_t entry_idx = 1; // fixed index for testing


void run_query_test() {
  PirTest test;
  // test.gen_and_expand();
  test.enc_then_add();
  // test.noise_budget_test();
}



void PirTest::gen_and_expand() {
  PRINT_BAR;
  DEBUG_PRINT("Running: " << __FUNCTION__);

  // ======================== Initialize the client and server
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L,
                       GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  pir_params.print_values();
  PirClient client(pir_params);
  PirServer server(pir_params); // Initialize the server with the parameters
  srand(time(0));
  const int client_id = rand();
  // Initialize the client
  std::stringstream galois_key_stream, gsw_stream, data_stream;

  // Client create galois keys and gsw keys and writes to the stream (to the server)
  size_t galois_key_size = client.create_galois_keys(galois_key_stream);
  size_t gsw_key_size = client.write_gsw_to_stream(
      client.generate_gsw_from_key(), gsw_stream);
  //--------------------------------------------------------------------------------
  server.decryptor_ = client.get_decryptor();
  // Server receives the gsw keys and galois keys and loads them when needed
  server.set_client_galois_key(client_id, galois_key_stream);
  server.set_client_gsw_key(client_id, gsw_stream);

  // ======================== Start generating the query
  // size_t entry_idx = rand() % pir_params.get_num_entries();
  DEBUG_PRINT("Client ID: " << client_id << " Entry index: " << entry_idx);
  PirQuery query = client.generate_query(entry_idx);  // a single BFV ciphertext

  // ======================== server receives the query and expand it
  auto expanded_query = server.expand_query(client_id, query);  // a vector of BFV ciphertexts
  std::vector<uint64_t> dims = server.get_dims();

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
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L,
                       GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  PirClient client(pir_params);

  // ======================== we try a simpler version of the client generate_query
  size_t plaintext_index = client.get_database_plain_index(entry_idx); // fixed index for testing
  std::vector<size_t> query_indices = client.get_query_indices(plaintext_index);

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

  std::vector<std::vector<uint64_t>> gadget = gsw_gadget(l, pir_params.get_base_log2(), coeff_mod_count, coeff_modulus);

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
