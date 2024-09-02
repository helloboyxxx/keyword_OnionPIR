#include "test_query.h"
#include "utils.h"
#include "seal/util/uintarithmod.h"

#include <fstream>

#define EXPERIMENT_ITER 1

const size_t entry_idx = 1; // fixed index for testing


void run_query_test() {
  PirTest test;
  test.gen_and_expand();
  // test.enc_then_add();
  // test.gen_query_test();
  // test.small_server_gsw_test();
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
  int ptr = dims[0];
  size_t gsw_l = pir_params.get_l();
  // for the rest dimensions, we read l plaintexts for each "GSW" plaintext, and reconstruct the using these l values.
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


// distribution test
void PirTest::gen_query_test() {
  PRINT_BAR;
  DEBUG_PRINT("Running: " << __FUNCTION__);

  // ======================== Initialize the client and server
  PirParams pir_params{DB_SZ, NUM_DIM, NUM_ENTRIES, ENTRY_SZ, GSW_L, GSW_L_KEY};
  PirClient client(pir_params);
  srand(time(0));
  const int client_id = rand();
  std::unique_ptr<PirServer> server = prepare_server(false, pir_params, client, client_id);


  // ======================== Directly use the client to generate the query many times
  size_t experiment_iter = 50000;

  // open /Users/sam/Desktop/code_test/temp_data/first_dim_enc_coef.csv
  std::ofstream file;
  std::ofstream file2;
  std::ofstream file3;
  file.open("/Users/sam/Desktop/code_test/temp_data/first_dim_enc_coef.csv");
  file2.open("/Users/sam/Desktop/code_test/temp_data/rest_dim_enc_coef.csv");
  file3.open("/Users/sam/Desktop/code_test/temp_data/zero_enc_coef.csv");

  // First we test if the first coefficients looks random
  for (int i = 0; i < experiment_iter; ++i) {
    std::cout << "i : " << i << " ";
    PirQuery query = client.generate_query(entry_idx); 
    // PirQuery query = client.generate_query(0);

    // iterate over the first 256 coefficients
    // Each line has 256 comma separated values
    auto pt = query.data(0);
    // from 310 to 318, we have 9 GSW gadgets. Inspect these values.
    for (int i = 310; i < 319; i++) {
      // std::cout << "0x" << std::hex << pt[i] << " ";
      file2 << "0x" << std::hex << pt[i];
      if (i < 318) {
        file2 << ", ";
      }
      else {
        file2 << std::endl;
      }
    }
  }

  // we generate many zero queries to see if the distributions are the same.
  for (int i = 0; i < experiment_iter; ++i) {
    // the client should query for the first entry. For the "rest dimensions", the query index are all 0.
    std::cout << "i : " << i << " ";
    PirQuery query = client.generate_query(0);
    auto pt = query.data(0);
    client.encryptor_->encrypt_zero_symmetric(query);

    // we query the same 310 to 318 coefficients
    for (int i = 310; i < 319; i++) {
      // std::cout << "0x" << std::hex << pt[i] << " ";
      file3 << "0x" << std::hex << pt[i];
      if (i < 318) {
        file3 << ", ";
      }
      else {
        file3 << std::endl;
      }
    }
  }

  file.close();
  file2.close();
  file3.close();
}



void PirTest::small_server_gsw_test() {
  PRINT_BAR;
  DEBUG_PRINT("Running: " << __FUNCTION__);

  // ======================== Initialize the client and server
  PirParams pir_params{256, 2, 256, 12000, 9, 9};
  pir_params.print_values();
  PirClient client(pir_params);
  srand(time(0));
  const int client_id = rand();
  std::unique_ptr<PirServer> server = prepare_server(false, pir_params, client, client_id);

  // ======================== We skip the packing unpacking part and directly generate the queries.
  
  uint64_t coeff_count = client.params_.poly_modulus_degree(); // 4096
  uint64_t l = client.pir_params_.get_l();
  uint64_t base_log2 = client.pir_params_.get_base_log2();
  size_t first_dim_sz = client.dims_[0];
  uint64_t plain_modulus = client.params_.plain_modulus().value(); // example: 16777259

  // The number of bits required for the first dimension is equal to the size of the first dimension
  uint64_t msg_size = first_dim_sz + client.pir_params_.get_l() * (client.dims_.size() - 1);
  uint64_t bits_per_ciphertext = 1; // padding msg_size to the next power of 2

  while (bits_per_ciphertext < msg_size) {
    bits_per_ciphertext *= 2;
  }
  DEBUG_PRINT(bits_per_ciphertext);
  
  // ======================== The first dimension
  std::vector<seal::Ciphertext> BFV_query;
  for (size_t i = 0; i < first_dim_sz; ++i) {
    if (i == 0) {
      seal::Plaintext plain_one{"1"};
      DEBUG_PRINT("plain_one: " << plain_one.to_string());
      seal::Ciphertext ct_one;
      client.encryptor_->encrypt_symmetric(plain_one, ct_one);
      BFV_query.push_back(ct_one);
    }
    else {
      seal::Ciphertext ct_zero;
      client.encryptor_->encrypt_zero_symmetric(ct_zero);
      BFV_query.push_back(ct_zero);
    }
  }


  // ======================== The rest dimensions
  // RGSW gadget
  uint64_t gadget[l];  // RGSW gadget
  uint64_t curr_exp = 1;
  for (int i = 0; i < l; i++) {
    gadget[i] = curr_exp;
    // we inverse the exponents to get the correct RGSW gadget
    // seal::util::try_invert_uint_mod(curr_exp, plain_modulus, gadget[i]);
    DEBUG_PRINT("gadget[" << i << "]: " << gadget[i]);
    curr_exp = (curr_exp << base_log2) % plain_modulus; // multiply by B and take mod every time
  }

  // Now the second dimension. Let's try RGSW(1) now.
  std::vector<seal::Ciphertext> GSW_query{2*l};
  int ptr = first_dim_sz;
  for (int k = 0; k < l; k++) {
    seal::Plaintext plain_query{"1"};
    plain_query[0] = gadget[k] % plain_modulus;
    seal::Ciphertext lower; // lower half of the GSW ciphertext
    client.encryptor_->encrypt_symmetric(plain_query, lower);
    // client.evaluator_->transform_from_ntt_inplace(lower);

    // Calculate the upper by multiplying the lower with RGSW(-s)
    seal::Ciphertext upper;
    auto neg_secret_key = server->client_gsw_keys_[client_id];
    data_gsw.external_product(neg_secret_key, lower, lower.size(), upper);

    // put both upper and lower to the GSW query
    GSW_query[k] = upper;
    GSW_query[k + l] = lower;

  }

  // ======================== Decrypt the query and interpret the result
  std::vector<seal::Plaintext> decrypted_query = client.decrypt_result(BFV_query);
  for (size_t i = 0; i < decrypted_query.size(); i++) {
    if (decrypted_query[i].is_zero() == false) {
      DEBUG_PRINT(i << ": " << decrypted_query[i].to_string());
    }
  }

  // ======================== Let server use these queries to 

}