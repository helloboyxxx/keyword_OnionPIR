#include "tests.h"
#include "external_prod.h"
#include "pir.h"
#include "server.h"
#include "utils.h"
#include <cassert>
#include <fstream>
#include <iostream>
#include <random>

// "Default" Parameters for the PIR scheme
#define DB_SZ             1 << 15       // Database size <==> Number of plaintexts in the database
#define NUM_ENTRIES       1 << 14       // Number of entries in the database, can be less than DB_SZ
#define GSW_L             5             // Parameter for GSW scheme. 
#define GSW_L_KEY         15            // GSW for query expansion
#define FST_DIM_SZ        256           // Number of dimensions of the hypercube
#define PT_MOD_WIDTH      48            // Width of the plain modulus 
#define CT_MODS	         {60, 60, 60}  // Coeff modulus for the BFV scheme

#define EXPERIMENT_ITERATIONS 10

void print_func_name(std::string func_name) {
#ifdef _DEBUG
  std::cout << "                    "<< func_name << "(Debug build)" << std::endl;
#endif
#ifdef _BENCHMARK
  std::cout << "                    "<< func_name << "(Benchmark build)" << std::endl;
#endif
}

void run_tests() {
  DEBUG_PRINT("Running tests");
  PRINT_BAR;

  // If we compare the following two examples, we do see that external product increase the noise much slower than BFV x BFV.
  // bfv_example();
  // test_external_product();
  // test_ct_sub();
  // serialization_example();

  // test_pir();
  test_seeded_pir();
  // find_pt_mod_width();
  // find_best_params();
  // test_keyword_pir(); // two server version
  // test_cuckoo_keyword_pir(); // single server version

  // test_plain_to_gsw();
  // test_prime_gen();

  PRINT_BAR;
  DEBUG_PRINT("Tests finished");
}

/**
 * @brief This is a BFV x BFV example. The coefficients in example vectors and the result are in hex.
 */
void bfv_example() {
  print_func_name(__FUNCTION__);

  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_degree = 4096;
  parms.set_poly_modulus_degree(poly_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree));

  SEALContext context_(parms);
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = new seal::Encryptor(context_, secret_key_);
  auto decryptor_ = new seal::Decryptor(context_, secret_key_);
  DEBUG_PRINT("poly_degree: " << poly_degree);
  std::cout << "Size f: " << context_.key_context_data()->parms().coeff_modulus().size()
            << std::endl;
  std::cout << "Size f: " << context_.first_context_data()->parms().coeff_modulus().size()
            << std::endl;
  seal::Plaintext a(poly_degree), b(poly_degree), result;
  a[0] = 1;
  a[1] = 9;

  b[0] = 3;
  b[1] = 6;

  DEBUG_PRINT("Vector a: " << a.to_string());
  DEBUG_PRINT("Vector b: " << b.to_string());

  seal::Ciphertext a_encrypted, b_encrypted, cipher_result;
  encryptor_->encrypt_symmetric(a, a_encrypted);
  encryptor_->encrypt_symmetric(b, b_encrypted);
  
  std::cout << "Noise budget before: " << decryptor_->invariant_noise_budget(a_encrypted)
            << std::endl;

  evaluator_.multiply(a_encrypted, b_encrypted, cipher_result);
  decryptor_->decrypt(cipher_result, result);
  std::cout << "Noise budget after: " << decryptor_->invariant_noise_budget(cipher_result) << std::endl;
  std::cout << "BFV x BFV result: " << result.to_string() << std::endl;
}

// This is a BFV x GSW example
void test_external_product() {
  print_func_name(__FUNCTION__);
  // PirParams pir_params(256, 2, 20000, 5, 15, 15);
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L, GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  pir_params.print_values();
  auto parms = pir_params.get_seal_params();    // This parameter is set to be: seal::scheme_type::bfv
  auto context_ = seal::SEALContext(parms);   // Then this context_ knows that it is using BFV scheme
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);
  size_t coeff_count = parms.poly_modulus_degree();
  uint64_t poly_degree = pir_params.get_seal_params().poly_modulus_degree();

  DEBUG_PRINT("poly_degree: " << poly_degree);
  // the test data vector a and results are both in BFV scheme.
  seal::Plaintext a(poly_degree), result;
  size_t plain_coeff_count = a.coeff_count();
  seal::Ciphertext a_encrypted(context_), cipher_result(context_);    // encrypted "a" will be stored here.
  auto &context_data = *context_.first_context_data();

  // vector b
  std::vector<uint64_t> b(poly_degree);

  // vector a is in the context of BFV scheme. 
  // 0, 1, 2, 4 are coeff_index of the term x^i, 
  // the index of the coefficient in the plaintext polynomial
  a[0] = 1;
  a[1] = 2;
  a[2] = 3;

  DEBUG_PRINT("Vector a: " << a.to_string());

  // vector b is in the context of GSW scheme.
  // b[0] = 3;
  b[2] = 5;
  
  // print b
  std::string b_result = "Vector b: ";
  for (int i = 0; i < 5; i++) {
    b_result += std::to_string(b[i]) + " ";
  }
  DEBUG_PRINT(b_result);
  
  // Since a_encrypted is in a context of BFV scheme, the following function encrypts "a" using BFV scheme.
  encryptor_.encrypt_symmetric(a, a_encrypted);

  std::cout << "Noise budget before: " << decryptor_.invariant_noise_budget(a_encrypted)
            << std::endl;
  GSWCiphertext b_gsw;
  data_gsw.encrypt_plain_to_gsw(b, encryptor_, decryptor_, b_gsw);
  data_gsw.gsw_ntt_negacyclic_harvey(b_gsw);  // transform b_gsw to NTT form

  size_t mult_rounds = 1;

  for (int i = 0; i < mult_rounds; i++) {
    data_gsw.external_product(b_gsw, a_encrypted, coeff_count, a_encrypted);
    data_gsw.ciphertext_inverse_ntt(a_encrypted);
    decryptor_.decrypt(a_encrypted, result);
    std::cout << "Noise budget after: " << decryptor_.invariant_noise_budget(a_encrypted)
              << std::endl;
  
  // output decrypted result
  std::cout << "External product result: " << result.to_string() << std::endl;
  }
}

// This is a simple test for demonstrating that we are expecting a "transparent"
// ciphertext if we have two identical ciphertext(value equal) subtracted. This
// is because it is possible to have two entries in the database that are thesame. 
// Please use -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF flag when compiling SEAL.
void test_ct_sub() {
  print_func_name(__FUNCTION__);
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L, GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  auto parms = pir_params.get_seal_params();    // This parameter is set to be: seal::scheme_type::bfv
  auto context_ = seal::SEALContext(parms);
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = new seal::Encryptor(context_, secret_key_);
  auto decryptor_ = new seal::Decryptor(context_, secret_key_);

  // Create a ciphertext of 1
  seal::Plaintext c(pir_params.get_seal_params().poly_modulus_degree());
  c[0] = 2;
  seal::Ciphertext c_encrypted(context_);
  encryptor_->encrypt_symmetric(c, c_encrypted);

  // Create two plaintexts of 3. This mimics the two identical entries in the database
  seal::Plaintext pt1(pir_params.get_seal_params().poly_modulus_degree());
  seal::Plaintext pt2(pir_params.get_seal_params().poly_modulus_degree());
  pt1[0] = 3; 
  pt2[0] = 3;

  // Multiplication of a * pt1 and a * pt2
  seal::Ciphertext result_1(context_);
  seal::Ciphertext result_2(context_);
  evaluator_.multiply_plain(c_encrypted, pt1, result_1);
  evaluator_.multiply_plain(c_encrypted, pt2, result_2);

  // Subtraction
  evaluator_.sub_inplace(result_1, result_2);

  // Decrypt the result
  seal::Plaintext result_pt;
  decryptor_->decrypt(result_1, result_pt);
  std::cout << "Result: " << result_pt.to_string() << std::endl;
}


void serialization_example() {
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L, GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  const auto params = pir_params.get_seal_params();
  const auto context_ = seal::SEALContext(params);
  const auto evaluator_ = seal::Evaluator(context_);
  const auto keygen_ = seal::KeyGenerator(context_);
  const auto secret_key_ = keygen_.secret_key();
  const auto encryptor_ = new seal::Encryptor(context_, secret_key_);
  const auto decryptor_ = new seal::Decryptor(context_, secret_key_);

  std::stringstream data_stream;

  // ================== Raw Zero ciphertext ==================
  seal::Ciphertext raw_zero;
  encryptor_->encrypt_zero_symmetric(raw_zero);
  auto raw_size = raw_zero.save(data_stream); // store the raw zero in the stream

  // ================== SEAL original method for creating serialized zero ==================
  // Original method for creating a serializable object
  Serializable<Ciphertext> orig_serialized_zero = encryptor_->encrypt_zero_symmetric();
  auto s_size = orig_serialized_zero.save(data_stream);   // ! Storing the original zero

  // ================== New way to create a ciphertext with a seed ==================
  // New way to create a ciphertext with a seed, do some operations and then convert it to a serializable object.
  seal::Ciphertext new_seeded_zero;
  encryptor_->encrypt_zero_symmetric_seeded(new_seeded_zero); // This function allows us to change the ciphertext.data(0).

  // Add something in the third coeeficient of seeded_zero
  DEBUG_PRINT("Size: " << new_seeded_zero.size());
  auto ptr_0 = new_seeded_zero.data(0);
  auto ptr_1 = new_seeded_zero.data(1); // corresponds to the second polynomial (c_1)
  // print the binary value of the first coefficient
  BENCH_PRINT("Indicator:\t" << std::bitset<64>(ptr_1[0]));  // used in has_seed_marker()
  // the seed is stored in here. By the time I write this code, it takes 81
  // bytes to store the prng seed. Notice that they have common headers.
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[1]));
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[2]));
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[3]));
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[4]));
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[5]));
  
  auto mods = context_.first_context_data()->parms().coeff_modulus();
  auto plain_modulus = params.plain_modulus().value();
  __uint128_t mod_0 = mods[0].value();
  __uint128_t mod_1 = mods[1].value();
  __uint128_t delta = mod_0 * mod_1 / plain_modulus;
  __uint128_t message = 15;
  __uint128_t to_add = delta * message;
  auto padding = params.poly_modulus_degree();
  ptr_0[0] = (ptr_0[0] + (to_add % mod_0)) % mod_0;
  ptr_0[0 + padding] = (ptr_0[0 + padding] + (to_add % mod_1)) % mod_1;

  // Convert seeded_zero to Serializable<Ciphertext>
  auto new_serialized_zero = encryptor_->ciphertext_to_serializable(new_seeded_zero);
  // write the serializable object to the stream
  auto s2_size = new_serialized_zero.save(data_stream); // ! Storing new ciphertext with a seed

  // ================== Deserialize and decrypt the ciphertexts ==================
  seal::Ciphertext raw_ct, orig_ct, new_ct;
  raw_ct.load(context_, data_stream);  // ! loading the raw zero
  orig_ct.load(context_, data_stream);  // ! loading the original zero
  new_ct.load(context_, data_stream); // ! loading the new ciphertext with a seed 

  // decrypt the ciphertexts
  seal::Plaintext raw_pt, orig_pt, new_pt;
  decryptor_->decrypt(raw_ct, raw_pt);
  decryptor_->decrypt(orig_ct, orig_pt);
  decryptor_->decrypt(new_ct, new_pt);

  // ================== Print the results ==================
  BENCH_PRINT("Raw zero size: " << raw_size);
  BENCH_PRINT("Serializable size 1: " << s_size);
  BENCH_PRINT("Serializable size 2: " << s2_size); // smaller size, but allow us to work on the ciphertext!

  BENCH_PRINT("Raw plaintext: " << raw_pt.to_string());
  BENCH_PRINT("Original plaintext: " << orig_pt.to_string());
  BENCH_PRINT("New plaintext: " << new_pt.to_string()); // Hopefully, this decrypts to the message.
}


// Testing Onion PIR scheme 
void test_pir() {
  print_func_name(__FUNCTION__);
  auto server_time_sum = 0;
  auto client_time_sum = 0;
  
  // setting parameters for PIR scheme
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L,
                       GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  pir_params.print_values();
  PirServer server(pir_params); // Initialize the server with the parameters

  BENCH_PRINT("Initializing server...");
  // Data to be stored in the database.
  std::vector<Entry> data = server.gen_data();
  BENCH_PRINT("Server initialized");

  // Run the query process many times.
  srand(time(0)); // reset the seed for the random number generator
  for (int i = 0; i < EXPERIMENT_ITERATIONS; i++) {
    
    // ========== OFFLINE PHASE ===========
    // Initialize the client
    PirClient client(pir_params);
    const int client_id = rand();

    server.decryptor_ = client.get_decryptor();
    server.set_client_galois_key(client_id, client.create_galois_keys());
    server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

    // ========== ONLINE PHASE ===========
    // Client start generating query
    size_t entry_index = rand() % pir_params.get_num_entries();
    BENCH_PRINT("Experiment [" << i << "]");
    DEBUG_PRINT("\t\tClient ID:\t" << client_id);
    DEBUG_PRINT("\t\tEntry index:\t" << entry_index);

    auto c_start_time = CURR_TIME;  // client start time for the query
    auto query = client.generate_query(entry_index, false);
    
    auto s_start_time = CURR_TIME;  // server start time for processing the query
    auto result = server.make_query(client_id, std::move(query));
    auto s_end_time = CURR_TIME;
    
    // client gets result from the server and decrypts it
    auto decrypted_result = client.decrypt_result(result);
    Entry entry = client.get_entry_from_plaintext(entry_index, decrypted_result[0]);
    auto c_end_time = CURR_TIME;
    
    BENCH_PRINT("\t\tServer time:\t" << TIME_DIFF(s_start_time, s_end_time) << " ms");
    BENCH_PRINT("\t\tClient Time:\t" << TIME_DIFF(c_start_time, c_end_time) - TIME_DIFF(s_start_time, s_end_time) << " ms"); 
    DEBUG_PRINT("\t\tNoise budget:\t" << client.get_decryptor()->invariant_noise_budget(result[0]));

    server_time_sum += TIME_DIFF(s_start_time, s_end_time);
    client_time_sum += TIME_DIFF(c_start_time, c_end_time) - TIME_DIFF(s_start_time, s_end_time);
    if (entry == data[entry_index]) {
      // print a green success message
      std::cout << "\033[1;32mSuccess!\033[0m" << std::endl;
    } else {
      // print a red failure message
      std::cout << "\033[1;31mFailure!\033[0m" << std::endl;

      std::cout << "Result:\t";
      print_entry(entry);
      std::cout << "Data:\t";
      print_entry(data[entry_index]);
    }
    PRINT_BAR;
  }

  std::cout << "Average server time: " << server_time_sum / EXPERIMENT_ITERATIONS << " ms" << std::endl;
  std::cout << "Average client time: " << client_time_sum / EXPERIMENT_ITERATIONS << " ms" << std::endl;
}

void test_seeded_pir() {
  print_func_name(__FUNCTION__);
  auto server_time_sum = 0;
  auto client_time_sum = 0;
  
  // ============== setting parameters for PIR scheme ==============
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L,
                       GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  pir_params.print_values();
  PirServer server(pir_params); // Initialize the server with the parameters

  BENCH_PRINT("Initializing server...");
  // Data to be stored in the database.
  std::vector<Entry> data = server.gen_data();
  BENCH_PRINT("Server initialized");

  // Run the query process many times.
  srand(time(0)); // reset the seed for the random number generator
  for (int i = 0; i < EXPERIMENT_ITERATIONS; i++) {
    
    // ============= OFFLINE PHASE ==============
    // Initialize the client
    PirClient client(pir_params);
    const int client_id = rand();

    server.decryptor_ = client.get_decryptor();
    server.set_client_galois_key(client_id, client.create_galois_keys());
    server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

    // Prepare data stream for the client
    std::stringstream data_stream;

    // ===================== ONLINE PHASE =====================
    // Client start generating query
    size_t entry_index = rand() % pir_params.get_num_entries();
    BENCH_PRINT("Experiment [" << i << "]");
    DEBUG_PRINT("\t\tClient ID:\t" << client_id);
    DEBUG_PRINT("\t\tEntry index:\t" << entry_index);

    // ============= CLIENT ===============
    auto c_start_time = CURR_TIME;  // client start time for the query
    PirQuery query = client.generate_query(entry_index, true);
    auto query_size = client.write_query_to_stream(query, data_stream);
    
    // ============= SERVER ===============
    auto s_start_time = CURR_TIME;  // server start time for processing the query
    auto result = server.make_seeded_query(client_id, data_stream);
    auto s_end_time = CURR_TIME;
    
    // client gets result from the server and decrypts it
    auto decrypted_result = client.decrypt_result(result);
    Entry entry = client.get_entry_from_plaintext(entry_index, decrypted_result[0]);
    auto c_end_time = CURR_TIME;
    
    DEBUG_PRINT("\t\tQuery size:\t" << query_size);
    BENCH_PRINT("\t\tServer time:\t" << TIME_DIFF(s_start_time, s_end_time) << " ms");
    BENCH_PRINT("\t\tClient Time:\t" << TIME_DIFF(c_start_time, c_end_time) - TIME_DIFF(s_start_time, s_end_time) << " ms"); 
    DEBUG_PRINT("\t\tNoise budget:\t" << client.get_decryptor()->invariant_noise_budget(result[0]));

    server_time_sum += TIME_DIFF(s_start_time, s_end_time);
    client_time_sum += TIME_DIFF(c_start_time, c_end_time) - TIME_DIFF(s_start_time, s_end_time);
    if (entry == data[entry_index]) {
      // print a green success message
      std::cout << "\033[1;32mSuccess!\033[0m" << std::endl;
    } else {
      // print a red failure message
      std::cout << "\033[1;31mFailure!\033[0m" << std::endl;

      std::cout << "Result:\t";
      print_entry(entry);
      std::cout << "Data:\t";
      print_entry(data[entry_index]);
    }
    PRINT_BAR;
  }

  std::cout << "Average server time: " << server_time_sum / EXPERIMENT_ITERATIONS << " ms" << std::endl;
  std::cout << "Average client time: " << client_time_sum / EXPERIMENT_ITERATIONS << " ms" << std::endl;
}




void test_keyword_pir() {
  print_func_name(__FUNCTION__);
  int table_size = 1 << 15;
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L, GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  pir_params.print_values();
  const int client_id = 0;
  PirServer server1(pir_params), server2(pir_params);

  int num_entries = table_size;
  std::vector<uint64_t> keywords;
  std::vector<Entry> data(num_entries);

  std::vector<uint64_t> t1(table_size), t2(table_size);
  std::vector<Entry> cuckoo1(table_size), cuckoo2(table_size);

  std::mt19937_64 rng;
  for (int i = 0; i < num_entries; i++) {
    uint64_t keyword = rng();
    keywords.push_back(keyword);
    data[i] = generate_entry_with_id(keyword, pir_params.get_entry_size(), 8);  // 8 in Zhikun's code
  }

  std::hash<uint64_t> hasher;
  uint64_t seed1 = rng(), seed2 = rng();
  table_size -= 1;
  while (1) {
    std::cout << "attempt hash" << std::endl;
    for (int i = 0; i < table_size; i++) {
      t1[i] = t2[i] = 0;
    }
    seed1 = rng();
    seed2 = rng();
    DEBUG_PRINT("Seed1: " << seed1 << " Seed2: " << seed2);
    for (int i = 0; i < num_entries; i++) {
      uint64_t x = keywords[i];
      bool success = false;
      for (int j = 0; j < 100; j++) {
        if (t1[hasher(x ^ seed1) % table_size] == 0) {
          t1[hasher(x ^ seed1) % table_size] = x;
          success = true;
          break;
        }
        std::swap(x, t1[hasher(x ^ seed1) % table_size]);
        if (t2[hasher(x ^ seed2) % table_size] == 0) {
          t2[hasher(x ^ seed2) % table_size] = x;
          success = true;
          break;
        }
        std::swap(x, t2[hasher(x ^ seed2) % table_size]);
      }
      if (!success) {
        goto nxt;
      }
    }
    break;
  nxt:;
  }

  for (int i = 0; i < num_entries; i++) {
    uint64_t x = keywords[i];
    if (t1[hasher(x ^ seed1) % table_size] == x) {
      cuckoo1[hasher(x ^ seed1) % table_size] = data[i];
    } else {
      cuckoo2[hasher(x ^ seed2) % table_size] = data[i];
    }
  }

  server1.set_database(cuckoo1);
  server2.set_database(cuckoo2);

  std::cout << "DB set" << std::endl;

  PirClient client(pir_params);
  std::cout << "Client initialized" << std::endl;
  server1.decryptor_ = client.get_decryptor();
  server1.set_client_galois_key(client_id, client.create_galois_keys());
  server1.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  server2.decryptor_ = client.get_decryptor();
  server2.set_client_galois_key(client_id, client.create_galois_keys());
  server2.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  std::cout << "Client registered" << std::endl;

  for (int i = 0; i < 1; i++) {
    int id = rng() % num_entries;
    auto query_id1 = hasher(keywords[id] ^ seed1) % table_size;
    auto query_id2 = hasher(keywords[id] ^ seed2) % table_size;
    auto query = client.generate_query(query_id1);
    auto result = server1.make_query(client_id, std::move(query));

    auto query2 = client.generate_query(query_id2);
    auto result2 = server2.make_query(client_id, std::move(query2));

    std::cout << "Result: " << std::endl;
    std::cout << client.get_decryptor()->invariant_noise_budget(result[0]) << std::endl;

    Entry entry1 = client.get_entry_from_plaintext(id, client.decrypt_result(result)[0]);
    Entry entry2 = client.get_entry_from_plaintext(id, client.decrypt_result(result2)[0]);

    auto end_time0 = CURR_TIME;

    if (entry1 == data[id]) {
      std::cout << "Success with first query" << std::endl;
    } else if (entry2 == data[id]) {
      std::cout << "Success with second query" << std::endl;
    } else {
      std::cout << "Failure!" << std::endl;

      std::cout << "Result:\t";
      print_entry(entry1);
      print_entry(entry2);
      std::cout << "Data:\t";
      print_entry(data[id]);
    }
  }
}

void test_cuckoo_keyword_pir() {
  print_func_name(__FUNCTION__);
  const int experiment_times = 1;

  const float blowup_factor = 2.0;
  const size_t hashed_key_width = 16;
  const size_t DBSize_ = 1 << 16;
  const size_t num_entries = 1 << 16;
  PirParams pir_params(DBSize_, FST_DIM_SZ, num_entries, GSW_L, GSW_L_KEY, PT_MOD_WIDTH, CT_MODS, hashed_key_width, blowup_factor);
  pir_params.print_values();
  PirServer server(pir_params);

  DEBUG_PRINT("Initializing server...");
  uint64_t keyword_seed = 123123;
  CuckooInitData keyword_data = server.gen_keyword_data(100, keyword_seed);

  if (keyword_data.inserted_data.size() == 0) {
    DEBUG_PRINT("Failed to insert data into cuckoo table. Exiting...");
    return;
  }
  // Now we do have a cuckoo table with data inserted.
  CuckooSeeds last_seeds = keyword_data.used_seeds.back();
  uint64_t seed1 = last_seeds.first;
  uint64_t seed2 = last_seeds.second;
  DEBUG_PRINT("Seed1: " << seed1 << " Seed2: " << seed2);
  
  DEBUG_PRINT("Initializing client...");
  PirClient client(pir_params);
  for (int i = 0; i < experiment_times; i++) {
    srand(time(0));
    const int client_id = rand();
    DEBUG_PRINT("Client ID: " << client_id);

    server.decryptor_ = client.get_decryptor();
    server.set_client_galois_key(client_id, client.create_galois_keys());
    server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

    // Generate a random keyword using keyword_seed. 
    size_t wanted_keyword_idx = rand() % num_entries;
    std::mt19937_64 rng(keyword_seed);
    rng.discard(wanted_keyword_idx);
    Key wanted_keyword = rng();
    DEBUG_PRINT("Wanted keyword: " << wanted_keyword);

    // client start generating keyword query
    auto c_start_time = CURR_TIME;
    std::vector<PirQuery> queries = client.generate_cuckoo_query(seed1, seed2, num_entries, wanted_keyword);
    auto c_end_time = CURR_TIME;

    // server start processing the query
    auto s_start_time = CURR_TIME;
    // we know that there is only two queries in the vector queries.
    auto reply1 = server.make_query(client_id, std::move(queries[0]));
    auto reply2 = server.make_query(client_id, std::move(queries[1]));
    auto s_end_time = CURR_TIME;

    // client start processing the reply
    auto c2_start_time = CURR_TIME;
    client.cuckoo_process_reply(seed1, seed2, num_entries, wanted_keyword, reply1, reply2);
    auto c2_end_time = CURR_TIME;

    DEBUG_PRINT("Server Time: " << TIME_DIFF(s_start_time, s_end_time) << " ms");
    DEBUG_PRINT("Client Time: " << TIME_DIFF(c_start_time, c_end_time) + TIME_DIFF(c2_start_time, c2_end_time) << " ms");
    DEBUG_PRINT("Noise budget left: " << client.get_decryptor()->invariant_noise_budget(reply1[0]));
    DEBUG_PRINT("Noise budget left: " << client.get_decryptor()->invariant_noise_budget(reply2[0]));

  }


}


// Understanding the process of encrypting a plain text to GSW ciphertext
void test_plain_to_gsw() {
  print_func_name(__FUNCTION__);

  // ================== Preparing parameters ==================
  PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L, GSW_L_KEY, PT_MOD_WIDTH, CT_MODS);
  auto parms = pir_params.get_seal_params();    // This parameter is set to be: seal::scheme_type::bfv
  auto context_ = seal::SEALContext(parms);   // Then this context_ knows that it is using BFV scheme
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);
  size_t coeff_count = parms.poly_modulus_degree();
  uint64_t poly_degree = pir_params.get_seal_params().poly_modulus_degree();


  // ================== Preparing the plain text ==================
  std::vector<uint64_t> plain_vec(coeff_count);
  plain_vec[0] = 1;

  // ================== Encrypting the plain text ==================
  GSWCiphertext gsw_key;

  // Now we can encrypt the plain text to GSW ciphertext.
  GSWCiphertext gsw_ct;
  data_gsw.encrypt_plain_to_gsw(plain_vec, encryptor_, decryptor_, gsw_ct);

  // Now, gsw_ct should contains l many BFV ciphertexts.





}



void find_pt_mod_width() {
  print_func_name(__FUNCTION__);

  // open a file to write the results
  std::ofstream file;
  file.open("../outputs/best_pt_mod.txt");
  file << "pt_mod_width, server_time, success_rate" << std::endl;

  for (size_t bit_width = 40; bit_width < 61; ++bit_width) {
    // setting parameters for PIR scheme
    PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, GSW_L, GSW_L_KEY, bit_width, CT_MODS);
    pir_params.print_values();
    PirServer server(pir_params); // Setup server params

    std::cout << "Initializing server..." << std::endl;
    // Radomly generate data to be stored in the database.
    std::vector<Entry> data = server.gen_data();

    auto server_time_sum = 0;
    size_t success_cnt = 0;
    // Run the query process many times.
    for (int i = 0; i < EXPERIMENT_ITERATIONS; i++) {
      srand(time(0)); // reset the seed for the random number generator
      // Initialize the client
      PirClient client(pir_params);
      const int client_id = rand();

      server.decryptor_ = client.get_decryptor();
      server.set_client_galois_key(client_id, client.create_galois_keys());
      server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

      // === Client start generating query ===
      size_t entry_index = rand() % pir_params.get_num_entries();
      auto query = client.generate_query(entry_index);

      auto s_start_time =
          CURR_TIME; // server start time for processing the query
      auto result = server.make_query(client_id, std::move(query));
      auto s_end_time = CURR_TIME;

      // client gets result from the server and decrypts it
      auto decrypted_result = client.decrypt_result(result);
      Entry entry =
          client.get_entry_from_plaintext(entry_index, decrypted_result[0]);

      // ================== Record the results ==================
      std::cout << "Experiment [" << i
                << "]\tServer time: " << TIME_DIFF(s_start_time, s_end_time)
                << " ms" << std::endl;
      server_time_sum += TIME_DIFF(s_start_time, s_end_time);

      if (entry == data[entry_index]) {
        // print a green success message
        std::cout << "\033[1;32mSuccess!\033[0m" << std::endl;
        success_cnt++;
      } else {
        // print a red failure message
        std::cout << "\033[1;31mFailure!\033[0m" << std::endl;
        break;
      }
    }
    
    // record the data
    // bit_width, mod, success_rate, average server time
    file << bit_width << " " << server_time_sum / EXPERIMENT_ITERATIONS << " "
         << (double)success_cnt / (double)EXPERIMENT_ITERATIONS << std::endl;
  }
}



void find_best_params() {
  print_func_name(__FUNCTION__);

  // open a file to write the results
  std::ofstream file;
  file.open("../outputs/best_param.txt");
  file << "pt_mod_width, l, l_key, server_time, all_success" << std::endl;

  for (size_t curr_l_key = 7; curr_l_key < 18; ++curr_l_key) {
    for (size_t curr_l = 3; curr_l < 11; ++curr_l) {
      for (size_t bit_width = 20; bit_width < 61; ++bit_width) {
        // setting parameters for PIR scheme
        PirParams pir_params(DB_SZ, FST_DIM_SZ, NUM_ENTRIES, curr_l, curr_l_key,
                             bit_width, CT_MODS);
        pir_params.print_values();
        PirServer server(
            pir_params); // Initialize the server with the parameters

        std::cout << "Initializing server..." << std::endl;
        // Data to be stored in the database.
        std::vector<Entry> data = server.gen_data();

        auto server_time_sum = 0;
        bool all_success = true;
        int end_iter = EXPERIMENT_ITERATIONS;
        // Run the query process many times.
        for (int i = 0; i < EXPERIMENT_ITERATIONS; i++) {
          srand(time(0)); // reset the seed for the random number generator
          // Initialize the client
          PirClient client(pir_params);
          const int client_id = rand();

          server.decryptor_ = client.get_decryptor();
          server.set_client_galois_key(client_id, client.create_galois_keys());
          server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

          // === Client start generating query ===
          size_t entry_index = rand() % pir_params.get_num_entries();
          auto query = client.generate_query(entry_index);

          auto s_start_time =
              CURR_TIME; // server start time for processing the query
          auto result = server.make_query(client_id, std::move(query));
          auto s_end_time = CURR_TIME;

          // client gets result from the server and decrypts it
          auto decrypted_result = client.decrypt_result(result);
          Entry entry =
              client.get_entry_from_plaintext(entry_index, decrypted_result[0]);

          // ================== Record the results ==================
          std::cout << "Experiment [" << i
                    << "]\tServer time: " << TIME_DIFF(s_start_time, s_end_time)
                    << " ms" << std::endl;
          server_time_sum += TIME_DIFF(s_start_time, s_end_time);

          if (entry == data[entry_index]) {
            // print a green success message
            std::cout << "\033[1;32mSuccess!\033[0m" << std::endl;
          } else {
            // print a red failure message
            std::cout << "\033[1;31mFailure!\033[0m" << std::endl;
            all_success = false;
            end_iter = i + 1;
            break;
          }
        }

        // record the data
        // bit_width, mod, all_success, average server time
        file << bit_width << " " << curr_l << " " << curr_l_key << " "
             << server_time_sum / end_iter << " "
             << " " << all_success << std::endl;

        std::cout << "Average server time: " << server_time_sum / end_iter
                  << " ms" << std::endl;
      }
    }
  }

  // close the file
  file.close();

}

void test_prime_gen() {
  print_func_name(__FUNCTION__);
  for (size_t i = 2; i < 65; ++i) {
    DEBUG_PRINT(generate_prime(i));
  }
}
