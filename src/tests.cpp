#include "tests.h"
#include "external_prod.h"
#include "pir.h"
#include "server.h"
#include "utils.h"
#include <cassert>
#include <iostream>
#include <fstream>
#include <random>

// "Default" Parameters for the PIR scheme
#define DB_SZ       1 << 15     // Database size <==> Number of plaintexts in the database
#define NUM_DIM     8           // Number of dimensions of the hypercube
#define NUM_ENTRIES 1 << 15     // Number of entries in the database
#define ENTRY_SZ    12000       // Size of each entry in the database
#define GSW_L       5           // Parameter for GSW scheme. 
#define GSW_L_KEY   13          // GSW for query expansion


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

  test_pir();
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

  PirParams pir_params(256, 2, 20000, 5, 5, 5);
  auto context_ = seal::SEALContext(pir_params.get_seal_params());
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = new seal::Encryptor(context_, secret_key_);
  auto decryptor_ = new seal::Decryptor(context_, secret_key_);

  uint64_t poly_degree = pir_params.get_seal_params().poly_modulus_degree();
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
  PirParams pir_params(DB_SZ, NUM_DIM, NUM_ENTRIES, ENTRY_SZ, GSW_L, GSW_L_KEY);
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
    data_gsw.cyphertext_inverse_ntt(a_encrypted);
    decryptor_.decrypt(a_encrypted, result);
    std::cout << "Noise budget after: " << decryptor_.invariant_noise_budget(a_encrypted)
              << std::endl;
  
  // output decrypted result
  std::cout << "External product result: " << result.to_string() << std::endl;
  }
}


// Testing Onion PIR scheme 
void test_pir() {
  print_func_name(__FUNCTION__);

  auto server_time_sum = 0;
  auto client_time_sum = 0;
  
  // setting parameters for PIR scheme
  size_t entry_size = (seal::Modulus(DatabaseConstants::PlaintextMod).bit_count() - 1) * DatabaseConstants::PolyDegree / 8;
  PirParams pir_params(DB_SZ, NUM_DIM, NUM_ENTRIES, entry_size, GSW_L, GSW_L_KEY);
  pir_params.print_values();
  PirServer server(pir_params); // Initialize the server with the parameters

  std::cout << "Initializing server..." << std::endl;
  // Data to be stored in the database.
  std::vector<Entry> data = server.gen_data();

  // DEBUG_PRINT("Initializing client...");

  // Run the query process many times.
  for (int i = 0; i < EXPERIMENT_ITERATIONS; i++) {
    srand(time(0)); // reset the seed for the random number generator
    // Initialize the client
    PirClient client(pir_params);
    const int client_id = rand();
    DEBUG_PRINT("Client ID: " << client_id);

    server.decryptor_ = client.get_decryptor();
    server.set_client_galois_key(client_id, client.create_galois_keys());
    server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

    // === Client start generating query ===
    size_t entry_index = rand() % pir_params.get_num_entries();

    auto c_start_time = CURR_TIME;  // client start time for the query
    auto query = client.generate_query(entry_index);
    
    auto s_start_time = CURR_TIME;  // server start time for processing the query
    auto result = server.make_query(client_id, std::move(query));
    auto s_end_time = CURR_TIME;
    
    // client gets result from the server and decrypts it
    auto decrypted_result = client.decrypt_result(result);
    Entry entry = client.get_entry_from_plaintext(entry_index, decrypted_result[0]);
    auto c_end_time = CURR_TIME;
    
    std::cout << "Experiment [" << i << "]\tServer time: " << TIME_DIFF(s_start_time, s_end_time) << " ms" << std::endl;
    std::cout << "\t\tClient Time: " << TIME_DIFF(c_start_time, c_end_time) - TIME_DIFF(s_start_time, s_end_time) << " ms" << std::endl;
    // std::cout << "Noise budget left: " << client.get_decryptor()->invariant_noise_budget(result[0]) << std::endl;

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
  PirParams pir_params(table_size, 8, table_size, 12000, 9, 9);
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
  const size_t DBSize_ = 1 << 16;
  const size_t num_entries = 1 << 16;
  PirParams pir_params(DBSize_, 9, num_entries, 12000, 9, 9, 16, blowup_factor);
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
  PirParams pir_params(256, 2, 20000, 5, 15, 15);
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



void find_best_params() {
  print_func_name(__FUNCTION__);

  // open a file to write the results
  std::ofstream file;
  file.open("plain_mod_test.txt");
  file << "bit_width, plain_mod, server_time, l, all_success" << std::endl;

  std::uint64_t curr_plain_mod = 0;

  for (size_t curr_l = 5; curr_l < 8; ++curr_l) {
    for (size_t bit_width = 34; bit_width < 80; ++bit_width) {
      // getting the current plain_mod
      curr_plain_mod = generate_prime(bit_width);

      // calculate the entry size in bytes
      size_t entry_size = (bit_width - 1) * DatabaseConstants::PolyDegree / 8;

      // setting parameters for PIR scheme
      PirParams pir_params(DB_SZ, NUM_DIM, NUM_ENTRIES, 12000, curr_l,
                          curr_l, curr_plain_mod);
      pir_params.print_values();
      PirServer server(pir_params); // Initialize the server with the parameters

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
        
        auto s_start_time = CURR_TIME;  // server start time for processing the query
        auto result = server.make_query(client_id, std::move(query));
        auto s_end_time = CURR_TIME;

        // client gets result from the server and decrypts it
        auto decrypted_result = client.decrypt_result(result);
        Entry entry = client.get_entry_from_plaintext(entry_index, decrypted_result[0]);

        // ================== Record the results ==================
        std::cout << "Experiment [" << i << "]\tServer time: " << TIME_DIFF(s_start_time, s_end_time) << " ms" << std::endl;
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
      file << bit_width << " " << curr_plain_mod << " "
          << " " << server_time_sum / end_iter << " "
          << " " << curr_l << " " << all_success
          << std::endl;

      std::cout << "Average server time: " << server_time_sum / end_iter << " ms" << std::endl;
    }
  }
  
  
  // close the file
  file.close();

}

void test_prime_gen() {
  print_func_name(__FUNCTION__);
  for (size_t i = 25; i < 30; ++i) {
    DEBUG_PRINT(generate_prime(i));
  }
}