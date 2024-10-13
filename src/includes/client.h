#pragma once

#include "external_prod.h"
#include "pir.h"
#include "server.h"
class PirClient {
public:
  PirClient(const PirParams &pirparms);
  ~PirClient();

  /**
  This is the core function for the client.
  High level steps:
  1. Compute the query indices.
  2. Creates a plain_query (pt in paper), add the first dimension, then encrypts it.
  3. For the rest dimensions, calculate required RGSW coefficients and insert
  them into the ciphertext. Result is $\tilde c$ in paper.
  @param entry_index The input to the PIR blackbox.
  @param use_seed By default set to true. Used for setting up
  seal::Ciphertext so that it stores the seed instead of pseudorandom values
  in c_1.
  @return PirQuery Returns a normal Ciphertext whnen use_seed is set to
  false. Otherwise, this returns a seal::Ciphertext with a a seed stored in
  c_1, which should not be touched before doing serialization.
  */
  PirQuery generate_query(const std::uint64_t entry_index, const bool use_seed = true);

  size_t write_query_to_stream(const PirQuery &query, std::stringstream &data_stream);
  size_t write_gsw_to_stream(const std::vector<Ciphertext> &gsw, std::stringstream &gsw_stream);

  std::vector<PirQuery> generate_cuckoo_query(uint64_t seed1, uint64_t seed2, uint64_t table_size, Key keyword);

  void cuckoo_process_reply(uint64_t seed1, uint64_t seed2, uint64_t table_size, Key keyword, std::vector<seal::Ciphertext> reply1, std::vector<seal::Ciphertext> reply2);

  size_t create_galois_keys(std::stringstream &galois_key_stream) const;

  std::vector<seal::Plaintext> decrypt_result(std::vector<seal::Ciphertext> reply);
  uint32_t client_id;
  seal::Decryptor *get_decryptor();
  /*!
      Retrieves an entry from the plaintext containing the entry.
  */
  Entry get_entry_from_plaintext(size_t entry_index, seal::Plaintext plaintext);

  std::vector<Ciphertext> generate_gsw_from_key(const bool use_seed=true);

private:
  seal::EncryptionParameters params_;
  PirParams pir_params_;
  uint64_t DBSize_;
  std::vector<uint64_t> dims_;
  seal::Decryptor *decryptor_;
  seal::Encryptor *encryptor_;
  seal::Evaluator *evaluator_;
  seal::KeyGenerator *keygen_;
  seal::SEALContext *context_;
  const seal::SecretKey *secret_key_;
  /*!
      Gets the corresponding plaintext index in a database for a given entry
     index
  */
  size_t get_database_plain_index(size_t entry_index);

  /*!
      Gets the query indices for a given plaintext
  */
  std::vector<size_t> get_query_indices(size_t plaintext_index);

  friend class PirTest;

};

/**
 * @brief 
 * we match the first hashed_key.size() elements of reply1 and reply2 with hashed_key.
 * If the hashed_key matches one of them, we add the corresponding value to the result.
 * If the hashed_key is not found in either, we return an empty entry.
 */
Entry get_value_from_replies(Entry reply1, Entry reply2, Key keyword, size_t hashed_key_width);