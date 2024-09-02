#pragma once

#include "external_prod.h"
#include "pir.h"
#include "server.h"
class PirClient {
public:
  PirClient(const PirParams &pirparms);
  ~PirClient();

  /*!
      Generates an OnionPIR query corresponding to the plaintext that encodes
     the given entry index. High level steps:
     1. Calculate the plaintext index. Generate plaintexts query (b vectors in paper) for each dimension.
     2. Creates a plain_query (pt in paper), add the first dimension, then encrypts it.
     3. For the rest dimensions, calculate required RGSW coefficients and insert them into the ciphertext. Result is $\tilde c$ in paper.
  */
  PirQuery generate_query(std::uint64_t entry_index);

  std::vector<PirQuery> generate_cuckoo_query(uint64_t seed1, uint64_t seed2, uint64_t table_size, Key keyword);

  void cuckoo_process_reply(uint64_t seed1, uint64_t seed2, uint64_t table_size, Key keyword, std::vector<seal::Ciphertext> reply1, std::vector<seal::Ciphertext> reply2);

  seal::GaloisKeys create_galois_keys();

  std::vector<seal::Plaintext> decrypt_result(std::vector<seal::Ciphertext> reply);
  uint32_t client_id;
  seal::Decryptor *get_decryptor();
  /*!
      Retrieves an entry from the plaintext containing the entry.
  */
  Entry get_entry_from_plaintext(size_t entry_index, seal::Plaintext plaintext);

  GSWCiphertext generate_gsw_from_key();

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
      Gets the query indexes for a given plaintext
  */
  std::vector<size_t> get_query_indexes(size_t plaintext_index);

  friend class PirTest;

};

/**
 * @brief 
 * we match the first hashed_key.size() elements of reply1 and reply2 with hashed_key.
 * If the hashed_key matches one of them, we add the corresponding value to the result.
 * If the hashed_key is not found in either, we return an empty entry.
 */
Entry get_value_from_replies(Entry reply1, Entry reply2, Key keyword, size_t hashed_key_width);