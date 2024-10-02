#pragma once

#include "client.h"
#include "external_prod.h"
#include "pir.h"
#include <optional>

typedef std::vector<std::optional<seal::Plaintext>> Database;
typedef std::pair<uint64_t, uint64_t> CuckooSeeds;

// struct for storing server public data after generating the database
struct CuckooInitData {
  std::vector<CuckooSeeds> used_seeds;  // all seeds used for constructing the cuckoo hash table
  std::vector<Entry> inserted_data; // database containing all inserted entries
};

class PirServer {
public:
  PirServer(const PirParams &pir_params);

  /**
   * @brief Generate random data for the server database. Return the generated data for testing purposes.
   */
  std::vector<Entry> gen_data();

  /**
   * @brief Generate random key-value pairs, configured using hashed_key_width_. 
   * Then set the database by inserting the key-value pairs using cuckoo hashing.
   * @return a copy of the generated database and all used seeds. The last pair of CuckooSeeds is the seeds used for the cuckoo hash.
   */
  CuckooInitData gen_keyword_data(size_t max_iter, uint64_t keyword_seed);

  /**
   * @brief Sets the server database using the provided vector of entries
   * @param new_db 
   */
  void set_database(std::vector<Entry> &new_db);

  std::vector<uint64_t> get_dims() const;

  // Given the client id and a packed client query, this function first unpacks the query, then returns the retrieved encrypted result.
  std::vector<seal::Ciphertext> make_query(uint32_t client_id, PirQuery &&query);

  /**
   * @brief A clever way to evaluate the external product for second to last dimensions. 
   * 
   * @param result The BFV ciphertexts
   * @param selection_cipher A single RGSW(b) ciphertext, where b \in {0, 1}. 0 to get the first half of the result, 1 to get the second half.
   * @return std::vector<seal::Ciphertext> 
   */
  std::vector<seal::Ciphertext> evaluate_gsw_product(std::vector<seal::Ciphertext> &result,
                                                     GSWCiphertext &selection_cipher);
  void set_client_galois_key(uint32_t client_id, seal::GaloisKeys client_key);
  void set_client_gsw_key(uint32_t client_id, GSWCiphertext &&gsw_key);

  seal::Decryptor *decryptor_;

  friend class PirTest;

private:
  uint64_t DBSize_;
  seal::SEALContext context_;
  seal::Evaluator evaluator_;
  std::vector<uint64_t> dims_;
  std::map<uint32_t, seal::GaloisKeys> client_galois_keys_;
  std::map<uint32_t, GSWCiphertext> client_gsw_keys_;
  Database db_;
  PirParams pir_params_;
  size_t hashed_key_width_;

  /*!
    Expands the first query ciphertext into a selection vector of ciphertexts
    where the ith ciphertext encodes the ith bit of the first query ciphertext.
  */
  std::vector<seal::Ciphertext> expand_query(uint32_t client_id, seal::Ciphertext &ciphertext) const;
  /*!
    Performs a cross product between the first selection vector and the
    database.
  */
  std::vector<seal::Ciphertext> evaluate_first_dim(std::vector<seal::Ciphertext> &selection_vector);
  std::vector<seal::Ciphertext>
  evaluate_first_dim_delayed_mod(std::vector<seal::Ciphertext> &selection_vector);

  /*!
    Transforms the plaintexts in the database into their NTT representation.
    This speeds up computation but takes up more memory.
  */
  void preprocess_ntt();
};

// ================== HELPER FUNCTIONS ==================

/**
* @brief Given an entry id and the length of the entry, generate a random entry using random number generator.
* 
* @param id entry id. This will be used as a seed for generating the entry randomly.
* @param len length(size) of the entry. Each entry is a vector of bytes.
* @return Entry 
*/
Entry generate_entry(int id, size_t entry_size);

/**
 * @brief Generate an entry with a key_id. This will be used as a seed for
 * generating the hashed_key. Note that in reality, the value is not randomly
 * generated. But here, for now, we generate the value randomly using the same seed.
 * ! One should modify this fucntion to generate the value using different seeds / methods.
 * entry_size - hashed_key_width = value_size is the only limit for the generated value.
 * @return Entry
 */
Entry generate_entry_with_id(uint64_t key_id, size_t entry_size, size_t hashed_key_width);


/**
 * @brief Create a new cuckoo hashing table. Insert all keywords into the table using cuckoo hashing. 
 * 
 * @param seed1 cuckoo seed 1
 * @param seed2 cuckoo seed 2
 * So either hash(keyword_seed ^ seed2) or hash(keyword_seed ^ seed2) points to the correct location in the hashing table.
 * @param swap_limit maximum number of swaps allowed for inserting a single entry into the hashing table.
 * @param keywords existing keywords to be inserted into the hashing table. 
 * @param blowup_factor decides the size of the hashing table. The size of the hashing table is blowup_factor * data.size().
 * @return std::vector<Entry> Return the non-empty hashing table if the insertion is successful. Otherwise, return an empty vector.
 */
std::vector<Key> cuckoo_insert(uint64_t seed1, uint64_t seed2, size_t swap_limit,
                                 std::vector<Key> &keywords, float blowup_factor);
