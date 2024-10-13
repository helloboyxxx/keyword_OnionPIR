#pragma once

#include "seal/seal.h"
#include "database_constants.h"
#include <vector>

// ================== MACROs ==================
#define CURR_TIME std::chrono::high_resolution_clock::now()
#define TIME_DIFF(start, end) std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()


// print for debug. Easily turn on/off by defining _DEBUG
#ifdef _DEBUG
#define DEBUG_PRINT(s) std::cout << s << std::endl;
#endif

#ifdef _BENCHMARK
#define DEBUG_PRINT(s) ; // do nothing
#endif

#define BENCH_PRINT(s) std::cout << s << std::endl;

#define PRINT_BAR DEBUG_PRINT("==============================================================");

// ================== NAMESPACES  ==================
using namespace seal::util;
using namespace seal;

// ================== TYPE DEFINITIONS ==================
// Each entry is a vector of bytes
typedef std::vector<uint8_t> Entry;
typedef Ciphertext PirQuery;
typedef Serializable<Ciphertext> SeededPirQuery;
typedef uint64_t Key; // key in the key-value pair. 

// ================== CLASS DEFINITIONS ==================
class PirParams {
public:
  /*!
  PirParams constructor.
  @param DBSize - Number of plaintexts in database
  @param first_dim_sz - Size of the first dimension of the database
  @param num_entries - Number of entries that will be stored in the database
  @param l - Parameter l for GSW scheme
  @param hashed_key_width - width of the hashed key in bits. Default is 0, stands for no keyword support.
  @param blowup_factor - blowup factor for the database used in keyword support. Default is 1.0.
  */
  PirParams(const uint64_t DBSize, const uint64_t first_dim_sz,
            const uint64_t num_entries,
            const uint64_t l, const uint64_t l_key,
            const size_t plain_mod_width, const std::vector<int> ct_mods, const size_t hashed_key_width = 0,
            const float blowup_factor = 1.0);


  // ================== getters ==================
  /**
    * @brief Calculates the number of entries that each plaintext can contain,
    aligning the end of an entry to the end of a plaintext.
   */
  size_t get_num_entries_per_plaintext() const;
  size_t get_num_bits_per_coeff() const;

  /**
   * @brief Calculates the number of bytes of data each plaintext contains,
   * after aligning the end of an entry to the end of a plaintext.
   */
  size_t get_num_bits_per_plaintext() const;
  seal::EncryptionParameters get_seal_params() const;
  uint64_t get_DBSize() const;
  size_t get_num_entries() const;
  size_t get_entry_size() const;
  std::vector<uint64_t> get_dims() const;
  uint64_t get_l() const;
  uint64_t get_l_key() const;
  uint64_t get_base_log2() const;
  size_t get_hashed_key_width() const;
  float get_blowup_factor() const;


  void print_values() const;

private:
  uint64_t DBSize_;            // number of plaintexts in the database
  uint64_t l_;                 // l for RGSW
  uint64_t l_key_;             // l for key RGSW
  uint64_t base_log2_;         // log of base for RGSW
  std::vector<uint64_t> dims_; // Number of dimensions
  size_t num_entries_;         // Number of entries in database
  size_t entry_size_;          // Size of single entry in bytes
  seal::EncryptionParameters seal_params_;
  size_t hashed_key_width_;
  float blowup_factor_;
};

// ================== HELPER FUNCTIONS ==================

void print_entry(Entry entry);


// Given a key_id and the hashed_key_width, generate a random key using random number generator.
std::vector<uint8_t> gen_single_key(uint64_t key_id, size_t hashed_key_width);