#pragma once

#include "database_constants.h"
#include "external_prod.h"
#include "seal/seal.h"
#include <stdexcept>
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

#define PRINT_BAR DEBUG_PRINT("==============================================================");

// ================== NAMESPACES  ==================
using namespace seal::util;
using namespace seal;

// ================== TYPE DEFINITIONS ==================
// Each entry is a vector of bytes
typedef std::vector<uint8_t> Entry;
typedef Ciphertext PirQuery;
typedef uint64_t Key; // key in the key-value pair. 

// ================== CLASS DEFINITIONS ==================
class PirParams {
public:
  /*!
      PirParams constructor.
      @param DBSize - Number of plaintexts in database
      @param ndim - Number of database dimensions
      @param num_entries - Number of entries in database
      @param entry_size - Size of each entry in bytes
      @param l - Parameter l for GSW scheme
      @param hashed_key_width - width of the hashed key in bits. Default is 0, stands for no keyword support.
      @param blowup_factor - blowup factor for the database used in keyword support. Default is 1.0.
      */
  PirParams(uint64_t DBSize, uint64_t ndim, uint64_t num_entries,
            uint64_t entry_size, uint64_t l, uint64_t l_key,
            size_t hashed_key_width = 0, float blowup_factor = 1.0)
      : DBSize_(DBSize),
        seal_params_(seal::EncryptionParameters(seal::scheme_type::bfv)),
        num_entries_(num_entries), entry_size_(entry_size), l_(l),
        hashed_key_width_(hashed_key_width), blowup_factor_(blowup_factor) {

    // Since all dimensions are fixed to 2 except the first one. We calculate the first dimension here.
    uint64_t first_dim = DBSize >> (ndim - 1);
    if (first_dim < 128) {
      throw std::invalid_argument("Size of first dimension is too small");
    }
    if ((first_dim & (first_dim - 1))) {
      throw std::invalid_argument("Size of database is not a power of 2");
    }

    // First dimension must be a power of 2.
    dims_.push_back(first_dim); 
    for (int i = 1; i < ndim; i++) {
      dims_.push_back(2);
    }

    // seal parameters requires at lest three parameters: poly_modulus_degree, coeff_modulus, plain_modulus
    // Then the seal context will be set properly for encryption and decryption.
    seal_params_.set_poly_modulus_degree(DatabaseConstants::PolyDegree); // example: a_1 x^4095 + a_2 x^4094 + ... + a_4096 x^0
    if (DatabaseConstants::PolyDegree == 8192) {
      seal_params_.set_coeff_modulus(
          CoeffModulus::Create(DatabaseConstants::PolyDegree, {60, 60, 60}));
    } else {
      seal_params_.set_coeff_modulus(CoeffModulus::BFVDefault(DatabaseConstants::PolyDegree));
    }
    seal_params_.set_plain_modulus(DatabaseConstants::PlaintextMod);
    // seal_params_.set_plain_modulus(DatabaseConstants::LargePlaintextMod);

    // It is possible to have multiple entries in a plaintext?
    // Plaintext definition in: seal::Plaintext (plaintext.h).
    // DEBUG_PRINT("get_num_entries_per_plaintext() = " << get_num_entries_per_plaintext());

    // The first part (mult) calculates the number of entries that this database can hold in total. (limits)
    // num_entries is the number of useful entries that the user can use in the database.
    if (DBSize_ * get_num_entries_per_plaintext() < num_entries) {
      DEBUG_PRINT("DBSize_ = " << DBSize_);
      DEBUG_PRINT("get_num_entries_per_plaintext() = " << get_num_entries_per_plaintext());
      DEBUG_PRINT("num_entries = " << num_entries);
      throw std::invalid_argument("Number of entries in database is too large");
    }


    // This for-loop calculates the sum of bits in the first_context_data().parms().coeff_modulus().
    // In our case, we have 36 + 36 = 72 bits. This is used for calculating the number of bits required for the base (B) in RGSW.
    auto modulus = seal_params_.coeff_modulus();
    int bits = 0;
    for (int i = 0; i < modulus.size() - 1; i++) {
      bits += modulus[i].bit_count();
    } // bits = 72

    // The number of bits for representing the largest modulus possible in the given context. See analysis folder.
    // This line rounds bits/l up to the nearest integer. 
    base_log2_ = (bits + l - 1) / l;

    // Set up parameters for GSW in external_prod.h
    data_gsw.l = l;
    data_gsw.base_log2 = base_log2_;
    data_gsw.context = new seal::SEALContext(seal_params_);

    // The l used for RGSW(s) in algorithm 4.
    key_gsw.l = l_key;
    key_gsw.base_log2 = (bits + l_key - 1) / l_key;   // same calculation method 
    key_gsw.context = data_gsw.context;
  }
  seal::EncryptionParameters get_seal_params() const;
  void print_values();
  uint64_t get_DBSize() const;
  std::vector<uint64_t> get_dims() const;
  // Calculates the number of entries that each plaintext can contain, aligning
  // the end of an entry to the end of a plaintext.
  size_t get_num_entries_per_plaintext() const;
  // ? What is the "coeff" here? Why it is possible to have multiple bits in a coeff?
  // ?  For me it seems that this is the number of bits required to represent a single coefficient of the polynomial corresponds to the plaintext.
  size_t get_num_bits_per_coeff() const;
  // Calculates the number of bytes of data each plaintext contains, after
  // aligning the end of an entry to the end of a plaintext.
  size_t get_num_bits_per_plaintext() const;
  size_t get_num_entries() const;
  size_t get_entry_size() const;
  uint64_t get_l() const;
  uint64_t get_base_log2() const;
  size_t get_hashed_key_width() const;
  float get_blowup_factor() const;

private:
  uint64_t DBSize_;            // number of plaintexts in the database
  uint64_t l_;                 // l for GSW
  uint64_t base_log2_;         // log of base for GSW
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