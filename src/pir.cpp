#include "pir.h"
#include "database_constants.h"
#include "external_prod.h"
#include "utils.h"

#include <cassert>

PirParams::PirParams(const uint64_t DBSize, const uint64_t first_dim_sz,
                     const uint64_t num_entries,
                     const uint64_t l, const uint64_t l_key,
                     const size_t pt_mod_width, const std::vector<int> ct_mods,
                     const size_t hashed_key_width, const float blowup_factor)
    : DBSize_(DBSize),
      seal_params_(seal::EncryptionParameters(seal::scheme_type::bfv)),
      num_entries_(num_entries), l_(l), l_key_(l_key),
      hashed_key_width_(hashed_key_width), blowup_factor_(blowup_factor) {


// =============== PARAMS CALCULATIONS ===============
  uint64_t pt_mod = generate_prime(pt_mod_width);
  // calculate the entry size in bytes automatically.
  entry_size_ =
      (seal::Modulus(pt_mod).bit_count() - 1) *
      DatabaseConstants::PolyDegree / 8;
  // seal parameters requires at lest three parameters: poly_modulus_degree,
  // coeff_modulus, plain_modulus Then the seal context will be set properly for
  // encryption and decryption.
  seal_params_.set_poly_modulus_degree(
      DatabaseConstants::PolyDegree); // example: a_1 x^4095 + a_2 x^4094 + ...

  seal_params_.set_coeff_modulus(
      CoeffModulus::Create(DatabaseConstants::PolyDegree, ct_mods));
  seal_params_.set_plain_modulus(pt_mod);

  // =============== VALIDATION ===============
  if (first_dim_sz < 128) {
    throw std::invalid_argument("Size of first dimension is too small");
  }
  // make sure if the first dimension is a power of 2.
  if ((first_dim_sz & (first_dim_sz - 1))) {
    throw std::invalid_argument("Size of database is not a power of 2");
  }
  if (get_num_entries_per_plaintext() == 0) {
    std::cerr << "Entry size: " << entry_size_ << std::endl;
    std::cerr << "Poly degree: " << DatabaseConstants::PolyDegree << std::endl;
    std::cerr << "bits per coeff: " << get_num_bits_per_coeff() << std::endl;
    throw std::invalid_argument("Number of entries per plaintext is 0, "
                                "possibly due to too large entry size");
  }
  // The first part (mult) calculates the number of entries that this database
  // can hold in total. (limits) num_entries is the number of useful entries
  // that the user can use in the database.
  if (DBSize_ * get_num_entries_per_plaintext() < num_entries) {
    std::cerr << "DBSize_ = " << DBSize_ << std::endl;
    std::cerr << "get_num_entries_per_plaintext() = "
              << get_num_entries_per_plaintext() << std::endl;
    std::cerr << "num_entries = " << num_entries << std::endl;
    throw std::invalid_argument("Number of entries in database is too large");
  }

  // =============== PARAMS CALCULATIONS ===============

  // Since all dimensions are fixed to 2 except the first one. We calculate the
  // number of dimensions here.
  const uint64_t ndim = 1 + log2((DBSize / first_dim_sz));
  // All dimensions are fixed to 2 except the first one.
  dims_.push_back(first_dim_sz);
  for (int i = 1; i < ndim; i++) {
    dims_.push_back(2);
  }

  // This for-loop calculates the sum of bits in the
  // first_context_data().parms().coeff_modulus(). This is used for calculating
  // the number of bits required for the base (B) in RGSW.
  auto modulus = seal_params_.coeff_modulus();
  int bits = 0;
  for (int i = 0; i < modulus.size() - 1; i++) {
    bits += modulus[i].bit_count();
  } 

  // The number of bits for representing the largest modulus possible in the
  // given context. See analysis folder. This line rounds bits/l up to the
  // nearest integer.
  base_log2_ = (bits + l - 1) / l;

  // Set up parameters for GSW in external_prod.h
  data_gsw.l = l;
  data_gsw.base_log2 = base_log2_;
  data_gsw.context = new seal::SEALContext(seal_params_);

  // The l used for RGSW(s) in algorithm 4.
  key_gsw.l = l_key;
  key_gsw.base_log2 = (bits + l_key - 1) / l_key; // same calculation method
  key_gsw.context = data_gsw.context;
}

size_t PirParams::get_num_entries_per_plaintext() const {
  size_t total_bits = get_num_bits_per_plaintext();
  return total_bits / (entry_size_ * 8);
}

size_t PirParams::get_num_bits_per_coeff() const {
  return seal_params_.plain_modulus().bit_count() - 1;
}

size_t PirParams::get_num_bits_per_plaintext() const {
  return get_num_bits_per_coeff() * seal_params_.poly_modulus_degree();
}

seal::EncryptionParameters PirParams::get_seal_params() const { return seal_params_; }
uint64_t PirParams::get_DBSize() const { return DBSize_; }
size_t PirParams::get_entry_size() const { return entry_size_; }
size_t PirParams::get_num_entries() const { return num_entries_; }
std::vector<uint64_t> PirParams::get_dims() const { return dims_; }
uint64_t PirParams::get_l() const { return l_; }
uint64_t PirParams::get_l_key() const { return l_key_; }
uint64_t PirParams::get_base_log2() const { return base_log2_; }
size_t PirParams::get_hashed_key_width() const { return hashed_key_width_; }
float PirParams::get_blowup_factor() const { return blowup_factor_; }


// ================== HELPER FUNCTIONS ==================

void print_entry(Entry entry) {
  int cnt = 0;
  for (auto &val : entry) {
    std::cout << (int)val << ", ";
    cnt += 1;
    if (cnt > 10) {
      break;
    }
  }
  std::cout << std::endl;
}


Entry gen_single_key(uint64_t key_id, size_t hashed_key_width) {
  Entry hashed_key;
  hashed_key.reserve(hashed_key_width);
  std::mt19937_64 rng(key_id);
  // generate the entire entry using random numbers for simplicity.
  for (int i = 0; i < hashed_key_width; i++) {
    hashed_key.push_back(rng() % 256);
  }
  return hashed_key;
}

void PirParams::print_values() const {
  std::cout << "==============================================================" << std::endl;
  std::cout << "                       PIR PARAMETERS                         " << std::endl;
  std::cout << "==============================================================" << std::endl;
  std::cout << "  DBSize_ (num plaintexts) \t\t\t= " << DBSize_ << std::endl;
  std::cout << "  Num entries per plaintext\t\t\t= "
            << get_num_entries_per_plaintext() << std::endl;
  std::cout << "  num_entries_(actually stored)\t\t\t= " << num_entries_ << std::endl;
  std::cout << "  entry_size_(byte)\t\t\t\t= " << entry_size_ << std::endl;
  std::cout << "  l_\t\t\t\t\t\t= " << l_ << std::endl;
  std::cout << "  l_key_\t\t\t\t\t= " << l_key_ << std::endl;
  std::cout << "  base_log2_\t\t\t\t\t= " << base_log2_ << std::endl;
  std::cout << "  dimensions_\t\t\t\t\t= [ ";
  for (const auto &dim : dims_) {
    std::cout << dim << " ";
  }
  std::cout << "]" << std::endl;
  std::cout << "  seal_params_.poly_modulus_degree()\t\t= "
            << seal_params_.poly_modulus_degree() << std::endl;

  auto coeff_modulus_size = seal_params_.coeff_modulus().size();
  std::cout << "  seal_params_.coeff_modulus().bit_count\t= [";

  for (std::size_t i = 0; i < coeff_modulus_size - 1; i++) {
    std::cout << seal_params_.coeff_modulus()[i].bit_count() << " + ";
  }

  std::cout << seal_params_.coeff_modulus().back().bit_count();
  std::cout << "] bits" << std::endl;
  std::cout << "  seal_params_.plain_modulus().bitcount()\t= "
            << seal_params_.plain_modulus().bit_count() << std::endl;

  std::cout << "  mod0: " << seal_params_.coeff_modulus()[0].value() << std::endl;
  std::cout << "  mod1: " << seal_params_.coeff_modulus()[1].value() << std::endl;

  std::cout << "==============================================================" << std::endl;
}
