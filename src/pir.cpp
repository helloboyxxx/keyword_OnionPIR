#include "pir.h"

#include <cassert>

seal::EncryptionParameters PirParams::get_seal_params() const { return seal_params_; }

uint64_t PirParams::get_DBSize() const { return DBSize_; }

std::vector<uint64_t> PirParams::get_dims() const { return dims_; }

uint64_t PirParams::get_l() const { return l_; }

uint64_t PirParams::get_base_log2() const { return base_log2_; }

void PirParams::print_values() {
  std::cout << "==============================================================" << std::endl;
  std::cout << "                       PIR PARAMETERS                         " << std::endl;
  std::cout << "==============================================================" << std::endl;
  std::cout << "  num_entries_                        = " << num_entries_ << std::endl;
  std::cout << "  l_                                   = " << l_ << std::endl;
  std::cout << "  base_log2_                           = " << base_log2_ << std::endl;
  std::cout << "  entry_size_                          = " << entry_size_ << std::endl;
  std::cout << "  DBSize_ (num plaintexts in database) = " << DBSize_ << std::endl;
  std::cout << "  DBCapacity (max num of entries)      = "
            << DBSize_ * get_num_entries_per_plaintext() << std::endl;
  std::cout << "  dimensions_                          = [ ";

  for (const auto &dim : dims_) {
    std::cout << dim << " ";
  }

  std::cout << "]" << std::endl;
  std::cout << "  seal_params_.poly_modulus_degree()       = " << seal_params_.poly_modulus_degree()
            << std::endl;

  auto coeff_modulus_size = seal_params_.coeff_modulus().size();
  std::cout << "  seal_params_.coeff_modulus().bit_count   = [";

  for (std::size_t i = 0; i < coeff_modulus_size - 1; i++) {
    std::cout << seal_params_.coeff_modulus()[i].bit_count() << " + ";
  }

  std::cout << seal_params_.coeff_modulus().back().bit_count();
  std::cout << "] bits" << std::endl;
  std::cout << "  seal_params_.coeff_modulus().size()      = "
            << seal_params_.coeff_modulus().size() << std::endl;
  std::cout << "  seal_params_.plain_modulus().bitcount()  = "
            << seal_params_.plain_modulus().bit_count() << std::endl;

  std::cout << "==============================================================" << std::endl;
}

size_t PirParams::get_num_entries_per_plaintext() const {
  size_t total_bits = get_num_bits_per_plaintext();
  return total_bits / (entry_size_ * 8);
}

size_t PirParams::get_entry_size() const { return entry_size_; }

size_t PirParams::get_num_entries() const { return num_entries_; }

size_t PirParams::get_num_bits_per_coeff() const {
  return seal_params_.plain_modulus().bit_count() - 1;
}

size_t PirParams::get_num_bits_per_plaintext() const {
  return get_num_bits_per_coeff() * seal_params_.poly_modulus_degree();
}

size_t PirParams::get_hashed_key_width() const { return hashed_key_width_; }

float PirParams::get_blowup_factor() const { return blowup_factor_; }

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