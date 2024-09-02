#include "utils.h"
#include <iomanip>

void utils::negacyclic_shift_poly_coeffmod(seal::util::ConstCoeffIter poly, size_t coeff_count,
                                           size_t shift, const seal::Modulus &modulus,
                                           seal::util::CoeffIter result) {
  if (shift == 0) {
    set_uint(poly, coeff_count, result);
    return;
  }

  uint64_t index_raw = shift;
  uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
  for (size_t i = 0; i < coeff_count; i++, poly++, index_raw++) {
    uint64_t index = index_raw & coeff_count_mod_mask;  // shifted index, possibly wrapping around
    if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !*poly) {
      // for those entries that are not wrapped around
      result[index] = *poly;
    } else {
      // For wrapped around entries, we fill in additive inverse.
      result[index] = modulus.value() - *poly; 
    }
  }
}

void utils::shift_polynomial(seal::EncryptionParameters &params, seal::Ciphertext &encrypted,
                             seal::Ciphertext &destination, size_t index) {
  auto encrypted_count = encrypted.size();
  auto coeff_count = params.poly_modulus_degree();
  auto coeff_mod_count = params.coeff_modulus().size() - 1;
  destination = encrypted;
  for (int i = 0; i < encrypted_count; i++) {
    for (int j = 0; j < coeff_mod_count; j++) {
      negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count), coeff_count, index,
                                     params.coeff_modulus()[j],
                                     destination.data(i) + (j * coeff_count));
    }
  }
}


void negate_poly_inplace(seal::Plaintext &plain) {
  std::cout << "TODO" << std::endl;
}


std::string uint128_to_string(__uint128_t value) {
    // Split the 128-bit value into two 64-bit parts
    uint64_t high = value >> 64;
    uint64_t low = static_cast<uint64_t>(value);

    std::ostringstream oss;

    // Print the high part, if it's non-zero, to avoid leading zeros
    if (high != 0) {
        oss << high << " * 2^64 + " << low;
    } else {
        oss << low;
    }
    return oss.str();
}



std::vector<std::vector<__uint128_t>> gsw_gadget(size_t l, uint64_t base_log2, size_t coeff_mod_count,
                const std::vector<seal::Modulus> &coeff_modulus) {
  // Create RGSW gadget.
  std::vector<std::vector<__uint128_t>> gadget(coeff_mod_count, std::vector<__uint128_t>(l));
  for (int i = 0; i < coeff_mod_count; i++) {
    __uint128_t mod = coeff_modulus[i].value();
    __uint128_t pow = 1;
    for (int j = l - 1; j >= 0; j--) {
      gadget[i][j] = pow;
      pow = (pow << base_log2) % mod;
    }
  }

// #ifdef _DEBUG
//   for (int i = 0; i < coeff_mod_count; i++) {
//     std::cout << "Gadget for mod " << i << ": " << std::endl;
//     for (int j = 0; j < l; j++) {
//       std::cout << uint128_to_string(gadget[i][j]) << " ";
//     }
//     std::cout << std::endl;
//   }
// #endif

  return gadget;
}