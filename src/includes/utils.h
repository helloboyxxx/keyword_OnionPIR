#pragma once
#include "seal/seal.h"
#include <iostream>


#ifdef _DEBUG
#define PRINT_INT_ARRAY(arr_name, arr, size) \
    do {                                     \
        std::cout << arr_name << ": [";      \
        for (int i = 0; i < size; ++i) {     \
            std::cout << arr[i];             \
            if (i < size - 1)                \
                std::cout << ", ";           \
        }                                    \
        std::cout << "]" << std::endl;       \
    } while (0)
#endif

#ifdef _BENCHMARK
#define PRINT_INT_ARRAY(arr_name, arr, size) ;  // do nothing
#endif


template <typename T> std::string to_string(T x) {
  std::string ret;
  if (x == 0) {
    return "0";
  }
  while (x) {
    ret += (x % 10) + '0';
    x /= 10;
  }
  reverse(ret.begin(), ret.end());
  return ret;
}

namespace utils {
/*!
    Helper function for multiply_poly_acum. Multiplies two operands together and
   stores the result in product_acum.
*/
inline void multiply_acum(uint64_t op1, uint64_t op2, __uint128_t &product_acum) {
  product_acum = product_acum + static_cast<__uint128_t>(op1) * static_cast<__uint128_t>(op2);
}

/*!
    Multiplies two polynomials in NTT form together and adds the result to a
   third polynomial in NTT form.
    @param ct_ptr - Pointer to the start of the data of the first polynomial
    @param pt_ptr - Pointer to the start of the data of the second polynomial
    @param size - Number of polynomial coefficients
    @param result - Pointer to the start of the data of the result polynomial
*/
inline void multiply_poly_acum(const uint64_t *ct_ptr, const uint64_t *pt_ptr, size_t size,
                               uint128_t *result) {
  for (int cc = 0; cc < size; cc += 32) {
    multiply_acum(ct_ptr[cc], pt_ptr[cc], result[cc]);
    multiply_acum(ct_ptr[cc + 1], pt_ptr[cc + 1], result[cc + 1]);
    multiply_acum(ct_ptr[cc + 2], pt_ptr[cc + 2], result[cc + 2]);
    multiply_acum(ct_ptr[cc + 3], pt_ptr[cc + 3], result[cc + 3]);
    multiply_acum(ct_ptr[cc + 4], pt_ptr[cc + 4], result[cc + 4]);
    multiply_acum(ct_ptr[cc + 5], pt_ptr[cc + 5], result[cc + 5]);
    multiply_acum(ct_ptr[cc + 6], pt_ptr[cc + 6], result[cc + 6]);
    multiply_acum(ct_ptr[cc + 7], pt_ptr[cc + 7], result[cc + 7]);
    multiply_acum(ct_ptr[cc + 8], pt_ptr[cc + 8], result[cc + 8]);
    multiply_acum(ct_ptr[cc + 9], pt_ptr[cc + 9], result[cc + 9]);
    multiply_acum(ct_ptr[cc + 10], pt_ptr[cc + 10], result[cc + 10]);
    multiply_acum(ct_ptr[cc + 11], pt_ptr[cc + 11], result[cc + 11]);
    multiply_acum(ct_ptr[cc + 12], pt_ptr[cc + 12], result[cc + 12]);
    multiply_acum(ct_ptr[cc + 13], pt_ptr[cc + 13], result[cc + 13]);
    multiply_acum(ct_ptr[cc + 14], pt_ptr[cc + 14], result[cc + 14]);
    multiply_acum(ct_ptr[cc + 15], pt_ptr[cc + 15], result[cc + 15]);
    multiply_acum(ct_ptr[cc + 16], pt_ptr[cc + 16], result[cc + 16]);
    multiply_acum(ct_ptr[cc + 17], pt_ptr[cc + 17], result[cc + 17]);
    multiply_acum(ct_ptr[cc + 18], pt_ptr[cc + 18], result[cc + 18]);
    multiply_acum(ct_ptr[cc + 19], pt_ptr[cc + 19], result[cc + 19]);
    multiply_acum(ct_ptr[cc + 20], pt_ptr[cc + 20], result[cc + 20]);
    multiply_acum(ct_ptr[cc + 21], pt_ptr[cc + 21], result[cc + 21]);
    multiply_acum(ct_ptr[cc + 22], pt_ptr[cc + 22], result[cc + 22]);
    multiply_acum(ct_ptr[cc + 23], pt_ptr[cc + 23], result[cc + 23]);
    multiply_acum(ct_ptr[cc + 24], pt_ptr[cc + 24], result[cc + 24]);
    multiply_acum(ct_ptr[cc + 25], pt_ptr[cc + 25], result[cc + 25]);
    multiply_acum(ct_ptr[cc + 26], pt_ptr[cc + 26], result[cc + 26]);
    multiply_acum(ct_ptr[cc + 27], pt_ptr[cc + 27], result[cc + 27]);
    multiply_acum(ct_ptr[cc + 28], pt_ptr[cc + 28], result[cc + 28]);
    multiply_acum(ct_ptr[cc + 29], pt_ptr[cc + 29], result[cc + 29]);
    multiply_acum(ct_ptr[cc + 30], pt_ptr[cc + 30], result[cc + 30]);
    multiply_acum(ct_ptr[cc + 31], pt_ptr[cc + 31], result[cc + 31]);
  }
}
void negacyclic_shift_poly_coeffmod(seal::util::ConstCoeffIter poly, size_t coeff_count,
                                    size_t shift, const seal::Modulus &modulus,
                                    seal::util::CoeffIter result);
void shift_polynomial(seal::EncryptionParameters &params, seal::Ciphertext &encrypted,
                      seal::Ciphertext &destination, size_t index);
} // namespace utils


// Inplace calculate the additive inverse of a seal::Plaintext
void negate_poly_inplace(seal::Plaintext &plain);

// Convert a 128-bit unsigned integer to a string
std::string uint128_to_string(__uint128_t value);

/**
 * @brief Construct a RGSW gadget. Notice that the gadget is from large to
 * small, i.e., the first row is B^(log q / log B -1), the final row is 1.
 */
std::vector<std::vector<__uint128_t>>
gsw_gadget(size_t l, uint64_t base_log2, size_t coeff_mod_count,
           const std::vector<seal::Modulus> &coeff_modulus);


// Generate a prime that is bit_width long
std::uint64_t generate_prime(size_t bit_width);