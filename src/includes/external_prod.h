#pragma once
#include "seal/seal.h"
#include <vector>

// A GSWCiphertext is a flattened 2lx2 matrix of polynomials
typedef std::vector<std::vector<uint64_t>> GSWCiphertext;

namespace gsw {

extern uint64_t l;
extern uint64_t base_log2;
extern seal::SEALContext const *context;

/*!
  Computes the external product between a GSW ciphertext and a decomposed BFV
  ciphertext.
  @param gsw_enc -GSW Ciphertext, should only encrypt 0 or 1 to prevent large
  noise growth
  @param rlwe_expansion - decomposed vector of BFV ciphertext
  @param ct_poly_size - number of ciphertext polynomials
  @param res_ct - output ciphertext
*/

void external_product(GSWCiphertext gsw_enc, seal::Ciphertext bfv,
                      size_t ct_poly_size, seal::Ciphertext &res_ct);

/*!
  Performs a gadget decomposition of a size 2 BFV ciphertext into 2 sets of
  rows of l polynomials (the 2 sets are concatenated into a single vector of
  vectors). Each polynomial coefficient encodes the value congruent to the
  original ciphertext coefficient modulus the value of base^(l-row).
  @param ct - input BFV ciphertext. Should be of size 2.
  @param output - output to store the decomposed ciphertext as a vector of
  vectors of polynomial coefficients
  @param pool - SEAL memory pool
*/
void decomp_rlwe(seal::Ciphertext ct,
                 std::vector<std::vector<uint64_t>> &output);

/*!
  Generates a GSW ciphertext from a BFV ciphertext query.

  @param query - input BFV ciphertext. Should be of size l * 2.
  @param gsw_key - GSW encryption of -s
  @param output - output to store the GSW ciphertext as a vector of vectors of
  polynomial coefficients
*/
void query_to_gsw(std::vector<seal::Ciphertext> query, GSWCiphertext gsw_key,
                  GSWCiphertext &output);

void encrypt_lwe_to_gsw();
} // namespace gsw