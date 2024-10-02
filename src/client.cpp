#include "client.h"
#include "external_prod.h"
#include "pir.h"
#include "utils.h"


PirClient::PirClient(const PirParams &pir_params)
    : params_(pir_params.get_seal_params()), DBSize_(pir_params.get_DBSize()),
      dims_(pir_params.get_dims()), pir_params_(pir_params) {
  context_ = new seal::SEALContext(params_);
  evaluator_ = new seal::Evaluator(*context_);
  keygen_ = new seal::KeyGenerator(*context_);
  secret_key_ = &keygen_->secret_key();
  encryptor_ = new seal::Encryptor(*context_, *secret_key_);
  decryptor_ = new seal::Decryptor(*context_, *secret_key_);
}

PirClient::~PirClient() {
  delete context_;
  delete evaluator_;
  delete keygen_;
  delete encryptor_;
  delete decryptor_;
}

seal::Decryptor *PirClient::get_decryptor() { return decryptor_; }

GSWCiphertext PirClient::generate_gsw_from_key() {
  GSWCiphertext gsw_enc;
  auto sk_ = secret_key_->data();
  auto ntt_tables = context_->first_context_data()->small_ntt_tables();
  auto coeff_modulus = context_->first_context_data()->parms().coeff_modulus();
  auto coeff_mod_count = coeff_modulus.size();
  auto coeff_count = params_.poly_modulus_degree();
  std::vector<uint64_t> sk_ntt(params_.poly_modulus_degree() * coeff_mod_count);

  memcpy(sk_ntt.data(), sk_.data(), coeff_count * coeff_mod_count * sizeof(uint64_t));

  RNSIter secret_key_iter(sk_ntt.data(), coeff_count);
  inverse_ntt_negacyclic_harvey(secret_key_iter, coeff_mod_count, ntt_tables);

  key_gsw.encrypt_plain_to_gsw(sk_ntt, *encryptor_, *decryptor_, gsw_enc);
  key_gsw.gsw_ntt_negacyclic_harvey(gsw_enc); // transform the GSW ciphertext to NTT form
  return gsw_enc;
}

size_t PirClient::get_database_plain_index(size_t entry_index) {
  return entry_index / pir_params_.get_num_entries_per_plaintext();
}

std::vector<size_t> PirClient::get_query_indexes(size_t plaintext_index) {
  std::vector<size_t> query_indexes;
  size_t index = plaintext_index;
  size_t size_of_remaining_dims = DBSize_;

  for (auto dim_size : dims_) {
    size_of_remaining_dims /= dim_size;
    query_indexes.push_back(index / size_of_remaining_dims);
    index = index % size_of_remaining_dims;
  }

  return query_indexes;
}

PirQuery PirClient::generate_query(std::uint64_t entry_index) {

  // Get the corresponding index of the plaintext in the database
  size_t plaintext_index = get_database_plain_index(entry_index);
  std::vector<size_t> query_indexes = get_query_indexes(plaintext_index);
  PRINT_INT_ARRAY("query_indexes", query_indexes.data(), query_indexes.size());
  uint64_t coeff_count = params_.poly_modulus_degree(); // 4096

  // The number of bits required for the first dimension is equal to the size of the first dimension
  uint64_t msg_size = dims_[0] + pir_params_.get_l() * (dims_.size() - 1);
  uint64_t bits_per_ciphertext = 1; // padding msg_size to the next power of 2

  while (bits_per_ciphertext < msg_size)
    bits_per_ciphertext *= 2;

  seal::Plaintext plain_query(coeff_count); // we allow 4096 coefficients in the plaintext polynomial to be set as suggested in the paper.

  // Algorithm 1 from the OnionPIR Paper
  // We set the corresponding coefficient to the inverse so the value of the
  // expanded ciphertext will be 1
  uint64_t inverse = 0;
  uint64_t plain_modulus = params_.plain_modulus().value(); // example: 16777259
  seal::util::try_invert_uint_mod(bits_per_ciphertext, plain_modulus, inverse);

  // Add the first dimension query vector to the query
  plain_query[ query_indexes[0] ] = inverse;
  
  // Encrypt plain_query first. Later we will insert the rest.
  PirQuery query; // pt in paper
  encryptor_->encrypt_symmetric(plain_query, query);  // $\tilde c$ in paper

  auto l = pir_params_.get_l();
  auto base_log2 = pir_params_.get_base_log2();
  auto context_data = context_->first_context_data();
  auto coeff_modulus = context_data->parms().coeff_modulus();
  auto coeff_mod_count = coeff_modulus.size();  // 2 here, not 3. Notice that here we use the first context_data, not all of coeff_modulus are used.

  // The following two for-loops calculates the powers for GSW gadgets.
  __uint128_t inv[coeff_mod_count];
  for (int k = 0; k < coeff_mod_count; k++) {
    uint64_t result;
    seal::util::try_invert_uint_mod(bits_per_ciphertext, coeff_modulus[k], result);
    inv[k] = result;
  }

  // coeff_mod_count many rows, each row is B^{l-1},, ..., B^0 under different moduli
  std::vector<std::vector<__uint128_t>> gadget = gsw_gadget(l, base_log2, coeff_mod_count, coeff_modulus);

  // This for-loop corresponds to the for-loop in Algorithm 1 from the OnionPIR paper
  int filled_cnt = dims_[0];  // we have already filled these many coefficients
  for (int i = 1; i < query_indexes.size(); i++) {  // dimensions
    // we use this if statement to replce the j for loop in Algorithm 1. This is because N_i = 2 for all i > 0
    // When 0 is requested, we use initial encrypted value of PirQuery query, where the coefficients decrypts to 0. 
    // When 1 is requested, we add special values to the coefficients of the query so that they decrypts to correct GSW(1) values.
    if (query_indexes[i] == 1) {
      // ! pt is a ct_coeff_type *. It points to the current position to be written.
      auto ptr = query.data(0) + filled_cnt;  // points to the current collection of coefficients to be written
      for (int k = 0; k < l; k++) {
        for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++) {
          auto pad = mod_id * coeff_count;   // We use two moduli for the same gadget value. They are apart by coeff_count.
          __uint128_t mod = coeff_modulus[mod_id].value();
          // the coeff is (B^{l-1}, ..., B^0) / bits_per_ciphertext
          auto coef = gadget[mod_id][k] * inv[mod_id] % mod;
          ptr[k + pad] = (ptr[k + pad] + coef) % mod;
        }
      }
    }
    filled_cnt += l;
  }

  return query;
}

/**
 * @brief Generate two queries in cuckoo hashing 
 * 
 * @param seed1 seed for the first hash function
 * @param seed2 seed for the second hash function
 * @param table_size used to calculate the index
 * @param keyword keyword to be searched
 * @return std::vector<PirQuery> two queries generated
 */
std::vector<PirQuery> PirClient::generate_cuckoo_query(uint64_t seed1, uint64_t seed2, uint64_t table_size, Key keyword) {
  size_t index1 = std::hash<Key>{}(keyword ^ seed1) % table_size;
  size_t index2 = std::hash<Key>{}(keyword ^ seed2) % table_size;
  PirQuery query1 = PirClient::generate_query(index1);
  PirQuery query2 = PirClient::generate_query(index2);
  return {query1, query2};
}

void PirClient::cuckoo_process_reply(uint64_t seed1, uint64_t seed2, uint64_t table_size, Key keyword, std::vector<seal::Ciphertext> reply1, std::vector<seal::Ciphertext> reply2) {
  size_t index1 = std::hash<Key>{}(keyword ^ seed1) % table_size;
  size_t index2 = std::hash<Key>{}(keyword ^ seed2) % table_size;
  Entry entry1 = PirClient::get_entry_from_plaintext(index1, PirClient::decrypt_result(reply1)[0]);
  Entry entry2 = PirClient::get_entry_from_plaintext(index2, PirClient::decrypt_result(reply2)[0]);
  // check which entry has hashed keyword in the first half of the entry
  size_t hashed_key_width = pir_params_.get_hashed_key_width();
  if (entry1.size() < hashed_key_width || entry2.size() < hashed_key_width) {
    throw std::invalid_argument("Entry size is too small");
  } else {
    // calculate hashed keyword stored
    // ! How to calculate hashed keyword not clear. Shouldn't entry look like (hash(keyword)|value)?
    Entry value = get_value_from_replies(entry1, entry2, keyword, hashed_key_width);
    if (value.size() == 0) {
      throw std::invalid_argument("Keyword not found");
    }
    DEBUG_PRINT("Printing the value: ")
    print_entry(value);
  }
}


seal::GaloisKeys PirClient::create_galois_keys() {
  std::vector<uint32_t> galois_elts = {1};

  // Compression factor determines how many bits there are per message (and
  // hence the total query size), with bits per message = 2^compression_factor.
  // For example, with compression factor = 11 and bit length = 4096, we end up
  // with 2048 bits per message and a total query size of 2. The 2048 bits will
  // be encoded in the first 2048 coeffs of the polynomial. 2^compression_factor
  // must be less than or equal to polynomial modulus degree and bit_length.
  int compression_factor = std::log2(dims_[0] + pir_params_.get_l() * (dims_.size() - 1) * 2);

  size_t min_ele = params_.poly_modulus_degree() / pow(2, compression_factor) + 1;
  for (size_t i = min_ele; i <= params_.poly_modulus_degree() + 1; i = (i - 1) * 2 + 1) {
    galois_elts.push_back(i);
  }
  seal::GaloisKeys galois_keys;
  keygen_->create_galois_keys(galois_elts, galois_keys);
  return galois_keys;
}

std::vector<seal::Plaintext> PirClient::decrypt_result(std::vector<seal::Ciphertext> reply) {
  std::vector<seal::Plaintext> result(reply.size(), seal::Plaintext(params_.poly_modulus_degree()));
  for (size_t i = 0; i < reply.size(); i++) {
    decryptor_->decrypt(reply[i], result[i]);
  }

  return result;
}

Entry PirClient::get_entry_from_plaintext(size_t entry_index, seal::Plaintext plaintext) {
  // Offset in the plaintext in bits
  size_t start_position_in_plaintext = (entry_index % pir_params_.get_num_entries_per_plaintext()) *
                                       pir_params_.get_entry_size() * 8;

  // Offset in the plaintext by coefficient
  size_t num_bits_per_coeff = pir_params_.get_num_bits_per_coeff();
  size_t coeff_index = start_position_in_plaintext / num_bits_per_coeff;

  // Offset in the coefficient by bits
  size_t coeff_offset = start_position_in_plaintext % num_bits_per_coeff;

  // Size of entry in bits
  size_t entry_size = pir_params_.get_entry_size();
  Entry result;

  uint128_t data_buffer = plaintext.data()[coeff_index] >> coeff_offset;
  uint128_t data_offset = num_bits_per_coeff - coeff_offset;

  while (result.size() < entry_size) {
    if (data_offset >= 8) {
      result.push_back(data_buffer & 0xFF);
      data_buffer >>= 8;
      data_offset -= 8;
    } else {
      coeff_index += 1;
      uint128_t next_buffer = plaintext.data()[coeff_index];
      data_buffer |= next_buffer << data_offset;
      data_offset += num_bits_per_coeff;
    }
  }

  return result;
}


Entry get_value_from_replies(Entry reply1, Entry reply2, Key keyword, size_t hashed_key_width) {
  Entry hashed_key = gen_single_key(keyword, hashed_key_width);
  Entry value;
  value.reserve(reply1.size() - hashed_key.size());

  // we match the first hashed_key.size() elements of reply1 and reply2 with hashed_key
  // if the hashed_key matches one of them, we add the corresponding value to the result
  // If the hashed_key is not found in either, we return an empty entry
  if (reply1.size() < hashed_key.size() || reply2.size() < hashed_key.size()) {
    throw std::invalid_argument("Entry size is too small");
  } else {
    if (std::equal(hashed_key.begin(), hashed_key.end(), reply1.begin())) {
      DEBUG_PRINT("Keyword found in reply 1");
      value.insert(value.end(), reply1.begin() + hashed_key.size(), reply1.end());
    } else if (std::equal(hashed_key.begin(), hashed_key.end(), reply2.begin())) {
      DEBUG_PRINT("Keyword found in reply 2");
      value.insert(value.end(), reply2.begin() + hashed_key.size(), reply2.end());
    } else {
      value = {};
    }
  }

  return value;
}