#pragma once

#include "database_constants.h"
#include "seal/seal.h"
#include <vector>
#include <stdexcept>

using namespace seal::util;
using namespace seal;

// Each entry is a vector of bytes
typedef std::vector<uint8_t> Entry;
typedef std::vector<Ciphertext> PirQuery;

class PirParams {
public:
    /*!
        PirParams constructor.
        @param DBSize - Number of plaintexts in database
        @param ndim - Number of database dimensions
        @param num_entries - Number of entries in database
        @param entry_size - Size of each entry in bytes
        */
    PirParams(uint64_t DBSize, uint64_t ndim, uint64_t num_entries, uint64_t entry_size): 
        DBSize_(DBSize),
        seal_params_(seal::EncryptionParameters(seal::scheme_type::bfv)),
        num_entries_(num_entries),
        entry_size_(entry_size)
        {
            uint64_t first_dim = DBSize >> (ndim - 1);
            if (first_dim < 128) {
                throw std::invalid_argument("Size of first dimension is too small");
            }
            if ((first_dim & (first_dim - 1))) {
                throw std::invalid_argument("Size of database is not a power of 2");
            }
            dims_.push_back(first_dim);
            for (int i = 1; i < ndim; i++) {
                dims_.push_back(2);
            }
            seal_params_.set_poly_modulus_degree(DatabaseConstants::PolyDegree);
            // seal_params_.set_coeff_modulus(CoeffModulus::Create(DatabaseConstants::PolyDegree, {55, 50, 50, 60}));
            // seal_params_.set_plain_modulus(PlainModulus::Batching(DatabaseConstants::PolyDegree, DatabaseConstants::PlaintextModBits));
            seal_params_.set_coeff_modulus({DatabaseConstants::CiphertextMod1, DatabaseConstants::CiphertextMod2});
            seal_params_.set_plain_modulus(DatabaseConstants::PlaintextMod);
        } 
    seal::EncryptionParameters get_seal_params() const;
    void print_values();
    uint64_t get_DBSize() const;
    std::vector<uint64_t> get_dims() const;
    // Calculates the number of entries that each plaintext can contain, aligning the end of an entry to the end of a plaintext.
    size_t get_num_entries_per_plaintext() const;
    size_t get_num_bits_per_coeff() const;
    // Calculates the number of bytes of data each plaintext contains, after aligning the end of an entry to the end of a plaintext.
    size_t get_num_bits_per_plaintext() const;
    size_t get_num_entries() const;
    size_t get_entry_size() const;

private:
    uint64_t DBSize_;                    // number of plaintexts in the database
    std::vector<uint64_t> dims_;                      // Number of dimensions
    size_t num_entries_;                 // Number of entries in database
    size_t entry_size_;                  // Size of single entry in bytes
    seal::EncryptionParameters seal_params_;
};


void print_entry(Entry entry);