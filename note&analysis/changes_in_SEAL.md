In `Encrypter.h`, add the following two functions for creating ciphertext while also remembering the seed.

```cpp
/**
This is a variant for the  encrypt_zero_symmetric that returns Serialiable<Ciphertext> directly.
This function saves seed inside the given ciphertext, which can be used to perform operation on the ciphertext
and then converted to serializable object.
@param destination The ciphertext to overwrite with the encrypted
@param[in] pool The MemoryPoolHandle pointing to a valid memory pool
@throws std::logic_error if a secret key is not set
@throws std::invalid_argument if pool is uninitialized */
inline void encrypt_zero_symmetric_seeded(Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
{
    encrypt_zero_internal(context_.first_parms_id(), false, true, destination, pool);
}

/**
This is similar to encrypt_zero_symmetric_seeded. But this is for encrypting the plaintext with secret key. */
inline void encrypt_symmetric_seeded(
    const Plaintext &plain, Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
{
    encrypt_internal(plain, false, true, destination, pool);
}
```

After doing this, please don't touch `data(1)`, otherwise, the seed will be changed.

---

In `rlwe.h`, add the following below `encrypt_zero_symmetric`: 

```cpp
/**
This serves Onion-PIR for creating the seeded RGSW-ciphertext. For the last l rows, we need
( -as+ e, a + sB ) \equiv (-a's + e, a' + sB) \equiv ( -(a - sB)s + e, a ), by observing a' = a - sB is also
uniformly at random.
@param secret_key The secret key used for encryption
@param B A vector of constant (scalar) multipliers, one for each coefficient.
@param context The SEALContext containing a chain of ContextData
@param parms_id Indicates the level of encryption
@param is_ntt_form If true, store ciphertext in NTT form
@param destination The output ciphertext, with seed stored in c_1.
*/
void prepare_seeded_gsw_key(
    const SecretKey &secret_key, const std::vector<uint64_t> &B, const SEALContext &context, parms_id_type parms_id, bool is_ntt_form,
    Ciphertext &destination);
```

Then in `rlwe.cpp`: 

```cpp

void prepare_seeded_gsw_key(
    const SecretKey &secret_key, const std::vector<uint64_t> &B, const SEALContext &context, parms_id_type parms_id, bool is_ntt_form,
    Ciphertext &destination) 
{
    // We use a fresh memory pool with `clear_on_destruction' enabled.
    MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

    auto &context_data = *context.get_context_data(parms_id);
    auto &parms = context_data.parms();
    auto &coeff_modulus = parms.coeff_modulus();
    auto &plain_modulus = parms.plain_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.poly_modulus_degree();
    auto ntt_tables = context_data.small_ntt_tables();
    size_t encrypted_size = 2;
    scheme_type type = parms.scheme();

    destination.resize(context, parms_id, encrypted_size);
    destination.is_ntt_form() = is_ntt_form;
    destination.scale() = 1.0;
    destination.correction_factor() = 1;

    // Create an instance of a random number generator. We use this for sampling
    // a seed for a second PRNG used for sampling u (the seed can be public
    // information. This PRNG is also used for sampling the noise/error below.
    auto bootstrap_prng = parms.random_generator()->create();

    // Sample a public seed for generating uniform randomness
    prng_seed_type public_prng_seed;
    bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<seal_byte *>(public_prng_seed.data()));

    // Set up a new default PRNG for expanding u from the seed sampled above
    auto ciphertext_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);

    // Generate ciphertext: (c[0], c[1]) = ( [-(a - sB)s + e]_q, a ) in BFV
    uint64_t *c0 = destination.data();
    uint64_t *c1 = destination.data(1);

    // Sample a uniformly at random
    // Sample non-NTT form and store the seed
    sample_poly_uniform(ciphertext_prng, parms, c1);
    for (size_t i = 0; i < coeff_modulus_size; i++)
    {
        // Transform the c1 into NTT representation
        ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
    }

    // Sample e <-- chi
    auto noise(allocate_poly(coeff_count, coeff_modulus_size, pool));
    SEAL_NOISE_SAMPLER(bootstrap_prng, parms, noise.get());

    // Calculate -((a - sB)s + e) (mod q) and store in c[0] in BFV
    for (size_t i = 0; i < coeff_modulus_size; i++)
    {
        // ! =============== NEW THINGS START ===============
        // First, compute c0 = sB, a polynomial-scalar multiplication
        multiply_poly_scalar_coeffmod(
            secret_key.data().data() + i * coeff_count, coeff_count, B[i], coeff_modulus[i], c0 + i * coeff_count);

        // Second, compute c0 = (a - c0) = (a - sB), a poly-poly subtraction
        sub_poly_coeffmod(
            c1 + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);

        // Third, compute c0 = (a - sB)s = c0 * s, a polypoly multiplication
        dyadic_product_coeffmod(
            secret_key.data().data() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
            c0 + i * coeff_count);
        // ! =============== NEW THINGS END ===============

        if (is_ntt_form)
        {
            // Transform the noise e into NTT representation
            ntt_negacyclic_harvey(noise.get() + i * coeff_count, ntt_tables[i]);
        }
        else
        {
            inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
        }

        // c0 = (a - sB)s + noise
        add_poly_coeffmod(
            noise.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
            c0 + i * coeff_count);
        // ((a - sB)s + noise, a) -> (-((a - sB)s + noise), a),
        negate_poly_coeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
    }

    size_t prng_info_byte_count =
        static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
    UniformRandomGeneratorInfo prng_info = ciphertext_prng->info();
    // Write prng_info to destination.data(1) after an indicator word
    c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
    prng_info.save(reinterpret_cast<seal_byte *>(c1 + 1), prng_info_byte_count, compr_mode_type::none);
}
```

