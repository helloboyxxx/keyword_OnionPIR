In `Encrypter.h`, add the following two functions for creating ciphertext while also remembering the seed.

```cpp
        /**
        This is a variant for the  encrypt_zero_symmetric that returns Serialiable<Ciphertext> directly.
        This function saves seed inside the given ciphertext, which can be used to perform operation on the ciphertext
        and then converted to serializable object.
        @param destination The ciphertext to overwrite with the encrypted
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero_symmetric_seeded(Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero_internal(context_.first_parms_id(), false, true, destination, pool);
        }

        inline Serializable<Ciphertext> ciphertext_to_serializable(Ciphertext &ciphertext)
        {
            return Serializable<Ciphertext>(std::move(ciphertext));
        }
```

After doing this, please don't touch `data(1)`, otherwise, the seed will be changed.

