# Major Updates in OnionPIR

Many updates has been made since the 2021 OnionPIR paper. This document records most (hopefully all) the changes that improves the scheme. 

### Change of the size of dimensions

In the paper, the dimension is set to $128, 4, 4, \ldots$. The choice of the size of dimensions changed from $4 \to 2$. This is because a trick can be used for reducing the request size. 

### Modulus switching & ciphertext decomposition in dim 1

The 2021 OnionPIR paper uses a technique to decompose the ciphertext-plaintext product in the first dimension to reduce the noise growth. If not doing this, the size of the ciphertext must be larger for reserving enough space for noise. This hits the response size. However, this is resolved by a simple modulus switching after the server done retrieving the query. Hence, we cancel the modulus switching algorithm for a cleaner and faster server computation. 

### Delayed modulus optimization

Is this a new stuff?

```cpp
// Computes a dot product between the selection vector and the database for the
// first dimension with a delayed modulus optimization. Selection vector should
// be transformed to ntt.
std::vector<seal::Ciphertext> PirServer::evaluate_first_dim(std::vector<seal::Ciphertext> &selection_vector)
```





### Number Theoretic Transform (NTT)

NTT is used for speading up polynomial multiplication.



A short tutorial: https://youtu.be/Pct3rS4Y0IA?si=25VrCwBJuBjtHqoN







