The goal here is to understand that is the `bits` and why is the `base_log2_` calculated this way. 

In the explanation for `SEALContext` class in `SEAL/native/src/seal/context.h`, it has: "By default, `SEALContext` creates a chain of `SEALContext::ContextData` instances. The first one in the chain corresponds to special encryption parameters that are reserved to be used by the various key classes (SecretKey, PublicKey, etc.)." The GSW gadget is used for decomposing RLWE ciphertext in the external product. Hence, the modulus must be large enough to express any ciphertext. 

Toy example: If $q = 73, l = 3$, what is $B$ if we set $B$ as some power of 2.

Now, in the code, the number of bits we can use for storing a default BFV coefficient is `bits`.  Specifically, `bits = 72` when poly_modulus_degree is set to 4096. As for `base_log2_`, check the calculation below. 
$$
\begin{align*}
B^{l} \geq 2^\mathbf{bits}\\
\log_2 B^l \geq \mathbf{bits}\\
l \cdot \log_2B \geq \mathbf{bits}\\
\log_2B \geq \frac{\mathbf{bits}}{l}
\end{align*}
$$

We also want $B$ to be small for better precision. 

![image-20240808235003929](https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240808235003929.png)











