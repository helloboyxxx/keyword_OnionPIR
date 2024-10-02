### Pre-flight: 

- Refreshing memory & notations
- The main fix
- New tricks

### Refresh & Notations

$\mathsf{RLWE}$ defined on $R[X] = \mathbb{Z}[X] / (X^N + 1)$: 
$$
\begin{align*}
\mathsf{RLWE}(m) &= (c_0, c_1) = (a, a \cdot s + e + m)\\
\mathsf{RGSW}(m) &= Z + m \cdot G\\
G&=\mathbf{I}_2 \otimes g=\left[\begin{array}{ll}
g & 0 \\
0 & g
\end{array}\right]\\
g^{(\ell  \times 1)} &= \left(B^{\log q / \log B-1}, B^{\log q / \log B-2}, \cdots, B^{\log q / \log B- \ell }\right)\\
\end{align*}
$$

Notice: $\mathsf{RLWE}$ puts $m$ in higher bits by scaling. $\mathsf{RGSW}$ is not scaling. Actually, $\mathsf{RGSW}$ is almost impossible to decrypt. 

We can reconstruct $\mathsf{RGSW}(m)$ using $l$ many $\mathsf{RLWE}$ ciphertexts and $\mathsf{RGSW}(-s)$.
$$
\begin{align*}
\mathsf{RGSW}(m) \Leftrightarrow \set{\mathsf{RLWE}^*(m B^{l-1}), \mathsf{RLWE}^*(m  B^{l-1}) \ldots, \mathsf{RLWE}^*(m  B^0)}\\
\mathsf{RLWE}^*(m B^k) = \mathsf{RLWE}(0) + (0, mB^k)
\end{align*}
$$

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240906024048238.png " style="width:40%;" />
  </figure>
</center>


Actual input / output (**correct me if I am wrong**): 
$$
\begin{align*}
&\bold{Input: \;\;}c = \mathsf{RLWE}^*\left(\sum_{i = 0}^{n - 1} m_i X^i \right), m_i \in \mathbb{Z}_q\\
&\bold{Output: \;\; } c_i = \mathsf{RLWE}^* \left(n \cdot m_i \right), 0 \leq i < n
\end{align*}
$$
Where $m_nX^n$ is the highest degree term in the polynomial. 

Only one Subs is enough: https://www.usenix.org/system/files/sec22fall_mahdavi.pdf

OpenMind implementation. 

==Possible to reuse Galois keys.==




### The Main Fix: 

Explicitally coefficients of the $\mathsf{RLWE}$ ciphertext in QueryPack so that those coefficients expands to correct $\mathsf{RGSW}$ components. 

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240906092829793.png " style="width:40%;" />
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/Screenshot 2024-09-06 at 9.31.09 AM.png " style="width:40%;" />
  </figure>
</center>

Currently, I hard-coded the algorithm when assuming $N_2 = \cdots = N_d = 2$. This cuts half of the external product in higher dimension computation.



### New tricks: 

- Modulus switching.
- Don't do decomposition for the first dimension. 
- Different bit length: $\log q = 72, \log t = 25$. Why: seal restricts this length. For $n = 4096$, there are $109$ bits can be used for everything. $\set{36, 36, 37}$. However, only the first two can be used for actual polynomial coefficients. Similarly, $n = 8192$, it allows 218 bits in total. Can we use smaller bits? $\set{32, 32, 45}$? Not really. 124 bit $q$  ? 
- Should use larger $l$ because we have smaller room for error. 
- Cheetah: https://eprint.iacr.org/2022/207.pdf . After modulus switching, drop some least significant bits.



LWE estimator: https://github.com/malb/lattice-estimator

level of security . Should be above 100 bit.

1. Fix n 
2. Fix distribution of error and secret key.





















