# Fix of the QueryPack algorithm

A simple result is that $b_i$ must not be bit vectors. Each entry in $b_i$ must has $f$ values, where $f = 1$ for the first dimension and $f = l$ for the rest dimensions.

### Exsisting supports in the paper.

- There are three for-loops in QueryPack algorithm. The third loop exists for some reason.
- Correspondinly, line 11 to line 14 of QueryUnpack algorithm has their meaning. 
- In Section 4.3 Query Compression, in the last paragraph of **Query packing**, it has "concatenating them gives a plaintext vector of size $256 + 4l (d − 1)$". $d$ is the number of dimensions of the hypercube. If we don't want to use "splitting" in the first dimension, we should use 128 instead of 256 entries for the first dimension. For the rest, 4 in $4l(d-1)$ is $N_i, \forall i \in \set{2, \ldots, d}$. In each dimension, we must insert $l$ **values** into `pt`.
- Each RGSW ciphertext "consists" of $2l$ BFV ciphertexts. These $l$ **values** "corresponds" to the $l$ rows of RGSW ciphertext.



### What do we need to pack? The high-level.

The goal is to have correct expanded value:

- The first dimension has $N_1 = 128$ many $\mathrm{BFV}(0)$ or $\mathrm{BFV}(1)$. Nothing too special here.
- Rest dimensions each has 2 or 4 $\mathrm{RGSW}$ ciphertexts, encrypting 0 or 1. (2 or 4 depends on implementation).

Since we want to use algorithm 3 in [Onion Ring ORAM](https://eprint.iacr.org/2019/736), where the output contains only $\mathrm{BFV}$ ciphertexts, we need to reconstruct $\mathrm{RGSW}$ ciphertexts using these $\mathrm{BFV}$ ciphertexts.

Recap of $\mathrm{RGSW}$ encryption:

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240716232306296.png " style="width:30%;" />
    <figcaption>  </figcaption>
  </figure>
</center>

An important but not trivial "observation": the top $l$ rows of $\mathbf{C}$ can be viewed as $\mathrm{BFV}(\mu \cdot (-s) / B^k)$, the bottom $l$ rows of $\mathbf{C}$ can be viewed as $\mathrm{BFV}( \mu / B^k)$, where $1 \leq k \leq l$ in both cases. See details in the end.

In our case, the message $\mu \in \set{0, 1}$. This makes the packing simpler. Together with another trick for reconstrucing the $\mathrm{RGSW}$ ciphertext (by using external product), we only need $l$ many $\mathrm{BFV}$ ciphertexts to be expanded. Specifically: 
$$
\mathrm{RGSW}(b_{i, j}) \Leftrightarrow \set{\mathrm{BFV}(b_{i, j} / B^1), \mathrm{BFV}(b_{i, j} / B^2) \ldots, \mathrm{BFV}(b_{i, j} / B^l)}
$$


The goal is to pack **some specific values** inside coefficients of a single $\mathrm{BFV}$ ciphertext, where these values should be expanded to the BFV ciphertexts described above. The following explains these "**specific values**".



### How do we pack? More details.

The output in algorithm 3 in Onion Ring ORAM has a $n$ in each output, where $n$ is the degree of the polynomial ring $\mathcal{R} = \mathbb{Z}[x] / (x^n + 1)$ we are using in $\mathrm{BFV}$. For plaintexts, we use $\mathcal{R}_t = \mathcal{R} \mod t = \mathbb{Z}_t[x] / (x^n + 1)$; for ciphertexts, we use $\mathcal{R}_q = \mathcal{R} \mod q = \mathbb{Z}_q[x] / (x^n + 1)$.  $t, q$ should both be prime.

So, to get the normal value, we should divide the value by $n$ when packing. In the following, let $b = b_{i, j} \in \set{0, 1}$.

Start with the simple **first dimension**: we want the output to encrypt $\mathrm{BFV}(b)$. Here, if we treat $b \in \mathcal{R}_t$ as a constant polynomial, then the packed value should be it's multiplicative inverse $b/n \in \mathcal{R}_t$, which numerical value equivalent to $b \cdot (1/n) \in \mathbb{Z}_t$. This is possible to find because $\mathbb{Z}_t$ is a field.

The **rest dimensions** are similar: for each $\mathrm{BFV}(b / B^k), 1 \leq k \leq l$, we pack $b \cdot (1/B^k) \cdot (1/n)$ into its corredsponding coefficient. Again, both $(1/B^k)$ and $(1/n)$ are can be calculated easily in the field.

---

### The "Observation":

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240716232958662.png " style="width:50%;" />
    <figcaption>  </figcaption>
  </figure>
</center>

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240716233024254.png " style="width:50%;" />
    <figcaption>  </figcaption>
  </figure>
</center>
#### Second Though:

A huge flaw: we cannot actually use $B^k$ in plaintext. Therefore, it is actually invalid to write $\operatorname{BFV}(b / B^k)$. 

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240730222740621.png " style="width:50%;" />
    <figcaption> Onion-Ring ORAM </figcaption>
  </figure>
</center>

However, using SEAL there is a way to somehow encode $B^k$ in a BFV ciphertext.

```
// SEAL/native/examples/1_bfv_basics.cpp
For example, if poly_modulus_degree is 4096, the coeff_modulus could consist of three 36-bit primes (108 bits).
```













### Question: 

Do we really need the trick for not packing the first $l$ rows of RGSW ciphertext? It increase a little bit a server side compurational cost (about a hundred external product) and a bit of noise. But adding these values won't increase the communication cost. Creating the query vector is also almost free?

Is algorithm 3 in Onion Ring ORAM buggy? Can use use other input values besides $\mathbb{B}_n[X]$?

I am not 100% sure about whether BFV is working on a polynomial ring. Only know definition of TLWE.





















### TODO: 

Do some simple trick to test this GSW(0)



















