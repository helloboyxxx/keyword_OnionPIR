The goal of this file is to help understand the GSW scheme and the implementation of `GSWCiphertext`in OnionPIR code. Let's start with my understanding of GSW scheme. 

### From TGSW to RGSW

RGSW is a ring variation of [GSW scheme](https://eprint.iacr.org/2013/340). I do not see any formal paper defining RGSW. However, I do find this particular paper helpful: [Faster Fully Homomorphic Encryption: Bootstrapping in less than 0.1 Seconds](https:/print.iacr.org/2016/870). This paper defines TLWE and TGSW. 

Conceptually, TFHE works on torus polynomial: $\mathbb{T}_N[X] = \mathbb{R}[X] / (X^N + 1) \mod 1$, where RGSW works on polynomial ring: $R[X] = \mathbb{Z}[X] / (X^N + 1)$. $N$ is the degree of the polynomial in both cases. The first definition is briefly given in: [OnionPIR: Response Efficient Single-Server PIR](https://eprint.iacr.org/2021/1081). 

Let's compare these two schemes.

#### TGSW

Given a base $B \in \mathbb{N}$ and a length parameter $\ell \in \mathbb{Z}^+$, we define a gadget vector:
$$
g^{(\ell \times 1)} = (1/B, \ldots, 1/B^\ell)^T
$$

> Example: $B = 10, \ell = 3, g = (1/10^1, 1/10^2, 1/10^3)$.

Then we use this vector to create TGSW gadget $G$. 
$$
G=\mathbf{I}_2 \otimes g=\left[\begin{array}{ll}
g & 0 \\
0 & g
\end{array}\right] \in \mathbb{T}_N[X]^{2 \ell \times 2}
$$




$$
\text{TGSW ciphertext: }C = Z + \mu \cdot G
$$

Where $Z$ is $2\ell$ rows of $\operatorname{TLWE}(0)$, $\mu$ is the message of this TGSW ciphertext. 

#### RGSW

Given a base $B \in \mathbb{N}$, and the length parameter $\ell \in \mathbb{Z}^+$, RGSW gadget:
$$
g^{(\ell  \times 1)} = \left(B^{\log q / \log B-1}, B^{\log q / \log B-2}, \cdots, B^{\log q / \log B- \ell }\right)
$$

Where $q$ is the coefficient modulus for ciphertext. In our implementation, $\log q / \log B = l$.

> Example: $B = 10, l = 3, g = (10^2, 10^1, 10^0)$.



#### The connection

In application, we deal with TGSW and RGSW in the same way, but only in different range. Since we cannot express $\mathbb{R}$ in infinite precision – we are in discrete case – TGSW is actually implemented as RGSW. RGSW has integer values from 1 to $q$ and 1 to $t$, where TGSW has discret values from 0 to 1. They share all the algorithms while only differs in the coefficients space.

#### Gadget Decomposition LWE samples:

Gadgets are used for both encrypting the GSW ciphertext, and to decompose LWE ciphertext during the external product.

Let $\pmb{v}$ be a TLWE sample. The decomposition of $\pmb{v}$ outputs an element on a polynomial ring: $\pmb{u} = \operatorname{Decomp}(\pmb{v}) \in \mathcal{R}$. Then a correct decomposition means $\| \pmb{u} \cdot G - \pmb{v}\|_\infty < \varepsilon $. We can think of decomposition as a way we extract bits from numbers.

Example on constant polynomials:

- TGSW: $B = 10, \ell = 3, g = (1/10, 1/10^2, 1 / 10^3)$, then decomposing $v = 0.468$ becomes: $\operatorname{Decomp}(v) = (4, 6, 8)$.
- RGSW: $B = 10, \ell = 3, g = (10^2, 10^1, 10^0)$, then decomposing $v = 839$ becomes: $\operatorname{Decomp}(v) = (8, 3, 9)$.

#### External Product and the Usage of Gadgets

Check theorem 3.14 in https://eprint.iacr.org/2016/870 to for the details of external product. In the proof, at some point, the decomposed LWE ($\pmb{u}$) is multiplied by the gadget ($\pmb{h}$) in the GSW ciphertext. We see a cancelation during this multiplication, makes the homomorphic multiplication possible under the hood.

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/Screenshot 2024-08-17 at 3.15.43 PM.png " style="width:60%;" />
    <figcaption>  </figcaption>
  </figure>
</center>





### Interpretation v.s. Storage

> We can store RGSW in RLWE form, but shouldn't interpret it as rows of RLWE. Since RGSW and TGSW are actually the same thing, I will use RGSW here.

The first thing to notice is is that we should not interpret each row of RGSW as RLWE (BFV), even though we can (and will) represent them in RLWE form. The $Z$ matrix are rows of RLWE(0). If we treat RLWE as black box, then adding extra values to the coefficients of RLWE will make the ciphertext unpredictable without opening the black box. In fact, we can encrypt a message to a GSW ciphertext, but cannot decrypt the ciphertext and get the message back. In our case, BFV scheme scales the message by a factor ($\Delta$) during the encryption state. Check [Introduction to the BFV encryption scheme](https://inferati.com/blog/fhe-schemes-bfv) for an introduction to BFV scheme. 

In our case, since we can store each row or RGSW as RLWE, we can use a very specific trick to pack the query, and use the algorithm 3 in Onion-Ring ORAM as a subroutine to unpack the query. By doing this, we reduce the online communication. The following is an important observation. I will use the notation in the link above.

In BFV scheme, we have: 
$$
\operatorname{BFV}(0) =
\begin{cases}
C_1 = [-(a \cdot SK + e)\cdot u + e_1]_q = [-a \cdot SK \cdot u - e\cdot u + e_1]_q\\
C_2 = [a \cdot u + e_2]_q
\end{cases}
$$
Therefore, if we only look at the first $l$ rows of a RGSW ciphertext, the $i^{\text{th}}$ row looks like: 
$$
\begin{align*}
\operatorname{RGSW}(M)_i &= Z_i + M \cdot G_i = 
\left(\;
C_{i, 1} + M g_i, \;
C_{i, 2}
\;\right)\\
&=
\left(\;
-(a \cdot SK + e)\cdot u + e_1 + M g_i, \;
C_{i, 2}
\;\right)\\
&= \operatorname{BFV^*}(M g_i/\Delta)

\end{align*}
$$

Here, I am using $\operatorname{BFV^*}( M g_i / \Delta)$  for a simpler expression. It is not "real" as we won't get the exact RGSW ciphertext if we encrypt $M g_i / \Delta$ when $\Delta > Mg_i$ for each row. The simple reason is: in a discrete case, this division would give 0.

Next, the bottom $l$ rows. Let $j \in [l]$ but represent the index of the second $l$ rows. So, $Z_j$ actually means $Z_{j + l}$.
$$
\begin{align*}
\operatorname{RGSW}(M)_j 
&= Z_j + M \cdot G =
\left(\;
C_{j, 1}, \;
C_{j, 2} + Mg_j
\;\right)\\
&=
\left(\;
-(a \cdot SK + e)\cdot u + e_1, \;
a \cdot u + e_2 + Mg_i
\;\right)\\

\end{align*}
$$
If we treat the second term as a new $C_{j, 2}'$, decrypting this row using BFV decryption gives us: 
$$
\begin{align*}
\text{message}(\operatorname{RGSW}(M)_j) &= 
\left[\lfloor \left( 
C_{j, 1} + (C_{j, 2} + Mg_j) \cdot \mathrm{SK} 
\right)
/ \Delta \rceil\right]_t\\
&= \left[\lfloor 
\left(\left(
-a \cdot u \cdot \mathrm{SK} - e \cdot u + e_1 \right) 
+ (a \cdot u \cdot \mathrm{SK} + e_2 \cdot \mathrm{SK} + Mg_i \cdot \mathrm{SK})
\right)
/ \Delta 
\rceil\right]_t\\
&\approx (Mg_j/ \Delta) \cdot \mathrm{SK}\\
&\Updownarrow\\
\operatorname{RGSW}(M)_j &= \operatorname{BFV^*}((Mg_j/ \Delta) \cdot \mathrm{SK})

\end{align*}
$$



Then the trick is to perform external product betweeen $\operatorname{RGSW}(\mathrm{SK})$ and the first $l$ rows, $\operatorname{BFV^*}(Mg_i/\Delta)$, to recreate the second $l$ rows of the query RGSW ciphertexts.
$$
\operatorname{RGSW}(\mathrm{SK}) \boxdot \operatorname{BFV^*}(Mg_i/\Delta) = \operatorname{BFV^*}((Mg_i/\Delta) \cdot SK)
$$



These are slightly different from what we had in [Onion Ring ORAM: Efficient Constant Bandwidth Oblivious RAM from (Leveled) TFHE](https://eprint.iacr.org/2019/736): 

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240820235754193.png " style="width:60%;" />
    <figcaption> Wrong statement </figcaption>
  </figure>
</center>
Wrong because encrypting message $\mu$ won't decomposing it. Instead, it just scales by different factors. It is also almost impossible to decrypt it if using BFV.



<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240821000206810.png " style="width:60%;" />
    <figcaption> Different RLWE scheme results in different expression</figcaption>
  </figure>
</center>




Details in BFV diff from TLWE:
- Decrypting TLWE $C=\left(c_1, c_2\right): \operatorname{Dec}(c)=\lfloor C_2-SK-\cdot C_1\rceil$
- Decrypting BFV $C=\left(C_1, C_2\right): \operatorname{Dec}(C)=\left[\frac{t\left[C_1+C_2 \cdot S K\right]_q}{q}\right]_t$
- Enc in TLWE: $c=\left(c_1, c_2\right)=\left(c_1, c_1 \cdot s k+\mu+e\right), C_1$ random
- Enc in zFV:C=\{ $\left.\begin{array}{l}{\left[-(a \cdot S K+e) r+e_1+\left\lfloor\left.\frac{q}{t} \right\rvert\, \cdot \mu\right]_q\right.} \\ {\left[a \cdot r+e_2\right]_q}\end{array}\right\}$
$\Delta$ scaling factor









