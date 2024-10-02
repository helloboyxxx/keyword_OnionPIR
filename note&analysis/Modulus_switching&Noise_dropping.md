### Modulus Switching

$$
\begin{align*}
a'_i = \text{round}(a_i q'/q)\\
b'_i = \text{round}(b_i q'/q)
\end{align*}
$$

Noise growth is in $O(\sqrt {n \log n})$ or $O(\sqrt n)$, $n$ is the degree of the polynomial. In SEAL, $\log q' \approx (\log q)/2$, thereby it cuts the response size by half. 

### Noise Dropping

$$
(a, as + \Delta m + e) = (a, b) = (a_H \cdot 2^i + a_L, b_H \cdot 2^j + b_L)
$$

Decryption looks like: 
$$
\begin{align*}
(b - as) &= (b_H \cdot 2^j + b_L) - (a_H \cdot 2^i + a_L)\cdot s\\
&= (b_H \cdot 2^j - a_H \cdot s \cdot 2^i) + (b_L - \underbrace{a_L \cdot s}_{\text{noise?}})
\end{align*}
$$



I calculated the bound for the variance of each coefficient, which is (almost) the same as the bound of LWE case given in [Cheetah](https://eprint.iacr.org/2022/207). I don't know how to bound the infinite norm of these coefficients. But I figured that this won't be any better than the LWE case.

Cheetah claims that this saves about 16% – 25% in size for LWE, with a tiny chance ($1 − 2^{38.5}$) of failing the decryption. 

**TL;DR:** I think noise dropping is worse than modulus switching. And I am not sure if it's a good idea to do  noise dropping AFTER modulus switching. How to bound the noise in that case?

---

#### Details (if you are interested):

Consider $a = a_L \in \mathbb{Z}_q$ below:
$$
\begin{align*}
C &= a * s \;\;\; \text{The coefficient of polynomial mult is a convolution.} \\
\text{Var}(C[k]) &= \mathbb{E}\left[C[k]^2\right] \\
&= \mathbb{E}\left[\sum_{i=0}^{k}\left(a[i] s[k-i]\right)^2\right]\\
&= \mathbb{E}\left[\sum_{i=0}^{k}(a^2[i]s^2[k-i]) + \sum_{0 \leq i < j \leq k}a[i]a[j]s[k-i]s[k-j]\right]\\
&= \sum_{i=0}^{k}\mathbb{E} \left[a^2[i]s^2[k-i]\right] 
+ 
\underbrace{\sum_{0 \leq i < j \leq k}\mathbb{E}\left[a[i]a[j]s[k-i]s[k-j]\right]}_{0}\\

&= \sum_{i=0}^{k}\left(\mathbb{E} \left[a^2[i]\right] 
\cdot  \mathbb{E}\left[s^2[k-i]\right] \right)\\
&= \frac{2}{3} \sum_{i=0}^{k}\mathbb{E} \left[a^2[i]\right] \\
&\approx \frac{2}{9}k q^2
\end{align*}
$$


The problem is how to calculate the following: 
$$
\text{Var}(\max_k (|C[k]|))
$$