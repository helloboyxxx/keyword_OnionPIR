Hi Haris, 

I hope you are doing well! Since our last meeting, I have been thinking about the tricks you have mentioned before. From the [Constant-weight PIR](https://www.usenix.org/conference/usenixsecurity22/presentation/mahdavi), I indeed confirm that we can expand the query by only using one $\mathsf{Subs}(c, k)$ for every level. The substitutions use $k = 2^i + 1, \forall i = 0, \ldots, \log_2 n$. You mentioned that it is possible to reduce the number of evaluation keys used. I have been thinking about this for a while, but still have no clue. Here what I have tried: 

1. The substitution is built using key switching. However, knowing the details for key switching and substitution seems useless. So I think opening the substitution black box won't help.
2. I have tried to do prime factorization on $k$. Suppose $k = pq$, where $p, q$ are prime, then $\mathsf{Subs}(\mathsf{Subs}(c, p), q)$ gives $x \mapsto (x^{p})^q = x^k$. However, I found that factorizing $k = 2^i + 1$ reduces the evaluation keys only when the factorized primes can be reused multiple times. This is not true when $n = 4096$. This means applying multiple substitution for one level is not the correct approach. Even if this approach works, I think the server computation is too expensive for doing this trick.
3. To reduce the height of the recursion tree: instead of extracting the odd and even parts of the polynomial in each level, extract it into more parts. However, I don't know how to do this.

Could you give me some hint? I also have some other confusions: 

1. SEAL implemented the symmetric version for BFV. I can only find [this](https://link.springer.com/chapter/10.1007/978-3-642-22792-9_29) (in page 509) as the reference of the symmetric variant of BFV scheme. Is it generally true that all RLWE based FHE schemes have both symmetric and asymmetric vartients?

2. In general, the [lattice estimator](https://github.com/malb/lattice-estimator) only give security estimation for LWE samples, not for RLWE samples. I found [this article](https://www.jeremykun.com/2022/12/28/estimating-the-security-of-ring-learning-with-errors-rlwe/), which mentioned that we can extract $n$ many LWE samples from one RLWE sample, then try attacking these $n$ samples. Is this how you estimated the security level previously? 

Regards, 
Yue Chen
