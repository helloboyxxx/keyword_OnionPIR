# FrodoPIR High-level

### Notations: 

> Not exactly the same as the paper. 

- DB: the raw database, an array of length $m$, each entry has $w$ bits. 

  - Example: 
    - $m = 2^{20}$
    - $w = 2^{20}$.  About 131 KB for each entry.
    - So, if $\alpha = 2^w = 2^{2^{20}}, \mathrm{DB} \in \mathbb{Z}_\alpha^m$.

- $D \gets \operatorname{parse}(\mathrm{DB}, p), D \in \mathbb{Z}_p^{m \times d}$: process raw database. 

  - The high-level is to "slice" each entry ($\mathrm{DB}[i]$) to $d$ many small chunks. Each chunk contains $\log(p)$ bits. 

  - Example:

    - $w = 2^{20}\text{ (bits)}$
    - $p = 2^{9}$
    - $d = \lceil w / \log(p) \rceil = \lceil 2^{20} / 9 \rceil = 116509 \approx 117 \text{k columns}$

- $A \in \mathbb{Z}_q^{n \times m}$: pseudorandomly generated matrix using seed $\mu$. 

  - This is used for creating the hint.
  - $0 < p < q$. 
  - Example: 
    - $q = 2^{32}$.
    - $n = 1774$  by some experiments . Increase in $n$ is more secure but has larger hint.

- $M = A \cdot D \in \mathbb{Z}_q^{n \times w}$: the hint. Client download this matrix.

  



### The Core Technical Ideas

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240730173827213.png " style="width:90%;" />
    <figcaption>  </figcaption>
  </figure>
</center>



<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240730173838653.png " style="width:70%;" />
    <figcaption>  </figcaption>
  </figure>
</center>

Note that in step (4), we have to perform a matrix-vector multiplication. This is unavoidable by design. The number of multiplication is $m \cdot d$. This is the same as performing $d$ many PIR using the same query vector. 

#### Why this is fast? 

In FrodoPIR's implementation, since $q = 2^{32}, p < q$, we can implement matrix-vector multiplication easily using `uint32_t` multiplication. That is, to compute the answer, we perform $m \cdot d$ many basic `uint32_t` multiplication. Example: $m \cdot d = 2^{20} \cdot (2^{20} / 9) \approx 122168541184$. This can be done in about 10 seconds on a Mac M1 chip, without considering any addition. If we use $w = 2^{13}$, it costs about 0.075 second.

These numbers are ballpark estimation calculated by Yue, not experimental values.



#### What is the client doing?

All the calculation and storage on client side serve for the LWE scheme. 



#### Down side:

Well, of course, the client have to download the hint. $M \in \mathbb{Z}_q^{n \times w}$ has $\log(q)nw = 32 \cdot 1774 \cdot 2^{20} = 59525562368 \text{ bits} \approx 7 \text{ GB}$ (as an example).

Also, the online communication is large. This scheme requires $O(N)$ upload during the online phase: nearly 4 MB when $m = 2^{20}$.









