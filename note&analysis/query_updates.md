# Updates on query related functionalities and details

The code was different from the pseudocode in OnionPIR paper. Yue made some changes on the code so to align with the pseudocode logic.



### Updates on `generate_query` on client side.

- Previously, if the `query_indexes[i] == 0`for dimension $i$, the code packed some "special values" to the coefficients of the query. Correspondingly, in `evaluate_gsw_product` on the server side, if the selection vector is RGSW(0), then it outputs the second half of the given vector. These old code are not consistent with the output of `get_query_indexes`, and are againsts the conventional vector order. Hence, the first update is to change the code so that we indeed pack the value 1 when `query_indexes[i] == 1`.
- Previously, the `coef`, which corresponds to the RGSW gadget value, are in reversed order. That is, for gadget = $(1/B, \ldots, 1/B^l)$, the previous code insert in the reversed order `coef` $=[B^{l-1}, B^{l-2}, \ldots, B^0]$. Corresponding changes are in: `external_prod.cpp > GSWEval::decomp_rlwe` and `external_prod.cpp > GSWEval::encrypt_plain_to_gsw`. The changed code aligns with algorithm 1 in [Faster Fully Homomorphic Encryption: Bootstrapping in less than 0.1 Seconds](https://eprint.iacr.org/2016/870).
- TODO: also encrypt the first $l$ rows for RGSW queries.