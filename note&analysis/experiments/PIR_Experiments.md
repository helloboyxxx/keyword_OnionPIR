### Experiments

```
#define DB_SZ       				1 << 15    
#define NUM_DIM     			9, 8, 7					// Variable here
#define NUM_ENTRIES 		1 << 15
#define ENTRY_SZ    			12000
#define GSW_L       				9
#define GSW_L_KEY  			 9
```

**The corresponding first dimension has size: 128, 256, 512**

| #Dim  | Expansion | Dim #0   | GSW gen total | Ext prod total |
| ----- | --------- | -------- | ------------- | -------------- |
| 9     | 168       | 2009     | 488           | 1277           |
| 9     | 165       | 2103     | 475           | 1397           |
| 9     | 164       | 2036     | 468           | 1271           |
| **8** | **400**   | **1951** | **419**       | **640**        |
| **8** | **341**   | **2060** | **429**       | **645**        |
| **8** | **344**   | **2075** | **418**       | **632**        |
| 7     | 757       | 2128     | 371           | 318            |
| 7     | 677       | 1716     | 346           | 309            |
| 7     | 660       | 1293     | 348           | 307            |



### Observation: 

Query expansion is slow when the first dimension is large: obviously, proportional to the number of bits for the first dimension.

Smaller first dimension means larger size for rest dimensions $\Rightarrow$ more external product $\Rightarrow$ slower.

The time spent on the first dimension product doesn't vary. This is because the first dimension uses BFV ct-pt mult and add, and every entry must be touched. The size of the first dimension won't affect the speed, but will affect the noise growth. 

