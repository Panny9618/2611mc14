| Target | Leading zero bits | Blocks | Expected attempts | Observed mean | Observed / expected | Expected noise (1 s.e.) | Min – max | Hash rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `000fffffffff…` | 12 | 600 | 4,096 | 4,149 | 1.01 | ±4% | 4 – 46,395 | 1,356,060 H/s |
| `0000ffffffff…` | 16 | 120 | 65,536 | 67,276 | 1.03 | ±9% | 527 – 358,761 | 1,384,921 H/s |
| `00000fffffff…` | 20 | 30 | 1,048,576 | 832,352 | 0.79 | ±18% | 8,503 – 3,143,144 | 1,415,687 H/s |

Overall: 35,532,844 hashes in 25.3 s = **1,404,274 hashes/s** (single Python thread, double SHA-256 of a 116-byte header, Python 3.13.18 on x86_64).
