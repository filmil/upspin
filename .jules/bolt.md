## 2023-10-24 - Zero-copy fast path in File Reader
**Learning:** Returning exactly-sized slices produced by unpackers avoids a memory copy (append) when a file consists of a single block. Since most files are single blocks, this saves an allocation and copy on a hot path.
**Action:** Always check if a slice can be returned directly instead of accumulating it into a larger buffer when the data is known to fit entirely in one segment.
