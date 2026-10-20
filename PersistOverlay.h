// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once
// Persistent overlay over a seeded sparse disk. The seed (the packed RAM disk the loader provides) stays the immutable base; the
// pages a running system changes are stored in a window of 4096-byte blocks on some other medium and put back on the next boot.
//
// Window layout (block = 4096 bytes, all integers little endian):
//   block 0                 header: "SHNGDATA", version 1, header bytes 64, page count, SHA-256 of the seed, generation (32 bit), crc32
//   blocks 1 .. B           presence bitmap, one bit per page of the disk, B = ceil(pages / 32768)
//   blocks B+1 .. B+pages   page i at B+1+i, valid only when its bit is set
// A page is written before its bit is set; the bit blocks are written by sync(), after the pages were made durable, and the
// medium is flushed again afterwards, so a bit never promises a page that did not reach the medium before it.
// A header whose page count or seed digest differs from the current seed is stale and is replaced (the overlay starts empty): an
// overlay is only ever applied on top of the exact seed it was made against.
//
// Ops: bool read(uint64_t block, uint32_t count, void *dst); bool write(uint64_t block, uint32_t count, const void *src);
//      bool sync();   (blocks are relative to the window)
#include <stdint.h>
#include <string.h>

namespace persist {
constexpr uint32_t kBlock = 4096;
constexpr uint32_t kHeaderBytes = 64;

inline uint32_t crc32 (const uint8_t *data, size_t bytes)
{
  uint32_t crc = 0xffffffffU;
  for (size_t i = 0; i < bytes; ++i) {
    crc ^= data[i];
    for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1)));
  }
  return ~crc;
}
inline void put32 (uint8_t *p, uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = uint8_t (v >> (8 * i)); }
inline void put64 (uint8_t *p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = uint8_t (v >> (8 * i)); }
inline uint32_t get32 (const uint8_t *p) { uint32_t v = 0; for (int i = 3; i >= 0; --i) v = (v << 8) | p[i]; return v; }
inline uint64_t get64 (const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }

inline uint64_t bitmapBlocks (uint64_t pages) { return (pages + 8ULL * kBlock - 1) / (8ULL * kBlock); }
inline uint64_t windowBlocks (uint64_t pages) { return 1 + bitmapBlocks (pages) + pages; }
inline uint64_t pageBlock (uint64_t pages, uint64_t index) { return 1 + bitmapBlocks (pages) + index; }

inline void encodeHeader (uint8_t block[kBlock], uint64_t pages, const uint8_t seed[32], uint64_t generation)
{
  memset (block, 0, kBlock);
  memcpy (block, "SHNGDATA", 8);
  put32 (block + 8, 1);
  put32 (block + 12, kHeaderBytes);
  put64 (block + 16, pages);
  memcpy (block + 24, seed, 32);
  put32 (block + 56, uint32_t (generation));
  // The CRC covers the first 60 bytes (the generation included); bytes 60..63 hold it.
  put32 (block + 60, crc32 (block, 60));
}
// 0 valid and for this seed; 1 blank or foreign (no magic); 2 damaged (CRC, version, size); 3 valid but for another seed/size.
inline int checkHeader (const uint8_t block[kBlock], uint64_t pages, const uint8_t seed[32], uint64_t *generation)
{
  if (memcmp (block, "SHNGDATA", 8)) return 1;
  if (get32 (block + 8) != 1 || get32 (block + 12) != kHeaderBytes || get32 (block + 60) != crc32 (block, 60)) return 2;
  if (generation) *generation = get32 (block + 56);
  if (get64 (block + 16) != pages || memcmp (block + 24, seed, 32)) return 3;
  return 0;
}

enum class Open { Resumed, Fresh, Blank, Failed };

struct Overlay {
  uint64_t pages = 0, generation = 0, present = 0;
  uint8_t *bitmap = nullptr;       // bitmapBlocks(pages) * kBlock bytes, owned by the caller
  uint8_t *dirty = nullptr;        // bitmapBlocks(pages) bytes, owned by the caller
  bool readOnly = true, anyDirty = false, active = false;
  int header = -1;                 // checkHeader result at open

  bool has (uint64_t i) const { return bitmap[i >> 3] >> (i & 7) & 1; }

  // `readOnly`: never write; a stale or blank window is reported (Blank) and left alone. Otherwise it is initialised: bitmap
  // first, header last, so a tear leaves no valid header.
  template <class Ops> Open open (Ops &ops, uint64_t pageCount, const uint8_t seed[32], bool ro, uint8_t *bits, uint8_t *dirtyFlags)
  {
    pages = pageCount; bitmap = bits; dirty = dirtyFlags; readOnly = ro; anyDirty = false; present = 0; active = false;
    uint64_t bb = bitmapBlocks (pages);
    uint8_t block[kBlock];
    if (!pages || !ops.read (0, 1, block)) return Open::Failed;
    header = checkHeader (block, pages, seed, &generation);
    if (header == 0) {
      for (uint64_t b = 0; b < bb; ++b) if (!ops.read (1 + b, 1, bitmap + b * kBlock)) return Open::Failed;
      memset (dirty, 0, bb);
      // Bits past the last page must be clear, or the loader would read blocks outside the window.
      for (uint64_t i = pages; i < bb * 8ULL * kBlock; ++i) if (has (i)) return Open::Failed;
      for (uint64_t i = 0; i < pages; ++i) present += has (i);
      active = true;
      return Open::Resumed;
    }
    memset (bitmap, 0, bb * kBlock);
    memset (dirty, 0, bb);
    if (ro) return Open::Blank;
    uint8_t zero[kBlock] = {};
    for (uint64_t b = 0; b < bb; ++b) if (!ops.write (1 + b, 1, zero)) return Open::Failed;
    if (!ops.sync ()) return Open::Failed;
    generation = (header == 3 || header == 2) ? generation + 1 : 1;
    encodeHeader (block, pages, seed, generation);
    if (!ops.write (0, 1, block) || !ops.sync ()) return Open::Failed;
    active = true;
    return Open::Fresh;
  }

  // Calls load(index, page) for every present page, in order. Stops at the first failure.
  template <class Ops, class Load> bool forEachPresent (Ops &ops, Load &load)
  {
    uint8_t block[kBlock];
    for (uint64_t i = 0; i < pages; ++i) {
      if (!has (i)) continue;
      if (!ops.read (pageBlock (pages, i), 1, block) || !load (i, block)) return false;
    }
    return true;
  }

  template <class Ops> bool writePage (Ops &ops, uint64_t index, const void *page)
  {
    if (readOnly || !active || index >= pages) return false;
    if (!ops.write (pageBlock (pages, index), 1, page)) return false;
    if (!has (index)) { bitmap[index >> 3] |= uint8_t (1 << (index & 7)); ++present; }
    dirty[index / (8ULL * kBlock)] = 1;
    anyDirty = true;
    return true;
  }

  template <class Ops> bool sync (Ops &ops)
  {
    if (readOnly || !active) return false;
    if (!anyDirty) return true;
    if (!ops.sync ()) return false;                       // pages durable before any bit that names them
    uint64_t bb = bitmapBlocks (pages);
    for (uint64_t b = 0; b < bb; ++b) {
      if (!dirty[b]) continue;
      if (!ops.write (1 + b, 1, bitmap + b * kBlock)) return false;
    }
    if (!ops.sync ()) return false;
    memset (dirty, 0, bb);
    anyDirty = false;
    return true;
  }
};
}  // namespace persist
