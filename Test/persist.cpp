// Host test for the persistent overlay core: a model medium with fault injection (torn writes, lost cache, write refusal).
#include <cassert>
#include <cstdio>
#include <vector>
#include "../PersistOverlay.h"
using namespace persist;
struct Medium {
  std::vector<uint8_t> durable, cache;          // cache holds writes not yet flushed
  std::vector<std::pair<uint64_t, std::vector<uint8_t>>> pending;
  unsigned writes = 0, syncs = 0, failWriteAt = ~0u, failSyncAt = ~0u, reads = 0;
  explicit Medium(uint64_t blocks) : durable(blocks * kBlock, 0xA5) {}      // never-written medium holds junk, not zeros
  bool read(uint64_t b, uint32_t n, void *d) {
    ++reads;
    for (uint32_t i = 0; i < n; ++i) { std::vector<uint8_t> v(durable.begin() + (b + i) * kBlock, durable.begin() + (b + i + 1) * kBlock);
      for (auto &p : pending) if (p.first == b + i) v = p.second; memcpy((uint8_t *)d + i * kBlock, v.data(), kBlock); }
    return true; }
  bool write(uint64_t b, uint32_t n, const void *s) {
    if (writes++ == failWriteAt) return false;
    for (uint32_t i = 0; i < n; ++i) pending.push_back({b + i, std::vector<uint8_t>((const uint8_t *)s + i * kBlock, (const uint8_t *)s + (i + 1) * kBlock)});
    return true; }
  bool sync() { if (syncs++ == failSyncAt) return false;
    for (auto &p : pending) memcpy(&durable[p.first * kBlock], p.second.data(), kBlock);
    pending.clear(); return true; }
  void powerLoss() { pending.clear(); }                                     // unflushed writes vanish
};
static std::vector<uint8_t> pageOf(uint8_t v) { return std::vector<uint8_t>(kBlock, v); }
int main() {
  const uint64_t pages = 65536 + 7;                     // forces two bitmap blocks and a ragged last byte
  uint8_t seedA[32], seedB[32]; memset(seedA, 1, 32); memset(seedB, 2, 32);
  assert(bitmapBlocks(pages) == 3);
  assert(bitmapBlocks(32768) == 1 && bitmapBlocks(32769) == 2 && bitmapBlocks(524288) == 16);
  assert(windowBlocks(524288) == 1 + 16 + 524288);
  Medium m(windowBlocks(pages));
  std::vector<uint8_t> bits(bitmapBlocks(pages) * kBlock), dirty(bitmapBlocks(pages));
  // Blank medium: read-only open must not write and reports Blank; read-write initialises it.
  { Overlay o; assert(o.open(m, pages, seedA, true, bits.data(), dirty.data()) == Open::Blank && m.writes == 0 && !o.active && o.header == 1); }
  Overlay o; assert(o.open(m, pages, seedA, false, bits.data(), dirty.data()) == Open::Fresh && o.active && o.present == 0 && o.generation == 1);
  // Write pages, sync, reopen: resumed with exactly those pages.
  assert(o.writePage(m, 0, pageOf(0x11).data()) && o.writePage(m, 40000, pageOf(0x22).data()) && o.writePage(m, pages - 1, pageOf(0x33).data()));
  assert(!o.writePage(m, pages, pageOf(0).data()));
  assert(o.sync(m));
  { Medium copy = m; Overlay r; std::vector<uint8_t> b2(bits.size()), d2(dirty.size());
    assert(r.open(copy, pages, seedA, true, b2.data(), d2.data()) == Open::Resumed && r.present == 3 && r.has(0) && r.has(40000) && r.has(pages - 1) && !r.has(1));
    unsigned seen = 0; struct L { unsigned *seen; bool operator()(uint64_t i, const uint8_t *p) { ++*seen; return p[0] == (i == 0 ? 0x11 : i == 40000 ? 0x22 : 0x33) && p[4095] == p[0]; } } load{&seen};
    assert(r.forEachPresent(copy, load) && seen == 3);
    assert(!r.writePage(copy, 1, pageOf(9).data()) && !r.sync(copy));   // read-only really is read-only
  }
  // A different seed (the seed was rebuilt) makes the overlay stale: it is replaced, not applied.
  { Medium copy = m; Overlay r; std::vector<uint8_t> b2(bits.size()), d2(dirty.size());
    assert(r.open(copy, pages, seedB, true, b2.data(), d2.data()) == Open::Blank && r.header == 3 && r.present == 0);
    assert(r.open(copy, pages, seedB, false, b2.data(), d2.data()) == Open::Fresh && r.generation == 2 && r.present == 0); }
  // Power loss before sync: pages written after the last sync are gone, and no bit promises them.
  assert(o.writePage(m, 5, pageOf(0x44).data())); m.powerLoss();
  { Overlay r; std::vector<uint8_t> b2(bits.size()), d2(dirty.size());
    assert(r.open(m, pages, seedA, true, b2.data(), d2.data()) == Open::Resumed && !r.has(5) && r.present == 3); }
  // Torn sync: pages flushed, bitmap write fails: the next open sees the old bitmap (page 5 absent), never a bit without its page.
  { Medium t = m; Overlay w; std::vector<uint8_t> b2(bits.size()), d2(dirty.size());
    assert(w.open(t, pages, seedA, false, b2.data(), d2.data()) == Open::Resumed);
    assert(w.writePage(t, 6, pageOf(0x55).data())); t.failWriteAt = t.writes;   // the data write already happened; the bitmap write that sync() issues next fails
    assert(!w.sync(t)); t.powerLoss();
    Overlay r; std::vector<uint8_t> b3(bits.size()), d3(dirty.size());
    assert(r.open(t, pages, seedA, true, b3.data(), d3.data()) == Open::Resumed && !r.has(6)); }
  // Damaged header (flip a bit): reported as damaged, read-write open reinitialises with a higher generation.
  { Medium t = m; t.durable[20] ^= 1; Overlay r; std::vector<uint8_t> b2(bits.size()), d2(dirty.size());
    assert(r.open(t, pages, seedA, true, b2.data(), d2.data()) == Open::Blank && r.header == 2);
    assert(r.open(t, pages, seedA, false, b2.data(), d2.data()) == Open::Fresh && r.present == 0); }
  // Bits beyond the last page are corruption.
  { Medium t = m; Overlay r; std::vector<uint8_t> b2(bits.size()), d2(dirty.size());
    t.durable[1 * kBlock + 2 * kBlock + 100] |= 0x80;    // inside bitmap block 3 (last), page index >= pages
    assert(r.open(t, pages, seedA, true, b2.data(), d2.data()) == Open::Failed); }
  // Failed initialisation leaves no valid header.
  { Medium t(windowBlocks(pages)); t.failSyncAt = 0; Overlay r; std::vector<uint8_t> b2(bits.size()), d2(dirty.size());
    assert(r.open(t, pages, seedA, false, b2.data(), d2.data()) == Open::Failed); t.powerLoss();
    Overlay q; assert(q.open(t, pages, seedA, true, b2.data(), d2.data()) == Open::Blank && q.header == 1); }
  puts("PASS: overlay header, bitmap, ordering, stale seed, torn writes, power loss");
}
