#include <metal_stdlib>
using namespace metal;

// Owned pre-raster result probe. The MODE subset and s10 are data, not
// physical launch registers. No wave/scheduling/export behavior is modeled.
// Round positive m * 2^scale toward +infinity or down. In this fixture
// m is at most 41 bits, and every nonzero result is normal and finite.
static uint xyz_directed(ulong m, int scale, bool up) {
  if (!m) return 0;
  const uint hi = uint(m >> 32);
  const int top = hi ? 63 - int(clz(hi)) : 31 - int(clz(uint(m)));
  const int drop = top - 23;
  ulong sig = drop > 0 ? m >> uint(drop) : m << uint(-drop);
  if (up && drop > 0 && (sig << uint(drop)) != m) ++sig;
  // Add (rather than OR) so a carry out of the significand increments the exponent.
  return (uint(top + scale + 127) << 23) + uint(sig) - 0x800000u;
}

kernel void owned_vertex_xyz(const device uint2 *state [[buffer(0)]],
                             constant uint4 &entry_v0 [[buffer(1)]],
                             device uint4 *out [[buffer(2)]],
                             uint id [[thread_position_in_grid]]) {
  const uint2 launch = state[id / 4u]; // One authored MODE/s10 pair per four lanes.
  const uint mode = launch.x;
  const uint s10 = launch.y;
  const uint v0 = entry_v0[id & 3u];
  const float scale = (mode & 0x220u) == 0 ? 2.0f : 1.0f;
  const float x = float(int(v0 & 2u)) * scale + (-1.0f);
  const float y = 1.0f - float(int((v0 << 1u) & 2u)) * scale;
  const uint round = mode & 3u;
  uint converted, z;
  if (round == 0u) {
    const float f = float(s10);
    converted = as_type<uint>(f);
    z = as_type<uint>(f * as_type<float>(0x37800080u));
  } else {
    // The ordinary Metal operators implement the nearest route above. The
    // directed controls implement each binary32 rounding step explicitly;
    // -infinity and toward zero coincide only on this positive domain.
    const bool up = round == 1u;
    converted = xyz_directed(ulong(s10), 0, up);
    z = 0;
    if (converted != 0) {
      const ulong sig = ulong((converted & 0x7fffffu) | 0x800000u);
      const int exponent = int(converted >> 23) - 127 - 23;
      // Exact literal = 65537 * 2^-32.
      z = xyz_directed(sig * 65537ul, exponent - 32, up);
    }
  }
  out[id] = uint4(as_type<uint>(x), as_type<uint>(y), z, converted);
}
