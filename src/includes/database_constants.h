#pragma once

namespace DatabaseConstants {
constexpr int PolyDegree = 4096;
constexpr unsigned long long PlaintextMod = 16777259; // Use for 4096
constexpr unsigned long long LargePlaintextMod = 442089503749; // Use for 8192
// constexpr unsigned long long PlaintextMod = 140737488355333; // Use for 8192
// constexpr unsigned long long CiphertextMod1 = 21873307932344321;
// constexpr unsigned long long CiphertextMod2 = 14832153251168257;
// Ciphertext Mod1 + Mod2 has a total length of 109 bits
} // namespace DatabaseConstants