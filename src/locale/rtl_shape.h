#pragma once

#include <string>

namespace locale {

// Shape RTL scripts (Arabic / Farsi / Urdu / Hebrew + mixed LTR) for Dear ImGui
// via vendored RTLScript: https://github.com/oscar7070/RTLScript
// Preserves ImGui "##id" suffixes. No-op when the string has no RTL letters.
std::string ShapeRtlForImGui(const char* utf8);

} // namespace locale
