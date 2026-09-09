#pragma once

#include <cstddef>
#include <string>

namespace locale {

// Load language pack from locales/<code>.json next to the exe.
// "en-US" clears the map (English source strings are the keys/fallback).
bool Load(const char* langCode);

const char* Current();
bool IsRtl();
void ApplyImGuiRtlFlags(); // no-op if ImGui has no RTL flag; sets helper state

// Lookup English source string -> translated (or English if missing).
const char* T(const char* english);

// Like T(), but skips RTL reshaping (raw translated UTF-8).
const char* TRaw(const char* english);

// Printf into a thread-local rotating buffer; fmt is looked up via T() first.
const char* TF(const char* englishFmt, ...);

// Dialog helpers (ids from zh-CN.json dialogs[].id)
const char* DialogTitle(const char* id, const char* englishFallback);
const char* DialogBody(const char* id, const char* englishFallback);

// UTF-8 -> UTF-16 for MessageBoxW
std::wstring ToWide(const char* utf8);

} // namespace locale
