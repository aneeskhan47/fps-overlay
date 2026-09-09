#include "locale/rtl_shape.h"

#include <RTLScript/RTLScript-RAII.hpp>

#include <cwctype>
#include <string>
#include <windows.h>

namespace locale {
namespace {

RTLScript::Raii::Instance& RtlInstance()
{
    static RTLScript::Raii::Instance inst;
    return inst;
}

bool IsRtlCodepoint(uint32_t cp)
{
    return (cp >= 0x0590 && cp <= 0x05FF) || (cp >= 0x0600 && cp <= 0x06FF) ||
           (cp >= 0x0750 && cp <= 0x077F) || (cp >= 0x08A0 && cp <= 0x08FF) ||
           (cp >= 0xFB1D && cp <= 0xFB4F) ||
           (cp >= 0xFB50 && cp <= 0xFDFF) || (cp >= 0xFE70 && cp <= 0xFEFF);
}

bool Utf8HasRtlLetter(const char* utf8)
{
    if (!utf8) return false;
    const unsigned char* p = (const unsigned char*)utf8;
    while (*p) {
        uint32_t cp = 0;
        if (*p < 0x80) {
            ++p;
            continue;
        }
        if ((*p & 0xE0) == 0xC0 && p[1]) {
            cp = ((*p & 0x1F) << 6) | (p[1] & 0x3F);
            p += 2;
        } else if ((*p & 0xF0) == 0xE0 && p[1] && p[2]) {
            cp = ((*p & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
            p += 3;
        } else if ((*p & 0xF8) == 0xF0 && p[1] && p[2] && p[3]) {
            cp = ((*p & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
            p += 4;
        } else {
            ++p;
            continue;
        }
        if (IsRtlCodepoint(cp))
            return true;
    }
    return false;
}

std::wstring Utf8ToWide(const char* utf8)
{
    if (!utf8 || !utf8[0]) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, &w[0], n);
    return w;
}

std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

wchar_t MirrorParen(wchar_t c)
{
    switch (c) {
    case L'(': return L')';
    case L')': return L'(';
    case L'[': return L']';
    case L']': return L'[';
    case L'{': return L'}';
    case L'}': return L'{';
    default: return c;
    }
}

void MirrorPairedPunctuationNearRtl(std::wstring& w)
{
    for (size_t i = 0; i < w.size(); ++i) {
        const wchar_t c = w[i];
        if (MirrorParen(c) == c)
            continue;
        const bool leftRtl = (i > 0) && IsRtlCodepoint((uint32_t)w[i - 1]);
        const bool rightRtl = (i + 1 < w.size()) && IsRtlCodepoint((uint32_t)w[i + 1]);
        if (leftRtl || rightRtl)
            w[i] = MirrorParen(c);
    }
}

bool StripOuterParens(std::wstring& w, wchar_t& openOut, wchar_t& closeOut)
{
    size_t b = 0, e = w.size();
    while (b < e && iswspace(w[b])) ++b;
    while (e > b && iswspace(w[e - 1])) --e;
    if (e - b < 2) return false;

    const wchar_t open = w[b];
    const wchar_t close = w[e - 1];
    const bool paired =
        (open == L'(' && close == L')') ||
        (open == L'[' && close == L']') ||
        (open == L'{' && close == L'}');
    if (!paired) return false;

    openOut = open;
    closeOut = close;
    w = w.substr(b + 1, e - b - 2);
    return true;
}

} // namespace

std::string ShapeRtlForImGui(const char* utf8)
{
    if (!utf8 || !utf8[0]) return {};

    const char* idSep = nullptr;
    for (const char* p = utf8; *p; ++p) {
        if (p[0] == '#' && p[1] == '#') {
            idSep = p;
            break;
        }
    }
    std::string visible = idSep ? std::string(utf8, idSep) : std::string(utf8);
    std::string idSuffix = idSep ? std::string(idSep) : std::string();

    if (!Utf8HasRtlLetter(visible.c_str()))
        return std::string(utf8);

    std::wstring in = Utf8ToWide(visible.c_str());

    std::wstring lead;
    while (!in.empty() && iswspace(in.front())) {
        lead.push_back(in.front());
        in.erase(in.begin());
    }

    wchar_t openCh = 0, closeCh = 0;
    const bool hadOuterParens = StripOuterParens(in, openCh, closeCh);

    std::wstring fixed = RtlInstance().ConvertToFixed(in);

    std::wstring outW = lead;
    if (hadOuterParens) {
        // "(غير متاح)" / "(در دسترس نیست)": shape inside, keep visual LTR ().
        outW.push_back(openCh);
        outW += fixed;
        outW.push_back(closeCh);
    } else {
        MirrorPairedPunctuationNearRtl(fixed);
        outW += fixed;
    }

    std::string out = WideToUtf8(outW);
    out += idSuffix;
    return out;
}

} // namespace locale
