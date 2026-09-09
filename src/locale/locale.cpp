#include "locale/locale.h"
#include "locale/rtl_shape.h"

#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <windows.h>

#include "imgui.h"

namespace locale {
namespace {

std::string g_lang = "en-US";
std::map<std::string, std::string> g_strings;
std::map<std::string, std::string> g_dialogTitles;
std::map<std::string, std::string> g_dialogBodies;
bool g_rtl = false;

std::string ExeDir()
{
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    char* slash = strrchr(exePath, '\\');
    if (slash) *(slash + 1) = '\0';
    return std::string(exePath);
}

bool LangIsRtl(const char* code)
{
    if (!code || !code[0]) return false;
    // Primary subtags that are typically RTL.
    static const char* kRtl[] = { "ar", "he", "fa", "ur", "ps", "sd", "yi" };
    for (const char* tag : kRtl) {
        size_t n = strlen(tag);
        if (_strnicmp(code, tag, n) == 0 && (code[n] == '\0' || code[n] == '-' || code[n] == '_'))
            return true;
    }
    return false;
}

static void SkipWs(const char*& p)
{
    while (*p && (unsigned char)*p <= 32) ++p;
}

static bool ParseJsonString(const char*& p, std::string& out)
{
    SkipWs(p);
    if (*p != '"') return false;
    ++p;
    out.clear();
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            ++p;
            switch (*p) {
            case '"': case '\\': case '/': out.push_back(*p); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                // Basic \uXXXX (BMP). Enough for zh-CN file which is mostly UTF-8 already.
                unsigned int cp = 0;
                for (int i = 0; i < 4 && p[1]; ++i) {
                    ++p;
                    char c = *p;
                    cp <<= 4;
                    if (c >= '0' && c <= '9') cp |= (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
                    else return false;
                }
                if (cp < 0x80) out.push_back((char)cp);
                else if (cp < 0x800) {
                    out.push_back((char)(0xC0 | (cp >> 6)));
                    out.push_back((char)(0x80 | (cp & 0x3F)));
                } else {
                    out.push_back((char)(0xE0 | (cp >> 12)));
                    out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                    out.push_back((char)(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default: out.push_back(*p); break;
            }
            ++p;
        } else {
            out.push_back(*p++);
        }
    }
    if (*p != '"') return false;
    ++p;
    return true;
}

// Extract flat "key":"value" string pairs from an object body (handles nesting by brace depth).
static void CollectStringPairs(const char* objStart, std::map<std::string, std::string>& out)
{
    const char* p = objStart;
    SkipWs(p);
    if (*p != '{') return;
    ++p;
    int depth = 1;
    while (*p && depth > 0) {
        SkipWs(p);
        if (*p == '{') { ++depth; ++p; continue; }
        if (*p == '}') { --depth; ++p; continue; }
        if (*p == '[') {
            // skip arrays at this depth by scanning until matching ]
            int ad = 1; ++p;
            while (*p && ad > 0) {
                if (*p == '"') {
                    std::string tmp;
                    if (!ParseJsonString(p, tmp)) break;
                    continue;
                }
                if (*p == '[') ++ad;
                else if (*p == ']') --ad;
                ++p;
            }
            continue;
        }
        if (*p == '"') {
            std::string key;
            if (!ParseJsonString(p, key)) break;
            SkipWs(p);
            if (*p != ':') continue;
            ++p;
            SkipWs(p);
            if (*p == '"') {
                std::string val;
                if (!ParseJsonString(p, val)) break;
                if (depth == 1)
                    out[key] = val;
            } else if (*p == '{') {
                // nested object: recurse only for value collection at deeper depths via depth tracking
                // skip by letting depth++ on '{'
                continue;
            } else {
                // non-string value: skip until comma/brace
                while (*p && *p != ',' && *p != '}' && *p != '{') ++p;
            }
            continue;
        }
        ++p;
    }
}

static const char* FindObjectAfterKey(const std::string& json, const char* key)
{
    std::string pattern = std::string("\"") + key + "\"";
    size_t pos = 0;
    while (true) {
        pos = json.find(pattern, pos);
        if (pos == std::string::npos) return nullptr;
        const char* p = json.c_str() + pos + pattern.size();
        SkipWs(p);
        if (*p == ':') {
            ++p;
            SkipWs(p);
            if (*p == '{') return p;
        }
        pos += pattern.size();
    }
}

static void ParseDialogs(const std::string& json, const std::string& langCode)
{
    g_dialogTitles.clear();
    g_dialogBodies.clear();
    const char* key = "\"dialogs\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return;
    const char* p = json.c_str() + pos + strlen(key);
    SkipWs(p);
    if (*p != ':') return;
    ++p;
    SkipWs(p);
    if (*p != '[') return;
    ++p;

    const std::string titleLang = "title_" + langCode;
    const std::string bodyLang = "body_" + langCode;

    while (*p) {
        SkipWs(p);
        if (*p == ']') break;
        if (*p == ',') { ++p; continue; }
        if (*p != '{') { ++p; continue; }

        // Capture this object as a substring by brace matching
        const char* start = p;
        int depth = 0;
        const char* q = p;
        do {
            if (*q == '"') {
                std::string tmp;
                if (!ParseJsonString(q, tmp)) break;
                continue;
            }
            if (*q == '{') ++depth;
            else if (*q == '}') {
                --depth;
                ++q;
                if (depth == 0) break;
                continue;
            }
            ++q;
        } while (*q);

        std::string obj(start, q);
        p = q;

        auto getField = [&](const char* field) -> std::string {
            std::string pat = std::string("\"") + field + "\"";
            size_t fp = obj.find(pat);
            if (fp == std::string::npos) return {};
            const char* fp_ = obj.c_str() + fp + pat.size();
            SkipWs(fp_);
            if (*fp_ != ':') return {};
            ++fp_;
            SkipWs(fp_);
            std::string val;
            if (!ParseJsonString(fp_, val)) return {};
            return val;
        };

        std::string id = getField("id");
        if (id.empty()) continue;
        std::string title = getField(titleLang.c_str());
        if (title.empty()) title = getField("title_en");
        std::string body = getField(bodyLang.c_str());
        if (body.empty()) body = getField("body_en");
        if (!title.empty()) g_dialogTitles[id] = title;
        if (!body.empty()) g_dialogBodies[id] = body;
    }
}

static bool LoadJsonFile(const std::string& path, const std::string& langCode)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string json = ss.str();
    if (json.empty()) return false;

    // Prefer translations.* nested maps
    static const char* kMaps[] = {
        "settings_window", "overlay_display", "context_menu", "tray", "application_identity"
    };

    const char* translations = FindObjectAfterKey(json, "translations");
    if (translations) {
        // Collect pairs from each named child object
        std::string translationsObj;
        {
            const char* p = translations;
            int depth = 0;
            const char* q = p;
            do {
                if (*q == '"') {
                    std::string tmp;
                    if (!ParseJsonString(q, tmp)) break;
                    continue;
                }
                if (*q == '{') ++depth;
                else if (*q == '}') {
                    --depth;
                    ++q;
                    if (depth == 0) break;
                    continue;
                }
                ++q;
            } while (*q);
            translationsObj.assign(p, q);
        }

        for (const char* mapName : kMaps) {
            const char* obj = FindObjectAfterKey(translationsObj, mapName);
            if (!obj) continue;
            CollectStringPairs(obj, g_strings);
        }
    } else {
        // Flat file fallback
        CollectStringPairs(json.c_str(), g_strings);
    }

    ParseDialogs(json, langCode);
    return !g_strings.empty() || !g_dialogBodies.empty();
}

} // namespace

bool Load(const char* langCode)
{
    g_strings.clear();
    g_dialogTitles.clear();
    g_dialogBodies.clear();
    g_lang = (langCode && langCode[0]) ? langCode : "en-US";
    g_rtl = LangIsRtl(g_lang.c_str());

    if (_stricmp(g_lang.c_str(), "en") == 0)
        g_lang = "en-US";
    else if (_stricmp(g_lang.c_str(), "ar-SA") == 0 || _stricmp(g_lang.c_str(), "ar-EG") == 0)
        g_lang = "ar";

    // Always try to load locales/<code>.json (en-US is identity / documentation mirror).
    // Missing keys still fall back to the English source string in T().
    std::string path = ExeDir() + "locales\\" + g_lang + ".json";
    if (!LoadJsonFile(path, g_lang)) {
        path = ExeDir() + "..\\..\\locales\\" + g_lang + ".json";
        LoadJsonFile(path, g_lang);
    }
    return true;
}

const char* Current() { return g_lang.c_str(); }
bool IsRtl() { return g_rtl; }

void ApplyImGuiRtlFlags()
{
    // Dear ImGui has no ConfigFlags_IsRtl (explicitly not planned upstream).
    // Community approach: reshape Arabic in T()/TF(), then mirror layout manually
    // (SetCursorPosX / fixed child widths / flipped widget chrome).
    if (!ImGui::GetCurrentContext())
        return;
    ImGuiStyle& style = ImGui::GetStyle();
    if (g_rtl) {
        style.WindowTitleAlign = ImVec2(1.0f, 0.5f);
        style.ButtonTextAlign = ImVec2(0.5f, 0.5f); // full-width CTAs stay centered
        style.SelectableTextAlign = ImVec2(1.0f, 0.5f);
    } else {
        style.WindowTitleAlign = ImVec2(0.0f, 0.5f);
        style.ButtonTextAlign = ImVec2(0.5f, 0.5f);
        style.SelectableTextAlign = ImVec2(0.0f, 0.5f);
    }
}

static const char* LookupRaw(const char* english)
{
    if (!english) return "";
    auto it = g_strings.find(english);
    if (it != g_strings.end()) return it->second.c_str();
    return english;
}

static const char* StoreTransient(const std::string& s)
{
    static std::string bufs[16];
    static int idx = 0;
    std::string& slot = bufs[idx++ & 15];
    slot = s;
    return slot.c_str();
}

const char* T(const char* english)
{
    const char* raw = LookupRaw(english);
    if (!g_rtl) return raw;
    return StoreTransient(ShapeRtlForImGui(raw));
}

const char* TRaw(const char* english)
{
    return LookupRaw(english);
}

const char* TF(const char* englishFmt, ...)
{
    static char rawBufs[8][1024];
    static int idx = 0;
    char* buf = rawBufs[idx++ & 7];
    const char* fmt = LookupRaw(englishFmt);
    va_list ap;
    va_start(ap, englishFmt);
    vsnprintf(buf, 1024, fmt, ap);
    va_end(ap);
    buf[1023] = '\0';
    if (!g_rtl) return buf;
    return StoreTransient(ShapeRtlForImGui(buf));
}

const char* DialogTitle(const char* id, const char* englishFallback)
{
    auto it = g_dialogTitles.find(id);
    if (it != g_dialogTitles.end()) return it->second.c_str();
    return englishFallback ? englishFallback : "";
}

const char* DialogBody(const char* id, const char* englishFallback)
{
    auto it = g_dialogBodies.find(id);
    if (it != g_dialogBodies.end()) return it->second.c_str();
    return englishFallback ? englishFallback : "";
}

std::wstring ToWide(const char* utf8)
{
    if (!utf8 || !utf8[0]) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w((size_t)n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, &w[0], n);
    return w;
}

} // namespace locale
