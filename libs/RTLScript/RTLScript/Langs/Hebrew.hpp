// RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType

#pragma once

#include <array>
#include "../Common/BaseComponents.hpp"

namespace RTLScript::Hebrew
{
    constexpr auto GLYPH_RANGE = GlyphRange(0x0590, 0x05FF);

    // ReSharper disable CommentTypo, IdentifierTypo
    enum class Alphabet : uint32_t {
        Alef,        // א
        Bet,         // ב
        Gimel,       // ג
        Dalet,       // ד
        Hei,         // ה
        Vav,         // ו
        Zayin,       // ז
        Chet,        // ח
        Tet,         // ט
        Yod,         // י
        Kaf,         // כ
        KafSofit,    // ך
        Lamed,       // ל
        Mem,         // מ
        MemSofit,    // ם
        Nun,         // נ
        NunSofit,    // ן
        Samekh,      // ס
        Ayin,        // ע
        Pei,         // פ
        PeiSofit,    // ף
        Tsadik,      // צ
        TsadikSofit, // ץ
        Kuf,         // ק
        Raysh,       // ר
        Shin,        // ש
        Tav,         // ת
    };

    constexpr std::array ALPHABET_ALL_LETTERS =
    {
        L'\u05D0', // HE_ALEF         // א
        L'\u05D1', // HE_BET          // ב
        L'\u05D2', // HE_GIMEL        // ג
        L'\u05D3', // HE_DALET        // ד
        L'\u05D4', // HE_HEI          // ה
        L'\u05D5', // HE_VAV          // ו
        L'\u05D6', // HE_ZAYIN        // ז
        L'\u05D7', // HE_CHET         // ח
        L'\u05D8', // HE_TET          // ט
        L'\u05D9', // HE_YOD          // י
        L'\u05DB', // HE_KAF          // כ
        L'\u05DA', // HE_KAF_SOFIT    // ך
        L'\u05DC', // HE_LAMED        // ל
        L'\u05DE', // HE_MEM          // מ
        L'\u05DD', // HE_MEM_SOFIT    // ם
        L'\u05E0', // HE_NUN          // נ
        L'\u05E2', // HE_NUN_SOFIT    // ן
        L'\u05E1', // HE_SAMEKH       // ס
        L'\u05E2', // HE_AYIN         // ע
        L'\u05E4', // HE_PEI          // פ
        L'\u05E3', // HE_PEI_SOFIT    // ף
        L'\u05E6', // HE_TSADIK       // צ
        L'\u05E5', // HE_TSADIK_SOFIT // ץ
        L'\u05E7', // HE_KUF          // ק
        L'\u05E8', // HE_RAYSH        // ר
        L'\u05E9', // HE_SHIN         // ש
        L'\u05EA', // HE_TAV          // ת
    };
    // ReSharper restore CommentTypo, IdentifierTypo
}