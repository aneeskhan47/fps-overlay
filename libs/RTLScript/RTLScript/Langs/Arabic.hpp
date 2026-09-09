// RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType

#pragma once

#include <array>
#include "RTLScript/Common/BaseComponents.hpp"

namespace RTLScript::Arabic
{
	// https://en.wikipedia.org/wiki/Arabic_script_in_Unicode
	constexpr auto GLYPH_RANGE = GlyphRange(0x0600, 0x1EEFF);

	// ReSharper disable CommentTypo, IdentifierTypo
	enum Tashkil : uint32_t {
		Fatha,                     // اَ
		Fathatan,                  // اً
		Damma,                     // اُ
		Dammatan,                  // اٌ
		Kasra,                     // اِ
		Kasratan,                  // اٍ
		Sukun,                     // اْ
		Shadda,                    // اّ

		Khanjaria,                 // اٰ

		SmallHighDotlessHeadOfKha,// ۡ
	};

	enum Alphabet : uint32_t {
		// Arabic
		AlefHamzaAbove,         // أ
		Alef,                   // ا
		AlefMaddahAbove,        // آ
		Hamza,                  // ء
		WawHamzaAbove,          // ؤ
		AlefHamzaBelow,         // إ
		YehHamzaAbove,          // ئ
		Beh,                    // ب
		Teh,                    // ت
		TehMarbuta,             // ة
		Theh,                   // ث
		Jeem,                   // ج
		Heth,                   // ح
		Kha,                    // خ
		Daal,                   // د
		Thaal,                  // ذ
		Reh,                    // ر
		Zain,                   // ز
		Seen,                   // س
		Sheen,                  // ش
		Saad,                   // ص
		Daad,                   // ض
		Taah,                   // ط
		Zaah,                   // ظ
		Ain,                    // ع
		Ghain,                  // غ
		Feh,                    // ف
		Qaaf,                   // ق
		Kaaf,                   // ک
		KaafNoHead,             // ك
		Laam,                   // ل
		Meem,                   // م
		Noon,                   // ن
		Waw,                    // و
		Ha,                     // ه
		Yeh,                    // ی
		ArabicYeh,              // ي
		AlefMaksura,            // ى
		Tatweel,                // ـ

		// Arabic special chars
		LaamAlef,               // لا
		LaamAlefHamzaAbove,     // لأ
		LaamAlefHamzaBelow,     // لإ
		LaamAlefMaddahAbove,    // لآ
		Allah,                  // ﷲ

		// Farsi			    
		FaPehEXT,               // پ
		FaGaafEXT,              // گ
		FaChenEXT,              // چ
		FaJehEXT,               // ژ

		// Urdu				    
		UrTeEXT,                // ٹ
		UrDalEXT,               // ڈ
		UrReEXT,                // ڑ
		UrNunghunnaEXT,         // ں
		UrBariyeEXT,            // ے
		UrHeEXT,                // ھ
		UrHaEXT,                // ہ
	};

	constexpr std::array ALL_LAAM_ALEF_VARIANTS = {
		Alphabet::LaamAlef,
		Alphabet::LaamAlefHamzaAbove,
		Alphabet::LaamAlefHamzaBelow,
		Alphabet::LaamAlefMaddahAbove,
	};

	constexpr std::array<UChar, 10> TASHKIL_ALL_DIACRITICS =
	{
		L'َ',  // AR_TASHKIL_FATHA                  // اَ
		L'ً',  // AR_TASHKIL_FATHATAN               // اً
		L'ُ',  // AR_TASHKIL_DAMMA                  // اُ
		L'ٌ',  // AR_TASHKIL_DAMMATAN               // اٌ
		L'ِ',  // AR_TASHKIL_KASRA                  // اِ
		L'ٍ',  // AR_TASHKIL_KASRATAN               // اٍ
		L'ْ',  // AR_TASHKIL_SUKUN                  // اْ
		L'ّ',  // AR_TASHKIL_SHADDA                 // اّ

		L'ٰ',  // AR_TASHKIL_ALEF_KHANJARIA         // اٰ

		L'ۡ', // AR_SMALL_HIGH_DOTLESS_HEAD_OF_KHA // ۡ
	};

	constexpr std::array ALPHABET_ALL_LETTERS =
	{
		// Arabic
		Letter(L'\u0623', L'\ufe83', L'\u0623', L'\ufe84', L'\ufe84'), // AR_ALEF_HAMZA_ABOVE, // أ
		Letter(L'\u0627', L'\ufe8d', L'\u0627', L'\ufe8e', L'\ufe8e'), // AR_ALEF, // ا
		Letter(L'\u0622', L'\ufe81', L'\u0622', L'\ufe82', L'\ufe82'), // AR_ALEF_MADDAH_ABOVE, // آ
		Letter(L'\u0621', L'\ufe80', L'\u0621', L'\u0621', L'\u0621'), // AR_HAMZA, // ء
		Letter(L'\u0624', L'\ufe85', L'\u0624', L'\ufe86', L'\ufe86'), // AR_WAW_HAMZA_ABOVE, // ؤ
		Letter(L'\u0625', L'\ufe87', L'\u0625', L'\ufe88', L'\ufe88'), // AlefHamzaBelow, // إ
		Letter(L'\u0626', L'\ufe89', L'\ufe8b', L'\ufe8c', L'\ufe8a'), // YehHamzaAbove, // ئ
		Letter(L'\u0628', L'\ufe8f', L'\ufe91', L'\ufe92', L'\ufe90'), // AR_BEH, // ب
		Letter(L'\u062A', L'\ufe95', L'\ufe97', L'\ufe98', L'\ufe96'), // Teh, // ت
		Letter(L'\u0629', L'\ufe93', L'\u0629', L'\u0629', L'\ufe94'), // TehMarbuta, // ة
		Letter(L'\u062b', L'\ufe99', L'\ufe9b', L'\ufe9c', L'\ufe9a'), // AR_THEH, // ث
		Letter(L'\u062c', L'\ufe9d', L'\ufe9f', L'\ufea0', L'\ufe9e'), // AR_JEEM, // ج
		Letter(L'\u062d', L'\ufea1', L'\ufea3', L'\ufea4', L'\ufea2'), // AR_HAH, // ح
		Letter(L'\u062e', L'\ufea5', L'\ufea7', L'\ufea8', L'\ufea6'), // AR_KHEH, // خ
		Letter(L'\u062f', L'\ufea9', L'\u062f', L'\ufeaa', L'\ufeaa'), // AR_DAAL, // د
		Letter(L'\u0630', L'\ufeab', L'\u0630', L'\ufeac', L'\ufeac'), // AR_THAAL, // ذ
		Letter(L'\u0631', L'\ufead', L'\u0631', L'\ufeae', L'\ufeae'), // AR_REH, // ر
		Letter(L'\u0632', L'\ufeaf', L'\u0632', L'\ufeb0', L'\ufeb0'), // AR_ZAIN, // ز
		Letter(L'\u0633', L'\ufeb1', L'\ufeb3', L'\ufeb4', L'\ufeb2'), // AR_SEEN, // س
		Letter(L'\u0634', L'\ufeb5', L'\ufeb7', L'\ufeb8', L'\ufeb6'), // AR_SHEEN, // ش
		Letter(L'\u0635', L'\ufeb9', L'\ufebb', L'\ufebc', L'\ufeba'), // AR_SAAD, // ص
		Letter(L'\u0636', L'\ufebd', L'\ufebf', L'\ufec0', L'\ufebe'), // AR_DAAD, // ض
		Letter(L'\u0637', L'\ufec1', L'\ufec3', L'\ufec4', L'\ufec2'), // AR_TAAH, // ط
		Letter(L'\u0638', L'\ufec5', L'\ufec7', L'\ufec8', L'\ufec6'), // AR_ZAAH, // ظ
		Letter(L'\u0639', L'\ufec9', L'\ufecb', L'\ufecc', L'\ufeca'), // AR_AIN, // ع
		Letter(L'\u063a', L'\ufecd', L'\ufecf', L'\ufed0', L'\ufece'), // AR_GHAIN, // غ
		Letter(L'\u0641', L'\ufed1', L'\ufed3', L'\ufed4', L'\ufed2'), // AR_FEH, // ف
		Letter(L'\u0642', L'\ufed5', L'\ufed7', L'\ufed8', L'\ufed6'), // AR_QAAF, // ق
		Letter(L'\u06a9', L'\ufb8e', L'\ufb90', L'\ufb91', L'\ufb8f'), // AR_KAAF, // ک
		Letter(L'\u0643', L'\ufed9', L'\ufedb', L'\ufedc', L'\ufeda'), // AR_KAAF_NO_HEAD, // ك
		Letter(L'\u0644', L'\ufedd', L'\ufedf', L'\ufee0', L'\ufede'), // AR_LAAM, // ل
		Letter(L'\u0645', L'\ufee1', L'\ufee3', L'\ufee4', L'\ufee2'), // AR_MEEM, // م
		Letter(L'\u0646', L'\ufee5', L'\ufee7', L'\ufee8', L'\ufee6'), // AR_NOON, // ن
		Letter(L'\u0648', L'\ufeed', L'\ufeed', L'\ufeee', L'\ufeee'), // AR_WAW, // و
		Letter(L'\u0647', L'\ufee9', L'\ufeeb', L'\ufeec', L'\ufeea'), // AR_HA, // ه
		Letter(L'\u06cc', L'\ufbfc', L'\ufbfe', L'\ufbff', L'\ufbfd'), // AR_YEH, // ی
		Letter(L'\u064a', L'\ufef1', L'\ufef3', L'\ufef4', L'\ufef2'), // AR_ARABIC_YEH, // ي
		Letter(L'\u0649', L'\ufeef', L'\u0649', L'\ufef0', L'\ufef0'), // AR_ALEF_MAKSURA, // ى
		Letter(L'\u0640', L'\u0640', L'\u0640', L'\u0640', L'\u0640'), // AR_TATWEEL, // ـ

		Letter(L'\ufefb', L'\ufefb', L'\ufefb', L'\ufefc', L'\ufefc'), // AR_LAAM_ALEF, // لا
		Letter(L'\ufef7', L'\ufef7', L'\ufef7', L'\ufef8', L'\ufef8'), // LaamAlefHamzaAbove, // لأ
		Letter(L'\ufef9', L'\ufef9', L'\ufef9', L'\ufefa', L'\ufefa'), // LaamAlefHamzaBelow, // لإ
		Letter(L'\ufef5', L'\ufef5', L'\ufef5', L'\ufef6', L'\ufef6'), // LaamAlefMaddahAbove, // لآ
		Letter(L'\ufdf2', L'\ufdf2', L'\ufdf2', L'\ufdf2', L'\ufdf2'), // AR_ALLAH, // ﷲ

		// Farsi
		Letter(L'\u067e', L'\ufb56', L'\ufb58', L'\ufb59', L'\ufb57'), // FaPehEXT, // پ
		Letter(L'\u06af', L'\ufb92', L'\ufb94', L'\ufb95', L'\ufb93'), // AR_EXT_FA_GAAF, // گ
		Letter(L'\u0686', L'\ufb7a', L'\ufb7c', L'\ufb7d', L'\ufb7b'), // AR_EXT_FA_CHEH, // چ
		Letter(L'\u0698', L'\ufb8a', L'\u0698', L'\ufb8b', L'\ufb8b'), // AR_EXT_FA_JEH, // ژ

		// Urdu
		Letter(L'\u0679', L'\ufb66', L'\ufb68', L'\ufb69', L'\ufb67'), // AR_EXT_UR_TE  , // ٹ
		Letter(L'\u0688', L'\ufb88', L'\ufb88', L'\ufb89', L'\ufb89'), // AR_EXT_UR_DAL, // ڈ
		Letter(L'\u0691', L'\ufb8c', L'\ufb8c', L'\ufb8d', L'\ufb8d'), // AR_EXT_UR_RE, // ڑ
		Letter(L'\u06ba', L'\ufb9e', L'\ufb9e', L'\ufb9f', L'\ufb9f'), // UrNunghunna, // ں
		Letter(L'\u06d2', L'\ufbae', L'\ufbae', L'\ufbaf', L'\ufbaf'), // UrBariyeEXT, // ے
		Letter(L'\u06be', L'\ufbaa', L'\ufbac', L'\ufbad', L'\ufbab'), // AR_EXT_UR_HE, // ھ
		Letter(L'\u06c1', L'\ufba6', L'\ufba8', L'\ufba9', L'\ufba7'), // AR_EXT_UR_HA, // ہ
	};
	// ReSharper restore CommentTypo,  IdentifierTypo
}
