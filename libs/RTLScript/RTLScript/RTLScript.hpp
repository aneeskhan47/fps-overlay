// RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType

#pragma once

#include "Internal/Internal.hpp"

namespace RTLScript
{
	using TextVector = std::vector<UChar>;

	enum class RTL_SCRIPT_API VersionType : uint32_t {
		Stable,
		Preview,
		Beta,
	};

	constexpr auto NAME = "RTLScript"; 	             // RTLScript name.
	constexpr auto VERSION = "2.0.0";	             // RTLScript version.
	constexpr uint32_t VERSION_NUM = 200;            // RTLScript version number.
	constexpr auto RELEASE_TYPE = VersionType::Beta; // RTLScript release type for example: STABLE, PREVIEW, BETA.

	using ConvertToFixedFlags = uint32_t;

	namespace ConvertToFixedFlagBits
	{
		enum RTL_SCRIPT_API : ConvertToFixedFlags {
			None                       /**/ = 0x00,
			JoiningArabicLetters       /**/ = 0x01,
			EnableSpecialWordAllahForm /**/ = 0x02, // Enables: الله
			EnableJointLaamAlefForm    /**/ = 0x04, // Enables: لا
		};
	};

	RTL_SCRIPT_SELECTANY_API constexpr auto DEFAULT_CONVERT_TO_FIXED_FLAGS =
		ConvertToFixedFlagBits::JoiningArabicLetters |
		ConvertToFixedFlagBits::EnableSpecialWordAllahForm |
		ConvertToFixedFlagBits::EnableJointLaamAlefForm;

	RTL_SCRIPT_SELECTANY_API constexpr UChar NULL_CHAR{}; // {} is default NULL value for a char.

	/// <summary>Get Arabic/Farsi/Urdu character place in a word for its form, depends on its previous and next character.</summary>
	/// <param name="prev">Previous character, to check if it's connected to arabicChar or not.</param>
	/// <param name="next">Next character, to check if it's connected to arabicChar or not.</param>
	/// <returns>Returns an int in type of char. Possible values: 0- no connection, 1- connected from behind, 2- connected from front, 3- connected from both side.</returns>
	RTL_SCRIPT_API LetterForm GetArabicLetterForm(const UChar& prev, const UChar& next);

	/// <summary>Check if given character is Arabic letter in beginner form or not.</summary>
	/// <param name="arabicChar">Character you want to check.</param>
	/// <returns>Returns a bool value. Possible values: true, false.</returns>
	RTL_SCRIPT_API bool IsArCharBeginner(const UChar& arabicChar);

	/// <summary>Find vector index of the give character in Ar_AlphabetsAllForms vector</summary>
	/// <param name="arabicChar">Character you want to get its index.</param>
	/// <returns>Returns a size_t* value if nullptr nothing found.</returns>
	RTL_SCRIPT_API size_t* FindArCharIndex(const UChar& arabicChar);

	/// <summary>Check if given character is Arabic letter or not.</summary>
	/// <param name="arabicChar">Character you want to check.</param>
	/// <returns>Returns a bool value. Possible values: true, false.</returns>
	RTL_SCRIPT_API bool IsArabicLetter(const UChar& arabicChar);

	/// <summary>Check if given Arabic character is the Arabic letter that you want to check for.</summary>
	RTL_SCRIPT_API bool MatchesLetterAnyForm(const UChar& c, const Letter& letter);

	//enum class CodepointResultType {
	//	Success,
	//	Empty,
	//	WrongFormat,
	//};
	//
	//struct CodepointResult {
	//	uint32_t Codepoint{}; // Unicode codepoint (or -1 if invalid)
	//	uint32_t BytesUsed{}; // Number of bytes read from the input string
	//	CodepointResultType Type = CodepointResultType::WrongFormat;
	//
	//	explicit CodepointResult(const CodepointResultType type) : Type(type) {}
	//	CodepointResult(const uint32_t codepoint, const uint32_t bytesUsed) : Codepoint(codepoint), BytesUsed(bytesUsed), Type(CodepointResultType::Success) {}
	//};

	using CustomLettersCombinationConditionEventTriggerOnFlags = uint32_t;

	namespace CustomLettersCombinationConditionEventTriggerOnFlagBits
	{
		enum RTL_SCRIPT_API : CustomLettersCombinationConditionEventTriggerOnFlags {
			None                       /**/ = 0x00,
			WordExactMatch             /**/ = 0x01,
			WordStartMatch             /**/ = 0x02,
			WordEndMatch               /**/ = 0x03,
			WordAnySegmentMatch        /**/ = 0x04,
		};
	};

	struct RTL_SCRIPT_API CustomLettersCombinationConditionEvent {
		std::vector<UString> TriggerLettersCombinations;
		CustomLettersCombinationConditionEventTriggerOnFlags Flags{};
		std::function<bool(UString& str, const size_t& i)> OnTriggerAction = nullptr; // Return true to continue processing other conditions, false to skip.
	};

	/// <summary> Check if the code point is RTL. </summary>
	/// <returns>Returns a bool value. Possible values: true, false.</returns>
	RTL_SCRIPT_API bool CodePointInGlyphRanges(const uint32_t codepoint, const std::vector<GlyphRange>& glyphRanges);

	/// <summary> Check if the char is punctuation or digit. </summary>
	/// <param name="c">A char.</param>
	/// <returns>Returns a bool value. Possible values: true, false.</returns>
	RTL_SCRIPT_API bool IsPunctuationOrDigit(const UChar c);

	/// <summary>Reverses Arabic/Farsi/Hebrew/Urdu... each of them containing RTL letters with different byte counts.</summary>
	RTL_SCRIPT_API UString ReverseRTLText(const UString& str, const std::vector<GlyphRange>& glyphRanges);

	/// <summary>Reverses Arabic/Farsi/Hebrew/Urdu... each of them containing RTL letters with different byte counts.</summary>
	RTL_SCRIPT_API void ReverseRTLLine(UString& reversedString, const UString& line, UString& temp, const std::vector<GlyphRange>& glyphRanges);

	/// <summary>Checks if the Arabic character represents  any type of LaamAlef.</summary>
	/// <returns>Returns a bool value. Possible values: true, false.</returns>
	RTL_SCRIPT_API bool HasAnyTypeOfLaamAlef(const UChar& arabicChar);

	/// <summary>Checks if the Arabic character is representing any type of Arabic diacritic.</summary>
	/// <returns>Returns a bool value. Possible values: true, false.</returns>
	RTL_SCRIPT_API bool CheckForAnyArabicDiacritic(const UChar& arabicChar);

	/// <summary>Gets the previous char ignoring diacritic char.</summary>
	/// <returns>Returns a size_t* value if nullptr nothing found!</returns>
	RTL_SCRIPT_API size_t* GetPreviousCharElementIgnoringDiacritic(const UString& text, const size_t& element);

	/// <summary>Gets the next char ignoring diacritic char.</summary>
	RTL_SCRIPT_API size_t* GetNextCharElementIgnoringDiacritic(const UString& text, const size_t& element);

	/// <summary>Get correct Unicode of Arabic/Farsi/Urdu letter depending on its position, previous, and next letters.</summary>
	/// <param name="arabicChar">Character you want to check.</param>
	/// <param name="prev">Previous character, to check if it's connected to ar char or not.</param>
	/// <param name="next">Next character, to check if it's connected to arCharacter or not.</param>
	RTL_SCRIPT_API UChar GetArCharGlyph(const UChar& arabicChar, const UChar& prev, const UChar& next);

	/// <summary> The main method to convert your text to a fixed text with BIDI. </summary>
	RTL_SCRIPT_API UString ConvertToFixed(const UString& text, const std::vector<GlyphRange>& glyphRanges, const ConvertToFixedFlags flags = DEFAULT_CONVERT_TO_FIXED_FLAGS);
}