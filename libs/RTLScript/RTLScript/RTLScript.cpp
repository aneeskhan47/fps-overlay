// RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType

#include "RTLScript.hpp"

#include <cwctype>
#include <sstream>
#include <unordered_set>

namespace RTLScript
{
	namespace Anon
	{
		void ProcessCustomLettersCombinationCondition(UString& text, const CustomLettersCombinationConditionEvent& condition) {
			for (size_t i = 0; i < text.size(); i++) {
				if (MatchesLetterAnyForm(text[i], Arabic::ALPHABET_ALL_LETTERS[condition.TriggerLettersCombinations[0][0]])) {
					if (!condition.OnTriggerAction(text, i))
						return;
				}
			}
		}

		void ProcessCustomLettersCombinationConditions(UString& text, const std::vector<CustomLettersCombinationConditionEvent>& conditions) {
			for (const auto& condition : conditions)
				ProcessCustomLettersCombinationCondition(text, condition);
		}
	}

	static const CustomLettersCombinationConditionEvent ON_LAA_ALEF_WORD_CONDITION = {
.TriggerLettersCombinations = { L"لا" },
.Flags = CustomLettersCombinationConditionEventTriggerOnFlagBits::WordExactMatch,
.OnTriggerAction = [](UString& str, const size_t& i) {
		str = Arabic::ALPHABET_ALL_LETTERS[Arabic::Alphabet::LaamAlef].Unicode;
		return true;
	},
	};

	LetterForm GetArabicLetterForm(const UChar& prev, const UChar& next) {
		bool inPrevious = false, inNext = false;
		for (auto const& letter : Arabic::ALPHABET_ALL_LETTERS) {
			if (letter.Unicode == prev) inPrevious = true;
			if (letter.Unicode == next) inNext = true;
		}

		if (inPrevious && inNext)
			return LetterForm::Medium;
		if (inNext)
			return LetterForm::Beginner;
		if (inPrevious)
			return LetterForm::Final;

		return LetterForm::Isolated;
	}

	bool IsArCharBeginner(const UChar& arabicChar) {
		return arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefHamzaAbove].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefMaddahAbove].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::Alef].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::Hamza].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::WawHamzaAbove].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefHamzaBelow].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::Daal].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::Thaal].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::Reh].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::Zain].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::FaJehEXT].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::Waw].Unicode ||
			arabicChar == Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefMaksura].Unicode;
	}

	size_t* FindArCharIndex(const UChar& arabicChar) {
		for (size_t i = 0; i < Arabic::ALPHABET_ALL_LETTERS.size(); i++)
			if (MatchesLetterAnyForm(arabicChar, Arabic::ALPHABET_ALL_LETTERS[i]))
				return &i;

		return nullptr;
	}

	bool IsArabicLetter(const UChar& arabicChar) {
		return std::ranges::any_of(Arabic::ALPHABET_ALL_LETTERS, [&](const auto& letter) { return MatchesLetterAnyForm(arabicChar, letter); });
	}

	bool MatchesLetterAnyForm(const UChar& c, const Letter& letter) {
		return c == letter.Unicode || c == letter.Isolated || c == letter.Beginner || c == letter.Medium || c == letter.Final;
	}

	bool CodePointInGlyphRanges(const uint32_t codepoint, const std::vector<GlyphRange>& glyphRanges) {
		return std::ranges::any_of(glyphRanges, [&](const auto& range) { return range.Contains(codepoint); });
	}

	bool IsPunctuationOrDigit(const UChar c) { return std::iswpunct(c) || std::iswdigit(c); }

	UString ReverseRTLText(const UString& str, const std::vector<GlyphRange>& glyphRanges) {
		UString reversedStr;

		std::wistringstream wif(str);
		UString line;

		bool isFirstLine = true;

		while (std::getline(wif, line)) {
			if (!isFirstLine)
				reversedStr.push_back('\n');

			isFirstLine = false;

			UString temp;

			ReverseRTLLine(reversedStr, line, temp, glyphRanges);

			if (!temp.empty())
				reversedStr.append(temp);
		}
		return reversedStr;
	}

	void ReverseRTLLine(UString& reversedString, const UString& line, UString& temp, const std::vector<GlyphRange>& glyphRanges) {
		bool prevRTL = false;

		for (size_t i = 0; i < line.size(); i++) {
			const bool isRTL = CodePointInGlyphRanges(line[i], glyphRanges);
			const bool isPunctuationOrDigitOrSpace = IsPunctuationOrDigit(line[i]) || std::iswspace(line[i]);

			if (isRTL || prevRTL && isPunctuationOrDigitOrSpace) {
				prevRTL = true;
				//if (isPunctuationOrDigitOrSpace) // To fix a char of count 1. to fix this bug: !?
				temp = line[i] + temp;
				//else {
					//temp = (wstr() + line[i]) + line[i + 1] + temp;
					//i++;
				//}
			}
			else {
				// Check if is no RTL text to change the direction.
				if (!isPunctuationOrDigitOrSpace)
					prevRTL = false;

				reversedString.insert(reversedString.end(), line[i]);
			}
		}
	}

	bool HasAnyTypeOfLaamAlef(const UChar& arabicChar) {
		return std::ranges::any_of(Arabic::ALL_LAAM_ALEF_VARIANTS, [&](const auto& variant) {
			return MatchesLetterAnyForm(arabicChar, Arabic::ALPHABET_ALL_LETTERS[variant]);
			});
	}

	bool CheckForAnyArabicDiacritic(const UChar& arabicChar) {
		const std::unordered_set diacritics(
			Arabic::TASHKIL_ALL_DIACRITICS.begin(),
			Arabic::TASHKIL_ALL_DIACRITICS.end()
		);
		return diacritics.contains(arabicChar);
	}

	size_t* GetPreviousCharElementIgnoringDiacritic(const UString& text, const size_t& element) {
		if (element == 0)
			return nullptr;

		size_t outElement = element - 1;

		if (!CheckForAnyArabicDiacritic(text[outElement]))
			return &outElement;

		return GetPreviousCharElementIgnoringDiacritic(text, outElement);
	}

	size_t* GetNextCharElementIgnoringDiacritic(const UString& text, const size_t& element) {
		size_t outElement = element + 1;
		if (outElement <= text.size() - 1) {
			if (!CheckForAnyArabicDiacritic(text[outElement]))
				return &outElement;

			return GetNextCharElementIgnoringDiacritic(text, outElement);
		}

		return nullptr;
	}

	UChar GetArCharGlyph(const UChar& arabicChar, const UChar& prev, const UChar& next) {
		const auto& charIndexIdx = FindArCharIndex(arabicChar);

		if (charIndexIdx == nullptr)
			return arabicChar;

		const auto& charIndex = *charIndexIdx;

		switch (GetArabicLetterForm(prev, next)) {
			case LetterForm::Medium:
				if (IsArCharBeginner(prev)) {
					if (Arabic::ALPHABET_ALL_LETTERS[charIndex].Beginner == Arabic::ALPHABET_ALL_LETTERS[Arabic::Yeh].Beginner)
						return Arabic::ALPHABET_ALL_LETTERS[Arabic::ArabicYeh].Beginner;

					return Arabic::ALPHABET_ALL_LETTERS[charIndex].Beginner;
				}
				if (Arabic::ALPHABET_ALL_LETTERS[charIndex].Medium == Arabic::ALPHABET_ALL_LETTERS[Arabic::Yeh].Medium)
					return Arabic::ALPHABET_ALL_LETTERS[Arabic::ArabicYeh].Medium;

				if (HasAnyTypeOfLaamAlef(prev))
					return Arabic::ALPHABET_ALL_LETTERS[charIndex].Beginner;

				return Arabic::ALPHABET_ALL_LETTERS[charIndex].Medium;
			case LetterForm::Beginner:
				if (Arabic::ALPHABET_ALL_LETTERS[charIndex].Beginner == Arabic::ALPHABET_ALL_LETTERS[Arabic::Yeh].Beginner)
					return Arabic::ALPHABET_ALL_LETTERS[Arabic::ArabicYeh].Beginner;

				return Arabic::ALPHABET_ALL_LETTERS[charIndex].Beginner;
			case LetterForm::Final:
				if (IsArCharBeginner(prev)) {
					if (Arabic::ALPHABET_ALL_LETTERS[charIndex].Isolated == Arabic::ALPHABET_ALL_LETTERS[Arabic::Yeh].Isolated)
						return Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefMaksura].Isolated;

					return Arabic::ALPHABET_ALL_LETTERS[charIndex].Isolated;
				}
				if (Arabic::ALPHABET_ALL_LETTERS[charIndex].Final == Arabic::ALPHABET_ALL_LETTERS[Arabic::Yeh].Final)
					return Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefMaksura].Final;

				if (HasAnyTypeOfLaamAlef(prev))
					return Arabic::ALPHABET_ALL_LETTERS[charIndex].Isolated;

				return Arabic::ALPHABET_ALL_LETTERS[charIndex].Final;

			case LetterForm::Unicode:  // Skip...
			case LetterForm::Isolated: // Skip...
			break;                     // Skip...
		}

		if (Arabic::ALPHABET_ALL_LETTERS[charIndex].Isolated == Arabic::ALPHABET_ALL_LETTERS[Arabic::Yeh].Isolated)
			return Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefMaksura].Isolated;

		return Arabic::ALPHABET_ALL_LETTERS[charIndex].Isolated;
	}

	/*void CheckForARWordAndReplace(const std::vector<ArabicAlphabets> checkFor, const wstr replaceTo, std::vector<wstr>& text)
	{
		const size_t checkForSize = checkFor.size();
		const size_t size = text.size();
		for (size_t i = 0; i < size; i++)
		{
			if (i < (size - checkForSize))
			{
				bool found = false;
				for (size_t c = 0; c < checkForSize; c++)
				{
					if (MatchesLetterAnyForm(text[i + c], checkFor[c]))
					{
						found = true;
						//break;
					}
					else
					{
						if (found)
						{
							found = false;
						}
					}
				}
				if (found)
				{
					text[i] = replaceTo;
					for (size_t c = 0; c < checkForSize; c++)
					{
						text.erase(text.begin() + (i + c));
					}
				}
			}
			break;
		}
	}*/

	static const CustomLettersCombinationConditionEvent ON_ALLAH_WORD_CONDITION = {
		.TriggerLettersCombinations = { L"الله" },
		.Flags = CustomLettersCombinationConditionEventTriggerOnFlagBits::WordExactMatch,
		.OnTriggerAction = [](UString& str, const size_t& i) {
			str = Arabic::ALPHABET_ALL_LETTERS[Arabic::Alphabet::Allah].Unicode;
			return true;
		},
	};

	UString ConvertToFixed(const UString& text, const std::vector<GlyphRange>& glyphRanges, const ConvertToFixedFlags flags) {
		if (text.empty()) return{};

		const UString reversedText = ReverseRTLText(text, glyphRanges);

		// ProcessCustomLettersCombinationConditions(reversedText,
		// 	{
		// 		ON_LAA_ALEF_WORD_CONDITION,
		// 		ON_ALLAH_WORD_CONDITION,
		// 	}
		// 	);

		// Change chars to they correct form for example: ل + ا = لا
		// for (size_t i = 0; i < reversedText.size(); i++) {
		// 	int elementPlus1 = i + 1;
		// 	if ((flags & ConvertToFixedFlagBits::EnableSpecialWordAllahForm) != ConvertToFixedFlagBits::None && i < reversedText.size() - 3)
		// 		// ﷲ
		// 		if (MatchesLetterAnyForm(reversedText[i], Arabic::ALPHABET_ALL_LETTERS[Arabic::Ha]) && MatchesLetterAnyForm(reversedText[elementPlus1], Arabic::ALPHABET_ALL_LETTERS[Arabic::Laam]) && MatchesLetterAnyForm(reversedText[i + 2], Arabic::ALPHABET_ALL_LETTERS[Arabic::Laam]) && MatchesLetterAnyForm(reversedText[i + 3], Arabic::ALPHABET_ALL_LETTERS[Arabic::Alef])) {
		// 			reversedText[i] = Arabic::ALPHABET_ALL_LETTERS[Arabic::Alphabet::Allah].Unicode];
		// 			reversedText.erase(reversedText.begin() + elementPlus1, reversedText.begin() + i + 4);
		// 		}
		// 
		// 	if ((flags & ConvertToFixedFlagBits::EnableJointLaamAlefForm) != ConvertToFixedFlagBits::None && i < reversedText.size() - 1)
		// 		// لا
		// 		if (MatchesLetterAnyForm(reversedText[i], Arabic::ALPHABET_ALL_LETTERS[Arabic::Alef]) && MatchesLetterAnyForm(reversedText[elementPlus1], Arabic::ALPHABET_ALL_LETTERS[Arabic::Laam])) {
		// 			reversedText[i] = Arabic::ALPHABET_ALL_LETTERS[Arabic::Alphabet::LaamAlef].Unicode];
		// 			reversedText.erase(reversedText.begin() + elementPlus1);
		// 		}
		// 
		// 	// لأ
		// 	if (MatchesLetterAnyForm(reversedText[i], Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefHamzaAbove]) && MatchesLetterAnyForm(reversedText[elementPlus1], Arabic::ALPHABET_ALL_LETTERS[Arabic::Laam])) {
		// 		reversedText[i] = Arabic::ALPHABET_ALL_LETTERS[Arabic::LaamAlefHamzaAbove].Unicode];
		// 		reversedText.erase(reversedText.begin() + elementPlus1);
		// 	}
		// 
		// 	// لإ
		// 	if (MatchesLetterAnyForm(reversedText[i], Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefHamzaBelow]) && MatchesLetterAnyForm(reversedText[elementPlus1], Arabic::ALPHABET_ALL_LETTERS[Arabic::Laam])) {
		// 		reversedText[i] = Arabic::ALPHABET_ALL_LETTERS[Arabic::LaamAlefHamzaBelow].Unicode];
		// 		reversedText.erase(reversedText.begin() + elementPlus1);
		// 	}
		// 
		// 	// لآ
		// 	if (MatchesLetterAnyForm(reversedText[i], Arabic::ALPHABET_ALL_LETTERS[Arabic::AlefMaddahAbove]) && MatchesLetterAnyForm(reversedText[elementPlus1], Arabic::ALPHABET_ALL_LETTERS[Arabic::Laam])) {
		// 		reversedText[i] = Arabic::ALPHABET_ALL_LETTERS[Arabic::LaamAlefMaddahAbove].Unicode];
		// 		reversedText.erase(reversedText.begin() + elementPlus1);
		// 	}
		// }

		UChar previousChar, nextChar;
		UString convertedText;

		for (size_t i = 0; i < reversedText.size(); i++) {
			if ((flags & ConvertToFixedFlagBits::JoiningArabicLetters) != ConvertToFixedFlagBits::None && IsArabicLetter(reversedText[i])) {
				if (const auto elementMinus1 = GetPreviousCharElementIgnoringDiacritic(reversedText, i);
					elementMinus1 != nullptr && IsArabicLetter(reversedText[*elementMinus1]))
					previousChar = reversedText[*elementMinus1];
				else
					previousChar = NULL_CHAR;

				if (const auto elementPlus1 = GetNextCharElementIgnoringDiacritic(reversedText, i);
					elementPlus1 != nullptr && IsArabicLetter(reversedText[*elementPlus1]))
					nextChar = reversedText[*elementPlus1];
				else
					nextChar = NULL_CHAR;

				// Note: nextChar and previousChar are swapped because the text is reversed.
				convertedText.push_back(GetArCharGlyph(reversedText[i], nextChar, previousChar)); // NOLINT(readability-suspicious-call-argument)
			}
			else
				convertedText.push_back(reversedText[i]);
		}
		return convertedText;
	}
}
