// RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType

#pragma once

#include "../Internal/InternalPlatform.hpp"

#include <stdexcept>
#include <algorithm>
#include <functional>
#include <string>

namespace RTLScript {
	using UString = std::wstring;
	using UChar = wchar_t;

	struct RTL_SCRIPT_API GlyphRange {
		uint32_t StartCodepoint{}, EndCodepoint{};

		constexpr GlyphRange(const uint32_t start, const uint32_t end) : StartCodepoint(start), EndCodepoint(end) {
			// static_assert(start > end, "StartCodepoint must be <= EndCodepoint");
			// if (start > end)
			// 	throw std::invalid_argument("StartCodepoint must be <= EndCodepoint");
		}

		[[nodiscard]] constexpr bool Contains(const uint32_t codepoint) const { return codepoint >= StartCodepoint && codepoint <= EndCodepoint; }
	};

	enum class RTL_SCRIPT_API LetterForm : uint32_t {
		Unicode,
		Isolated,
		Beginner,
		Medium,
		Final,
	};

	struct RTL_SCRIPT_API Letter {
		UChar Unicode{}, Isolated{}, Beginner{}, Medium{}, Final{};

		constexpr explicit Letter(const UChar unicode, const UChar isolated, const UChar beginner, const UChar medium, const UChar final)
			: Unicode(unicode), Isolated(isolated), Beginner(beginner), Medium(medium), Final(final) { }

		constexpr const auto& operator[](const LetterForm& form) const {
			switch (form) {
				case LetterForm::Unicode:  /**/ return Unicode;
				case LetterForm::Isolated: /**/ return Isolated;
				case LetterForm::Beginner: /**/ return Beginner;
				case LetterForm::Medium:   /**/ return Medium;
				case LetterForm::Final:    /**/ return Final;
			}
			throw std::out_of_range("Index out of range in Letter struct");
		}
	};
}