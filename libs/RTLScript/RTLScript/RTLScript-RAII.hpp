// RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType

// ReSharper disable CppClangTidyClangDiagnosticPadded, CppClangTidyCppcoreguidelinesSpecialMemberFunctions
#pragma once

#include "Internal/Internal.hpp"

#ifdef RTL_SCRIPT_RAII_ENABLE_FARSI
#include "Langs/Farsi.hpp"
#endif

#ifdef RTL_SCRIPT_RAII_ENABLE_HEBREW
#include "Langs/Hebrew.hpp"
#endif

#include "RTLScript.hpp"

namespace RTLScript::Raii
{
	// Base class for RAII object.
	// class RTL_SCRIPT_API ObjectBase {
	// public:
	// 	virtual ~ObjectBase() = default;
	// 	void Dispose() const { delete this; }
	// };

	// RTLScript RAII Instance.
	class RTL_SCRIPT_API Instance {
	public:
		Instance();
		virtual ~Instance();

		[[nodiscard]] UString ConvertToFixed(const UString& str) const;

		[[nodiscard]] const auto& GetFlags() const { return Flags_; }
		void SetFlags(const ConvertToFixedFlags flags) { Flags_ = flags; }

		[[nodiscard]] const auto& GetGlyphRanges() const { return GlyphRanges_; }

		// Sets the glyph ranges used for RTL detection only! otherwise if you include glyphs that are for LTR you will brake the text.
		void SetGlyphRanges(std::vector<GlyphRange> glyphRanges) { GlyphRanges_ = std::move(glyphRanges); }
	private:
		ConvertToFixedFlags Flags_ = DEFAULT_CONVERT_TO_FIXED_FLAGS;

		std::vector<GlyphRange> GlyphRanges_ = {
Arabic::GLYPH_RANGE,
#ifdef RTL_SCRIPT_RAII_ENABLE_HEBREW
		Hebrew::GLYPH_RANGE,
#endif
		};
	};
};