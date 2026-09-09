// RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType

#include "RTLScript-RAII.hpp"

namespace RTLScript::Raii
{
	Instance::Instance() = default;
	Instance::~Instance() = default;

	UString Instance::ConvertToFixed(const UString& str) const {
		return RTLScript::ConvertToFixed(str, GlyphRanges_, Flags_);
	}
};