## RTLScript (2.0 initial beta currently not very tested maybe not working as expected)
A simple tiny library for Arabic, Hebrew, Farsi, Urdu and etc. for modern CXX standards.

**RTLScript is a fork of FarsiType: https://github.com/AmyrAhmady/FarsiType**

Tested with Clang CXX standard 23 need to also work with CXX 20
*Just a logo that i made for fun i Love to make a logos for my projects (:*

![RTLTypeLogo](https://github.com/oscar7070/RTLType/assets/56559647/1d01306a-8669-4920-98d4-6554cf16e600)

## Screenshots (using [ImGui](https://github.com/ocornut/imgui) for rendering through [ExtremeEngine](https://github.com/oscar7070/ExtremeEngine))
Correct Form:  
![ScreenShot](https://github.com/oscar7070/RTLScript/blob/master/screenshots/Fixed.png)
  
Broken:   
![ScreenShot](https://github.com/oscar7070/RTLScript/blob/master/screenshots/Broken.png)

## About
Hi, i needed RTL text in my project and i found a beautiful repository named FarsiType(https://github.com/AmyrAhmady/FarsiType) and i decided to improve it for my needs.

## Features
1. RTLScript have a full support for Arabic, Hebrew, Farsi and Urdu.
2. Supports extra symbols like: لا, لأ, لآ, لإ, الله.
3. Supports Arabic tashkil(diacritic) for example: َ  ً  ُ  ٌ  ِ  ٍ  ْ and some other.
4. Very easy to work with it.
5. Support RTL and LTR text in the same line.
6. Uses RAII and regular standart headers.

## How to use it?
RTLScript is very easy to use:
```
#define RTL_SCRIPT_RAII_ENABLE_HEBREW // To enable Hebrew feature.
#define RTL_SCRIPT_RAII_ENABLE_FARSI  // To enable Farsi feature.
// No need to enable Arabic feature, it's enabled by default.
#include <RTLScript/RTLScript-RAII.hpp> // Recommended to use the RAII header, but it's not necessary.

void main()
{
	const RTLScript::Raii::Instance instance; // No need to manually clean up anything, the RAII instance will handle it.

	// No need manually set glyph ranges if you are using the RAII header, it's already set for Arabic, Farsi, and Hebrew. only if you need special glyph ranges
	// instance.SetGlyphRanges({ RTLScript::Arabic::GLYPH_RANGE, RTLScript::Hebrew::GLYPH_RANGE, RTLScript::GlyphRange(6u, 7u) });
	// instance.SetFlags(RTLScript::ConvertToFixedFlagBits::EnableJointLaamAlefForm); // can set custom flags if needed.

	const RTLScript::UString text = L"أنا أحب الأناناس"; // Need to pass a wide string.
	const auto fixedText = instance.ConvertToFixed(text); // Convert to fixed text.

	// Now do with the result what you want!
}
```

## Not working?
First, if it's not working make sure that your project setted to MultiByte or Unicode and not ASCII.

Second, check that you are using /utf-8.

Third, check if your project files saved in utf-8.

Fourth, choose a font that supports that RTL language that you want to use.
