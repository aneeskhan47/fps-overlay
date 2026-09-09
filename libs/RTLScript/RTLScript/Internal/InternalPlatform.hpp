#pragma once

// Static linking into fps-overlay (not a DLL).
#ifndef RTL_SCRIPT_API
#define RTL_SCRIPT_API
#endif

#ifdef _MSC_VER
#define RTL_SCRIPT_SELECTANY_API extern __declspec(selectany)
#else
#define RTL_SCRIPT_SELECTANY_API extern
#endif
