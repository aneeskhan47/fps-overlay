// FPS Overlay — Lightweight DirectX 11 + ImGui performance monitor
//
// Features:
//   - Real game FPS via ETW (Event Tracing for Windows — hooks DXGI Present)
//   - GPU usage & temperature via LibreHardwareMonitor (supports NVIDIA, AMD, Intel)
//   - CPU / RAM monitoring
//   - Hardware names (CPU model, GPU model)
//   - Custom hotkey binding
//   - System tray integration
//
// Requires: run as Administrator for game FPS capture (ETW needs it)

#include <windows.h>
#include <dwmapi.h>
#include <d3d11.h>
#include <dxgi.h>
#include <shellapi.h>
#include <evntrace.h>
#include <evntcons.h>
#include <psapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <algorithm>

// Note: Link with -lwbemuuid -lole32 -loleaut32 for WMI support
// Note: Link with lhwm-cpp-wrapper.lib and mscoree.lib for LibreHardwareMonitor support

#include "imgui.h"
#include "lhwm-cpp-wrapper.h"
#include <tuple>
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

// ═══════════════════════════════════════════════════════════════════════════
// Constants & safety defines
// ═══════════════════════════════════════════════════════════════════════════
#define WM_TRAYICON   (WM_USER + 1)
#define IDM_SETTINGS  1001
#define IDM_EXIT      1002
#define IDM_SHOW      1003
#define IDM_HIDE      1004

#ifndef PROCESS_TRACE_MODE_EVENT_RECORD
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000
#endif
#ifndef PROCESS_TRACE_MODE_REAL_TIME
#define PROCESS_TRACE_MODE_REAL_TIME    0x00000100
#endif
#ifndef EVENT_CONTROL_CODE_ENABLE_PROVIDER
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER 1
#endif
#ifndef TRACE_LEVEL_INFORMATION
#define TRACE_LEVEL_INFORMATION 4
#endif

// Microsoft-Windows-DXGI provider  {CA11C036-0102-4A2D-A6AD-F03CFED5D3C9}
static const GUID DXGI_PROVIDER =
    { 0xCA11C036, 0x0102, 0x4A2D, { 0xA6, 0xAD, 0xF0, 0x3C, 0xFE, 0xD5, 0xD3, 0xC9 } };

static const char* ETW_SESSION_NAME = "FPSOverlay_ETW";

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════
struct OverlayConfig {
    bool showFPS  = true;
    bool showCPU  = true;
    bool showGPU  = true;
    bool showVRAM = true;     // GPU VRAM usage
    bool showRAM  = true;
    bool horizontal = false;  // horizontal compact view
    bool useFahrenheit = false; // false = Celsius, true = Fahrenheit
    int  position = 0;        // 0=TL  1=TR  2=BL  3=BR
    int  opacity  = 85;       // 30..100 %
    int  toggleKey = VK_INSERT;
    int  exitKey   = VK_END;
    float customX = -1.0f;    // custom position (-1 = use corner preset)
    float customY = -1.0f;
    int  selectedGpu = 0;     // selected GPU index (0 = first GPU)
};

// ═══════════════════════════════════════════════════════════════════════════
// GPU list (for multi-GPU support via LHWM)
// ═══════════════════════════════════════════════════════════════════════════
#define MAX_GPUS 8
struct GpuInfo {
    char name[256];
    std::string tempPath;      // LHWM sensor path for temperature
    std::string loadPath;      // LHWM sensor path for GPU load
    std::string vramUsedPath;  // LHWM sensor path for VRAM used
    std::string vramTotalPath; // LHWM sensor path for VRAM total
};
static GpuInfo g_gpuList[MAX_GPUS];
static int g_gpuCount = 0;

// Helper to convert Celsius to Fahrenheit
inline float ToDisplayTemp(float celsius, bool useFahrenheit) {
    return useFahrenheit ? (celsius * 9.0f / 5.0f + 32.0f) : celsius;
}

// Temperature thresholds (in Celsius) - adjust for F display comparison
inline float GetHighTempThreshold(bool useFahrenheit) { return useFahrenheit ? 185.0f : 85.0f; }
inline float GetMedTempThreshold(bool useFahrenheit) { return useFahrenheit ? 158.0f : 70.0f; }

// ═══════════════════════════════════════════════════════════════════════════
// Configuration file (INI) - saved next to overlay.exe
// ═══════════════════════════════════════════════════════════════════════════
static char g_configPath[MAX_PATH] = "";

static void InitConfigPath()
{
    if (g_configPath[0] != '\0') return; // already initialized
    
    // Get the directory where the executable is located
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    
    // Remove the executable name to get the directory
    char* lastSlash = strrchr(exePath, '\\');
    if (lastSlash) *(lastSlash + 1) = '\0';
    
    // Append the config filename
    snprintf(g_configPath, MAX_PATH, "%sconfig.ini", exePath);
}

static int ReadIniInt(const char* section, const char* key, int defaultVal)
{
    return GetPrivateProfileIntA(section, key, defaultVal, g_configPath);
}

static float ReadIniFloat(const char* section, const char* key, float defaultVal)
{
    char buf[32];
    GetPrivateProfileStringA(section, key, "", buf, sizeof(buf), g_configPath);
    if (buf[0] == '\0') return defaultVal;
    return (float)atof(buf);
}

static void WriteIniInt(const char* section, const char* key, int value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", value);
    WritePrivateProfileStringA(section, key, buf, g_configPath);
}

static void WriteIniFloat(const char* section, const char* key, float value)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f", value);
    WritePrivateProfileStringA(section, key, buf, g_configPath);
}

static void LoadConfig(OverlayConfig& cfg)
{
    InitConfigPath();
    
    // Check if config file exists
    DWORD attrib = GetFileAttributesA(g_configPath);
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        // No config file, use defaults
        return;
    }
    
    // Display settings
    cfg.showFPS       = ReadIniInt("Display", "showFPS", 1) != 0;
    cfg.showCPU       = ReadIniInt("Display", "showCPU", 1) != 0;
    cfg.showGPU       = ReadIniInt("Display", "showGPU", 1) != 0;
    cfg.showVRAM      = ReadIniInt("Display", "showVRAM", 1) != 0;
    cfg.showRAM       = ReadIniInt("Display", "showRAM", 1) != 0;
    
    // Layout settings
    cfg.horizontal    = ReadIniInt("Layout", "horizontal", 0) != 0;
    cfg.useFahrenheit = ReadIniInt("Layout", "useFahrenheit", 0) != 0;
    cfg.position      = ReadIniInt("Layout", "position", 0);
    cfg.opacity       = ReadIniInt("Layout", "opacity", 85);
    cfg.customX       = ReadIniFloat("Layout", "customX", -1.0f);
    cfg.customY       = ReadIniFloat("Layout", "customY", -1.0f);
    
    // Hotkeys
    cfg.toggleKey     = ReadIniInt("Hotkeys", "toggleKey", VK_INSERT);
    cfg.exitKey       = ReadIniInt("Hotkeys", "exitKey", VK_END);
    
    // GPU selection
    cfg.selectedGpu   = ReadIniInt("GPU", "selectedGpu", 0);
    
    // Clamp values to valid ranges
    if (cfg.position < 0 || cfg.position > 3) cfg.position = 0;
    if (cfg.opacity < 30) cfg.opacity = 30;
    if (cfg.opacity > 100) cfg.opacity = 100;
    if (cfg.selectedGpu < 0) cfg.selectedGpu = 0;
}

static void SaveConfig(const OverlayConfig& cfg)
{
    InitConfigPath();
    
    // Display settings
    WriteIniInt("Display", "showFPS", cfg.showFPS ? 1 : 0);
    WriteIniInt("Display", "showCPU", cfg.showCPU ? 1 : 0);
    WriteIniInt("Display", "showGPU", cfg.showGPU ? 1 : 0);
    WriteIniInt("Display", "showVRAM", cfg.showVRAM ? 1 : 0);
    WriteIniInt("Display", "showRAM", cfg.showRAM ? 1 : 0);
    
    // Layout settings
    WriteIniInt("Layout", "horizontal", cfg.horizontal ? 1 : 0);
    WriteIniInt("Layout", "useFahrenheit", cfg.useFahrenheit ? 1 : 0);
    WriteIniInt("Layout", "position", cfg.position);
    WriteIniInt("Layout", "opacity", cfg.opacity);
    WriteIniFloat("Layout", "customX", cfg.customX);
    WriteIniFloat("Layout", "customY", cfg.customY);
    
    // Hotkeys
    WriteIniInt("Hotkeys", "toggleKey", cfg.toggleKey);
    WriteIniInt("Hotkeys", "exitKey", cfg.exitKey);
    
    // GPU selection
    WriteIniInt("GPU", "selectedGpu", cfg.selectedGpu);
}

// ═══════════════════════════════════════════════════════════════════════════
// App state
// ═══════════════════════════════════════════════════════════════════════════
enum AppMode    { MODE_CONFIG, MODE_OVERLAY };
enum PendingCmd { CMD_NONE, CMD_START_OVERLAY, CMD_SHOW_SETTINGS, CMD_EXIT };

static OverlayConfig g_Config;
static AppMode       g_Mode       = MODE_CONFIG;
static PendingCmd    g_Pending    = CMD_NONE;
static bool          g_Running    = true;
static bool          g_OvlVisible = true;

static HINSTANCE      g_hInstance = nullptr;
static HWND           g_hwnd     = nullptr;
static NOTIFYICONDATA g_nid      = {};

// ── Hardware info ──
static char g_cpuName[256] = "Unknown";
static char g_gpuName[256] = "Unknown";

// ── GPU stats (from LHWM) ──
static float g_gpuUsage = 0.0f;
static float g_gpuTemp  = 0.0f;
static float g_vramUsed  = 0.0f;  // in GB
static float g_vramTotal = 0.0f;  // in GB

// ── ETW state ──
static TRACEHANDLE      g_etwSession = 0;
static TRACEHANDLE      g_etwTrace   = 0;
static std::thread      g_etwThread;
static std::atomic<bool>  g_etwRunning{false};
static std::atomic<float> g_gameFps{0.0f};
static std::atomic<DWORD> g_targetPid{0};
static DWORD              g_lastTargetPid = 0;    // to detect PID change
static bool               g_etwAvailable = false;
static bool               g_isAdmin = false;      // running as administrator?
static double              g_qpcFreq     = 1.0;
static char               g_targetProcessName[128] = "";  // current tracked process name

// ── CPU temperature (WMI) ──
static float g_cpuTemp = 0.0f;
static bool  g_cpuTempAvailable = false;

// ── LibreHardwareMonitor (LHWM) state ──
static bool  g_lhwmAvailable = false;
static std::string g_lhwmCpuTempPath;      // e.g., "/amdcpu/0/temperature/3"
static std::string g_lhwmGpuTempPath;      // e.g., "/gpu-nvidia/0/temperature/0"
static std::string g_lhwmGpuLoadPath;      // e.g., "/gpu-nvidia/0/load/0"
static std::string g_lhwmGpuVramUsedPath;  // VRAM used
static std::string g_lhwmGpuVramTotalPath; // VRAM total
static float g_lhwmCpuTemp = 0.0f;
static float g_lhwmGpuTemp = 0.0f;
static float g_lhwmGpuLoad = 0.0f;
static float g_lhwmGpuVramUsed = 0.0f;     // in GB
static float g_lhwmGpuVramTotal = 0.0f;    // in GB

// ── DX11 ──
static ID3D11Device*           g_pd3dDevice        = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext  = nullptr;
static IDXGISwapChain*         g_pSwapChain        = nullptr;
static ID3D11RenderTargetView* g_pRenderTargetView = nullptr;

// ── Hotkey listener state ──
static int  g_listeningFor = 0;   // 0=none, 1=toggle, 2=exit

// ═══════════════════════════════════════════════════════════════════════════
// Forward declarations
// ═══════════════════════════════════════════════════════════════════════════
bool    CreateDeviceD3D(HWND);
void    CleanupDeviceD3D();
void    CreateRenderTarget();
void    CleanupRenderTarget();
void    AddTrayIcon();
void    RemoveTrayIcon();
void    SwitchToOverlay();
void    SwitchToConfig();
void    ShutdownBackends();
void    InitBackends();
void    ApplyStyle();
static float GetCpuUsage();

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND, UINT, WPARAM, LPARAM);

// ═══════════════════════════════════════════════════════════════════════════
// Utility: key name from VK code
// ═══════════════════════════════════════════════════════════════════════════
static const char* GetKeyName(int vk)
{
    static char buf[64];
    UINT sc = MapVirtualKey(vk, MAPVK_VK_TO_VSC);
    LONG lp = sc << 16;

    // Extended-key flag for nav keys
    switch (vk) {
        case VK_INSERT: case VK_DELETE: case VK_HOME: case VK_END:
        case VK_PRIOR:  case VK_NEXT:
        case VK_LEFT:   case VK_RIGHT:  case VK_UP:   case VK_DOWN:
        case VK_NUMLOCK: case VK_SNAPSHOT: case VK_CANCEL:
            lp |= (1 << 24);
            break;
    }

    if (GetKeyNameTextA(lp, buf, sizeof(buf)) > 0)
        return buf;
    snprintf(buf, sizeof(buf), "0x%02X", vk);
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════════
// Admin check
// ═══════════════════════════════════════════════════════════════════════════
static bool IsRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

// ═══════════════════════════════════════════════════════════════════════════
// Hardware detection
// ═══════════════════════════════════════════════════════════════════════════
static void QueryCpuName()
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        DWORD sz = sizeof(g_cpuName);
        RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(g_cpuName), &sz);
        RegCloseKey(hKey);

        // trim leading spaces
        char* p = g_cpuName;
        while (*p == ' ') p++;
        if (p != g_cpuName) memmove(g_cpuName, p, strlen(p) + 1);
    }
}

static void QueryGpuName()
{
    if (!g_pd3dDevice) return;

    IDXGIDevice* dxgiDev = nullptr;
    g_pd3dDevice->QueryInterface(__uuidof(IDXGIDevice),
                                 reinterpret_cast<void**>(&dxgiDev));
    if (!dxgiDev) return;

    IDXGIAdapter* adapter = nullptr;
    dxgiDev->GetAdapter(&adapter);
    if (adapter) {
        DXGI_ADAPTER_DESC desc;
        adapter->GetDesc(&desc);
        WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1,
                            g_gpuName, sizeof(g_gpuName), nullptr, nullptr);
        adapter->Release();
    }
    dxgiDev->Release();
}

// ═══════════════════════════════════════════════════════════════════════════
// Process name and description from PID
// ═══════════════════════════════════════════════════════════════════════════
static void GetFileDescription(const char* filePath, char* outDesc, size_t maxLen)
{
    outDesc[0] = '\0';
    
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeA(filePath, &dummy);
    if (size == 0) return;
    
    std::vector<char> data(size);
    if (!GetFileVersionInfoA(filePath, 0, size, data.data())) return;
    
    // Try to get FileDescription
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;
    UINT cbTranslate = 0;
    
    if (!VerQueryValueA(data.data(), "\\VarFileInfo\\Translation",
                        reinterpret_cast<LPVOID*>(&lpTranslate), &cbTranslate))
        return;
    
    if (cbTranslate < sizeof(LANGANDCODEPAGE)) return;
    
    char subBlock[128];
    snprintf(subBlock, sizeof(subBlock),
             "\\StringFileInfo\\%04x%04x\\FileDescription",
             lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
    
    char* description = nullptr;
    UINT descLen = 0;
    if (VerQueryValueA(data.data(), subBlock,
                       reinterpret_cast<LPVOID*>(&description), &descLen)) {
        if (description && descLen > 0 && description[0] != '\0') {
            snprintf(outDesc, maxLen, "%s", description);
        }
    }
}

static void GetProcessName(DWORD pid, char* outName, size_t maxLen)
{
    outName[0] = '\0';
    if (pid == 0) return;
    
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (hProc) {
        char fullPath[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProc, 0, fullPath, &size)) {
            // Extract just the filename
            const char* exeName = strrchr(fullPath, '\\');
            if (exeName) exeName++; else exeName = fullPath;
            
            // Try to get file description
            char description[256] = {};
            GetFileDescription(fullPath, description, sizeof(description));
            
            if (description[0]) {
                snprintf(outName, maxLen, "%s (%s)", exeName, description);
            } else {
                snprintf(outName, maxLen, "%s", exeName);
            }
        }
        CloseHandle(hProc);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CPU Temperature via WMI (works on some systems)
// ═══════════════════════════════════════════════════════════════════════════
static IWbemLocator*   g_pWbemLocator  = nullptr;
static IWbemServices*  g_pWbemServices = nullptr;
static bool            g_wmiInitialized = false;

static bool InitWMI()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return false;
    
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE, nullptr);
    // Ignore if already initialized
    
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, reinterpret_cast<void**>(&g_pWbemLocator));
    if (FAILED(hr)) return false;
    
    // Try OpenHardwareMonitor WMI namespace first (most reliable)
    hr = g_pWbemLocator->ConnectServer(
        _bstr_t(L"ROOT\\OpenHardwareMonitor"), nullptr, nullptr, nullptr,
        0, nullptr, nullptr, &g_pWbemServices);
    
    if (FAILED(hr)) {
        // Try standard WMI namespace (works on some systems)
        hr = g_pWbemLocator->ConnectServer(
            _bstr_t(L"ROOT\\WMI"), nullptr, nullptr, nullptr,
            0, nullptr, nullptr, &g_pWbemServices);
    }
    
    if (FAILED(hr)) {
        g_pWbemLocator->Release();
        g_pWbemLocator = nullptr;
        return false;
    }
    
    hr = CoSetProxyBlanket(g_pWbemServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                           nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr, EOAC_NONE);
    
    g_wmiInitialized = true;
    return true;
}

static void ShutdownWMI()
{
    if (g_pWbemServices) { g_pWbemServices->Release(); g_pWbemServices = nullptr; }
    if (g_pWbemLocator)  { g_pWbemLocator->Release();  g_pWbemLocator  = nullptr; }
    g_wmiInitialized = false;
}

static float QueryCpuTemperature()
{
    if (!g_wmiInitialized || !g_pWbemServices) return 0.0f;
    
    IEnumWbemClassObject* pEnumerator = nullptr;
    HRESULT hr;
    
    // Try OpenHardwareMonitor sensor query
    hr = g_pWbemServices->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT Value FROM Sensor WHERE SensorType='Temperature' AND Name LIKE '%CPU%'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);
    
    if (FAILED(hr)) {
        // Try MSAcpi_ThermalZoneTemperature (built-in, but less reliable)
        hr = g_pWbemServices->ExecQuery(
            _bstr_t(L"WQL"),
            _bstr_t(L"SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr, &pEnumerator);
    }
    
    if (FAILED(hr)) return 0.0f;
    
    float temp = 0.0f;
    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    
    if (pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        
        // Try "Value" first (OpenHardwareMonitor)
        hr = pObj->Get(L"Value", 0, &vtProp, nullptr, nullptr);
        if (SUCCEEDED(hr) && vtProp.vt == VT_R4) {
            temp = vtProp.fltVal;
        } else {
            // Try "CurrentTemperature" (MSAcpi - returns in tenths of Kelvin)
            VariantClear(&vtProp);
            hr = pObj->Get(L"CurrentTemperature", 0, &vtProp, nullptr, nullptr);
            if (SUCCEEDED(hr) && (vtProp.vt == VT_I4 || vtProp.vt == VT_UI4)) {
                // Convert from tenths of Kelvin to Celsius
                temp = (vtProp.lVal / 10.0f) - 273.15f;
            }
        }
        VariantClear(&vtProp);
        pObj->Release();
    }
    
    pEnumerator->Release();
    return temp;
}

// ═══════════════════════════════════════════════════════════════════════════
// LibreHardwareMonitor (LHWM) — cross-vendor hardware monitoring
// ═══════════════════════════════════════════════════════════════════════════
// Helper to check if a hardware name is a GPU (excluding integrated graphics)
static bool IsDiscreteGpu(const std::string& name) {
    // Check for discrete GPU identifiers
    bool isGpu = (name.find("GeForce") != std::string::npos ||
                  name.find("RTX") != std::string::npos ||
                  name.find("GTX") != std::string::npos ||
                  name.find("Radeon RX") != std::string::npos ||
                  name.find("Radeon Pro") != std::string::npos ||
                  name.find("Arc") != std::string::npos ||  // Intel Arc
                  name.find("NVIDIA") != std::string::npos);
    
    // Exclude integrated graphics
    bool isIntegrated = (name.find("Radeon Graphics") != std::string::npos ||  // AMD APU
                         name.find("Intel UHD") != std::string::npos ||
                         name.find("Intel HD") != std::string::npos ||
                         name.find("Intel Iris") != std::string::npos);
    
    return isGpu && !isIntegrated;
}

// Find an existing GPU in the list by name, or return -1
static int FindGpuByName(const char* name) {
    for (int i = 0; i < g_gpuCount; i++) {
        if (strcmp(g_gpuList[i].name, name) == 0) return i;
    }
    return -1;
}

static bool InitLHWM()
{
    try {
        auto sensors = LHWM::GetHardwareSensorMap();
        if (sensors.empty()) return false;
        
        // Debug: write sensor list to file for troubleshooting
        FILE* dbg = nullptr;
        fopen_s(&dbg, "lhwm_sensors.txt", "w");
        if (dbg) {
            fprintf(dbg, "LHWM Sensors Found:\n");
            fprintf(dbg, "==================\n\n");
        }
        
        // The map structure from lhwm-cpp-wrapper is:
        // Key (map key) = Hardware name (e.g., "AMD Ryzen 9 5900HS...")
        // Value = vector<tuple<sensorName, sensorType, sensorPath>>
        //   tuple[0] = Sensor name (e.g., "CPU Core #1", "GPU Core")
        //   tuple[1] = Sensor type (e.g., "Temperature", "Load")
        //   tuple[2] = Sensor path (e.g., "/amdcpu/0/temperature/0")
        
        std::string cpuTempFallback;
        g_gpuCount = 0;  // Reset GPU count
        
        for (const auto& [hardwareName, sensorList] : sensors) {
            // Debug: log hardware name
            if (dbg) {
                fprintf(dbg, "Hardware: %s\n", hardwareName.c_str());
            }
            
            // Check if this is CPU or GPU hardware by hardware name
            bool isCpuHardware = (hardwareName.find("Ryzen") != std::string::npos ||
                                  hardwareName.find("Intel") != std::string::npos ||
                                  hardwareName.find("CPU") != std::string::npos ||
                                  hardwareName.find("Core") != std::string::npos);
            
            bool isDiscreteGpuHardware = IsDiscreteGpu(hardwareName);
            
            // If this is a discrete GPU, find or create entry in GPU list
            int gpuIndex = -1;
            if (isDiscreteGpuHardware && g_gpuCount < MAX_GPUS) {
                gpuIndex = FindGpuByName(hardwareName.c_str());
                if (gpuIndex < 0) {
                    // New GPU - add to list
                    gpuIndex = g_gpuCount;
                    snprintf(g_gpuList[gpuIndex].name, sizeof(g_gpuList[gpuIndex].name), "%s", hardwareName.c_str());
                    g_gpuList[gpuIndex].tempPath.clear();
                    g_gpuList[gpuIndex].loadPath.clear();
                    g_gpuList[gpuIndex].vramUsedPath.clear();
                    g_gpuList[gpuIndex].vramTotalPath.clear();
                    g_gpuCount++;
                }
            }
            
            // Iterate through all sensors for this hardware
            for (const auto& sensorInfo : sensorList) {
                const auto& [sensorName, sensorType, sensorPath] = sensorInfo;
                
                // Debug output
                if (dbg) {
                    fprintf(dbg, "  Sensor: %s\n", sensorName.c_str());
                    fprintf(dbg, "    Type: %s\n", sensorType.c_str());
                    fprintf(dbg, "    Path: %s\n", sensorPath.c_str());
                }
                
                // Also detect by path pattern
                bool isCpuPath = (sensorPath.find("/amdcpu/") != std::string::npos ||
                                  sensorPath.find("/intelcpu/") != std::string::npos);
                bool isGpuPath = (sensorPath.find("/gpu-nvidia/") != std::string::npos ||
                                  sensorPath.find("/gpu-amd/") != std::string::npos ||
                                  sensorPath.find("/gpu-intel/") != std::string::npos);
                
                // CPU temperature sensors
                if ((isCpuHardware || isCpuPath) && sensorType == "Temperature") {
                    // Prefer Package, Tctl/Tdie, or Core temps
                    if (sensorName.find("Package") != std::string::npos ||
                        sensorName.find("Tctl") != std::string::npos ||
                        sensorName.find("Tdie") != std::string::npos ||
                        sensorName.find("Core (Tctl/Tdie)") != std::string::npos) {
                        g_lhwmCpuTempPath = sensorPath;
                    } else if (g_lhwmCpuTempPath.empty()) {
                        cpuTempFallback = sensorPath;
                    }
                }
                
                // GPU sensors - store in the GPU's entry
                if (gpuIndex >= 0) {
                    if (sensorType == "Temperature") {
                        if (sensorName.find("Core") != std::string::npos || 
                            sensorName.find("GPU") != std::string::npos ||
                            g_gpuList[gpuIndex].tempPath.empty()) {
                            g_gpuList[gpuIndex].tempPath = sensorPath;
                        }
                    }
                    else if (sensorType == "Load") {
                        if (sensorName.find("Core") != std::string::npos || 
                            sensorName.find("GPU") != std::string::npos ||
                            g_gpuList[gpuIndex].loadPath.empty()) {
                            g_gpuList[gpuIndex].loadPath = sensorPath;
                        }
                    }
                    else if (sensorType == "SmallData" || sensorType == "Data") {
                        if (sensorName.find("Memory Used") != std::string::npos ||
                            sensorName.find("GPU Memory Used") != std::string::npos) {
                            g_gpuList[gpuIndex].vramUsedPath = sensorPath;
                        }
                        else if (sensorName.find("Memory Total") != std::string::npos ||
                                 sensorName.find("GPU Memory Total") != std::string::npos) {
                            g_gpuList[gpuIndex].vramTotalPath = sensorPath;
                        }
                    }
                }
            }
            
            if (dbg) fprintf(dbg, "\n");
        }
        
        // Use fallback CPU temp if needed
        if (g_lhwmCpuTempPath.empty() && !cpuTempFallback.empty()) {
            g_lhwmCpuTempPath = cpuTempFallback;
        }
        
        // Clamp selected GPU to valid range
        if (g_Config.selectedGpu >= g_gpuCount) {
            g_Config.selectedGpu = 0;
        }
        
        // Set active GPU paths and name
        if (g_gpuCount > 0) {
            int idx = g_Config.selectedGpu;
            g_lhwmGpuTempPath = g_gpuList[idx].tempPath;
            g_lhwmGpuLoadPath = g_gpuList[idx].loadPath;
            g_lhwmGpuVramUsedPath = g_gpuList[idx].vramUsedPath;
            g_lhwmGpuVramTotalPath = g_gpuList[idx].vramTotalPath;
            snprintf(g_gpuName, sizeof(g_gpuName), "%s", g_gpuList[idx].name);
        }
        
        if (dbg) {
            fprintf(dbg, "==================\n");
            fprintf(dbg, "GPUs Found: %d\n", g_gpuCount);
            for (int i = 0; i < g_gpuCount; i++) {
                fprintf(dbg, "  [%d] %s\n", i, g_gpuList[i].name);
                fprintf(dbg, "      Temp: %s\n", g_gpuList[i].tempPath.empty() ? "(none)" : g_gpuList[i].tempPath.c_str());
                fprintf(dbg, "      Load: %s\n", g_gpuList[i].loadPath.empty() ? "(none)" : g_gpuList[i].loadPath.c_str());
            }
            fprintf(dbg, "\nSelected Sensors:\n");
            fprintf(dbg, "  CPU Temp: %s\n", g_lhwmCpuTempPath.empty() ? "(none)" : g_lhwmCpuTempPath.c_str());
            fprintf(dbg, "  GPU Temp: %s\n", g_lhwmGpuTempPath.empty() ? "(none)" : g_lhwmGpuTempPath.c_str());
            fprintf(dbg, "  GPU Load: %s\n", g_lhwmGpuLoadPath.empty() ? "(none)" : g_lhwmGpuLoadPath.c_str());
            fclose(dbg);
        }
        
        return !g_lhwmCpuTempPath.empty() || g_gpuCount > 0;
    }
    catch (...) {
        return false;
    }
}

static void PollLHWMStats()
{
    if (!g_lhwmAvailable) return;
    
    try {
        // CPU temperature
        if (!g_lhwmCpuTempPath.empty()) {
            g_lhwmCpuTemp = LHWM::GetSensorValue(g_lhwmCpuTempPath);
        }
        
        // GPU stats - update both LHWM-specific and unified variables
        if (!g_lhwmGpuTempPath.empty()) {
            g_lhwmGpuTemp = LHWM::GetSensorValue(g_lhwmGpuTempPath);
            g_gpuTemp = g_lhwmGpuTemp;
        }
        if (!g_lhwmGpuLoadPath.empty()) {
            g_lhwmGpuLoad = LHWM::GetSensorValue(g_lhwmGpuLoadPath);
            g_gpuUsage = g_lhwmGpuLoad;
        }
        if (!g_lhwmGpuVramUsedPath.empty()) {
            // Value is in MB, convert to GB
            g_lhwmGpuVramUsed = LHWM::GetSensorValue(g_lhwmGpuVramUsedPath) / 1024.0f;
            g_vramUsed = g_lhwmGpuVramUsed;
        }
        if (!g_lhwmGpuVramTotalPath.empty()) {
            g_lhwmGpuVramTotal = LHWM::GetSensorValue(g_lhwmGpuVramTotalPath) / 1024.0f;
            g_vramTotal = g_lhwmGpuVramTotal;
        }
    }
    catch (...) {
        // Silently ignore polling errors
    }
}

// Switch to a different GPU by index
static void SelectGpu(int index)
{
    if (index < 0 || index >= g_gpuCount) return;
    
    g_Config.selectedGpu = index;
    
    // Update active sensor paths
    g_lhwmGpuTempPath = g_gpuList[index].tempPath;
    g_lhwmGpuLoadPath = g_gpuList[index].loadPath;
    g_lhwmGpuVramUsedPath = g_gpuList[index].vramUsedPath;
    g_lhwmGpuVramTotalPath = g_gpuList[index].vramTotalPath;
    
    snprintf(g_gpuName, sizeof(g_gpuName), "%s", g_gpuList[index].name);
}

// ═══════════════════════════════════════════════════════════════════════════
// ETW — game FPS capture (hooks DXGI Present events system-wide)
// ═══════════════════════════════════════════════════════════════════════════
static void WINAPI EtwCallback(PEVENT_RECORD pEvent)
{
    if (!g_etwRunning.load(std::memory_order_relaxed)) return;

    // Only DXGI Present::Start (Event ID 42)
    if (memcmp(&pEvent->EventHeader.ProviderId, &DXGI_PROVIDER, sizeof(GUID)) != 0) return;
    if (pEvent->EventHeader.EventDescriptor.Id != 42) return;

    DWORD pid = pEvent->EventHeader.ProcessId;
    DWORD target = g_targetPid.load(std::memory_order_relaxed);
    if (target == 0 || pid != target) return;

    double ts = (double)pEvent->EventHeader.TimeStamp.QuadPart / g_qpcFreq;

    // Simple 1-second accumulator (all on the ETW thread — no lock needed)
    static DWORD s_lastPid   = 0;
    static int   s_count     = 0;
    static double s_startTs  = 0;

    if (pid != s_lastPid) { s_lastPid = pid; s_count = 0; s_startTs = ts; return; }

    s_count++;
    double elapsed = ts - s_startTs;
    if (elapsed >= 1.0) {
        g_gameFps.store((float)s_count / (float)elapsed, std::memory_order_relaxed);
        s_count  = 0;
        s_startTs = ts;
    }
}

static bool StartEtwSession()
{
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_qpcFreq = (double)freq.QuadPart;

    // Buffer for properties + session name
    struct { EVENT_TRACE_PROPERTIES p; char name[256]; } buf;

    // Stop any leftover session from a previous crash
    ZeroMemory(&buf, sizeof(buf));
    buf.p.Wnode.BufferSize   = sizeof(buf);
    buf.p.LoggerNameOffset   = offsetof(decltype(buf), name);
    ControlTraceA(0, ETW_SESSION_NAME, &buf.p, EVENT_TRACE_CONTROL_STOP);

    // Prepare fresh properties
    ZeroMemory(&buf, sizeof(buf));
    buf.p.Wnode.BufferSize    = sizeof(buf);
    buf.p.Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    buf.p.Wnode.ClientContext = 1;                        // QPC timestamps
    buf.p.LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    buf.p.LoggerNameOffset    = offsetof(decltype(buf), name);

    ULONG rc = StartTraceA(&g_etwSession, ETW_SESSION_NAME, &buf.p);
    if (rc != ERROR_SUCCESS) return false;

    rc = EnableTraceEx2(g_etwSession, &DXGI_PROVIDER,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
    if (rc != ERROR_SUCCESS) {
        ZeroMemory(&buf, sizeof(buf));
        buf.p.Wnode.BufferSize = sizeof(buf);
        buf.p.LoggerNameOffset = offsetof(decltype(buf), name);
        ControlTraceA(g_etwSession, nullptr, &buf.p, EVENT_TRACE_CONTROL_STOP);
        g_etwSession = 0;
        return false;
    }

    EVENT_TRACE_LOGFILEA logFile = {};
    logFile.LoggerName          = const_cast<LPSTR>(ETW_SESSION_NAME);
    logFile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwCallback;

    g_etwTrace = OpenTraceA(&logFile);
    if (g_etwTrace == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        ZeroMemory(&buf, sizeof(buf));
        buf.p.Wnode.BufferSize = sizeof(buf);
        buf.p.LoggerNameOffset = offsetof(decltype(buf), name);
        ControlTraceA(g_etwSession, nullptr, &buf.p, EVENT_TRACE_CONTROL_STOP);
        g_etwSession = 0;
        return false;
    }

    g_etwRunning.store(true);
    g_etwThread = std::thread([]() {
        TRACEHANDLE h = g_etwTrace;
        ProcessTrace(&h, 1, nullptr, nullptr);
    });

    return true;
}

static void StopEtwSession()
{
    if (!g_etwRunning.load()) return;
    g_etwRunning.store(false);

    if (g_etwTrace != 0 && g_etwTrace != (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        CloseTrace(g_etwTrace);
        g_etwTrace = 0;
    }
    if (g_etwThread.joinable())
        g_etwThread.join();

    struct { EVENT_TRACE_PROPERTIES p; char name[256]; } buf;
    ZeroMemory(&buf, sizeof(buf));
    buf.p.Wnode.BufferSize = sizeof(buf);
    buf.p.LoggerNameOffset = offsetof(decltype(buf), name);
    ControlTraceA(g_etwSession, ETW_SESSION_NAME, &buf.p, EVENT_TRACE_CONTROL_STOP);
    g_etwSession = 0;

    g_gameFps.store(0.0f);
}

// ═══════════════════════════════════════════════════════════════════════════
// CPU usage
// ═══════════════════════════════════════════════════════════════════════════
static float GetCpuUsage()
{
    static ULARGE_INTEGER sI = {}, sK = {}, sU = {};
    FILETIME fi, fk, fu;
    if (!GetSystemTimes(&fi, &fk, &fu)) return 0;

    ULARGE_INTEGER i,k,u;
    i.LowPart = fi.dwLowDateTime; i.HighPart = fi.dwHighDateTime;
    k.LowPart = fk.dwLowDateTime; k.HighPart = fk.dwHighDateTime;
    u.LowPart = fu.dwLowDateTime; u.HighPart = fu.dwHighDateTime;

    ULONGLONG di = i.QuadPart - sI.QuadPart;
    ULONGLONG dk = k.QuadPart - sK.QuadPart;
    ULONGLONG du = u.QuadPart - sU.QuadPart;
    sI = i; sK = k; sU = u;

    ULONGLONG total = dk + du;
    return total ? (1.0f - (float)di / (float)total) * 100.0f : 0.0f;
}

// ═══════════════════════════════════════════════════════════════════════════
// Tray icon
// ═══════════════════════════════════════════════════════════════════════════
void AddTrayIcon()
{
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = g_hwnd;
    g_nid.uID              = 1;
    g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    // Load embedded icon (resource ID 1), fallback to default if not found
    g_nid.hIcon            = LoadIcon(g_hInstance, MAKEINTRESOURCE(1));
    if (!g_nid.hIcon)
        g_nid.hIcon        = LoadIcon(nullptr, IDI_APPLICATION);
    lstrcpy(g_nid.szTip, "FPS Overlay");
    Shell_NotifyIcon(NIM_ADD, &g_nid);
}

void RemoveTrayIcon() { Shell_NotifyIcon(NIM_DELETE, &g_nid); }

// ═══════════════════════════════════════════════════════════════════════════
// ImGui style
// ═══════════════════════════════════════════════════════════════════════════
void ApplyStyle()
{
    ImGui::StyleColorsDark();
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 10; s.FrameRounding = 6; s.GrabRounding = 6;
    s.WindowBorderSize = 1; s.FrameBorderSize = 0;
    s.WindowPadding = ImVec2(14, 10);
    s.FramePadding  = ImVec2(8, 5);
    s.ItemSpacing   = ImVec2(10, 8);

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]         = ImVec4(0.08f,0.08f,0.10f,1);
    c[ImGuiCol_Border]           = ImVec4(0.25f,0.27f,0.32f,0.6f);
    c[ImGuiCol_FrameBg]          = ImVec4(0.14f,0.14f,0.17f,1);
    c[ImGuiCol_FrameBgHovered]   = ImVec4(0.20f,0.20f,0.24f,1);
    c[ImGuiCol_FrameBgActive]    = ImVec4(0.26f,0.26f,0.30f,1);
    c[ImGuiCol_CheckMark]        = ImVec4(0.30f,0.75f,1.00f,1);
    c[ImGuiCol_SliderGrab]       = ImVec4(0.30f,0.75f,1.00f,1);
    c[ImGuiCol_SliderGrabActive] = ImVec4(0.45f,0.85f,1.00f,1);
    c[ImGuiCol_Button]           = ImVec4(0.16f,0.16f,0.20f,1);
    c[ImGuiCol_ButtonHovered]    = ImVec4(0.22f,0.22f,0.28f,1);
    c[ImGuiCol_ButtonActive]     = ImVec4(0.28f,0.28f,0.34f,1);
    c[ImGuiCol_Separator]        = ImVec4(0.22f,0.24f,0.28f,1);
}

// ═══════════════════════════════════════════════════════════════════════════
// DX11
// ═══════════════════════════════════════════════════════════════════════════
bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL got;
    if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            levels, 2, D3D11_SDK_VERSION, &sd,
            &g_pSwapChain, &g_pd3dDevice, &got, &g_pd3dDeviceContext)))
        return false;
    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release();        g_pSwapChain        = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)        { g_pd3dDevice->Release();        g_pd3dDevice        = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* buf = nullptr;
    g_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&buf));
    if (buf) { g_pd3dDevice->CreateRenderTargetView(buf, nullptr, &g_pRenderTargetView); buf->Release(); }
}

void CleanupRenderTarget()
{
    if (g_pRenderTargetView) { g_pRenderTargetView->Release(); g_pRenderTargetView = nullptr; }
}

// ═══════════════════════════════════════════════════════════════════════════
// Backend / mode helpers
// ═══════════════════════════════════════════════════════════════════════════
void ShutdownBackends()
{
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    CleanupDeviceD3D();
}

void InitBackends()
{
    CreateDeviceD3D(g_hwnd);
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
}

// Toggle click-through mode on the overlay window
static void SetClickThrough(bool enable)
{
    LONG_PTR style = GetWindowLongPtr(g_hwnd, GWL_EXSTYLE);
    if (enable)
        style |= WS_EX_TRANSPARENT;
    else
        style &= ~WS_EX_TRANSPARENT;
    SetWindowLongPtr(g_hwnd, GWL_EXSTYLE, style);
}

void SwitchToOverlay()
{
    ShutdownBackends();
    DestroyWindow(g_hwnd);

    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    
    // Always start click-through - we toggle it when CTRL is held
    DWORD exStyle = WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE;
    
    g_hwnd = CreateWindowEx(
        exStyle,
        "FPSOverlay", "FPS Overlay", WS_POPUP,
        0, 0, w, h, nullptr, nullptr, g_hInstance, nullptr);

    SetLayeredWindowAttributes(g_hwnd, RGB(0,0,0), 255, LWA_ALPHA);
    MARGINS m = { -1 }; DwmExtendFrameIntoClientArea(g_hwnd, &m);

    InitBackends();
    ShowWindow(g_hwnd, SW_SHOWNOACTIVATE);
    AddTrayIcon();

    // Start ETW for real game FPS
    g_etwAvailable = StartEtwSession();

    g_Mode       = MODE_OVERLAY;
    g_OvlVisible = true;
}

void SwitchToConfig()
{
    StopEtwSession();
    RemoveTrayIcon();
    ShutdownBackends();
    DestroyWindow(g_hwnd);

    int cw = 420, ch = 680;
    int cx = (GetSystemMetrics(SM_CXSCREEN) - cw) / 2;
    int cy = (GetSystemMetrics(SM_CYSCREEN) - ch) / 2;
    g_hwnd = CreateWindowEx(0, "FPSOverlay", "FPS Overlay",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        cx, cy, cw, ch, nullptr, nullptr, g_hInstance, nullptr);

    InitBackends();
    ShowWindow(g_hwnd, SW_SHOW);
    g_Mode = MODE_CONFIG;
}

// ═══════════════════════════════════════════════════════════════════════════
// Rendering helpers
// ═══════════════════════════════════════════════════════════════════════════
static void Present(float r, float g, float b, float a)
{
    ImGui::Render();
    const float c[4] = { r, g, b, a };
    g_pd3dDeviceContext->OMSetRenderTargets(1, &g_pRenderTargetView, nullptr);
    g_pd3dDeviceContext->ClearRenderTargetView(g_pRenderTargetView, c);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_pSwapChain->Present(1, 0);
}

static ImVec4 ColorByLoad(float v, float warn = 70, float crit = 90)
{
    if (v > crit) return ImVec4(1,.3f,.3f,1);
    if (v > warn) return ImVec4(1,.85f,.15f,1);
    return ImVec4(.70f,.70f,.75f,1);
}

// ═══════════════════════════════════════════════════════════════════════════
// WinMain
// ═══════════════════════════════════════════════════════════════════════════
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int)
{
    g_hInstance = hInst;

    // ── Load saved configuration ──
    LoadConfig(g_Config);

    // ── Query hardware ──
    QueryCpuName();

    // ── Register window class with icon ──
    HICON hIcon = LoadIcon(hInst, MAKEINTRESOURCE(1));
    if (!hIcon) hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(wc); wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc; wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = hIcon;
    wc.hIconSm = hIcon;
    wc.lpszClassName = "FPSOverlay";
    RegisterClassEx(&wc);

    // ── Config window ──
    int cw = 420, ch = 680;
    int cx = (GetSystemMetrics(SM_CXSCREEN) - cw) / 2;
    int cy = (GetSystemMetrics(SM_CYSCREEN) - ch) / 2;
    g_hwnd = CreateWindowEx(0, wc.lpszClassName, "FPS Overlay",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        cx, cy, cw, ch, nullptr, nullptr, hInst, nullptr);
    if (!g_hwnd) return 1;

    // ── Check admin privileges (app should always run as admin via manifest) ──
    g_isAdmin = IsRunningAsAdmin();

    if (!CreateDeviceD3D(g_hwnd)) {
        MessageBox(g_hwnd, "DirectX 11 initialisation failed.", "FPS Overlay", MB_OK | MB_ICONERROR);
        CleanupDeviceD3D(); return 1;
    }

    // Get GPU name from DXGI adapter (fallback if LHWM doesn't provide it)
    QueryGpuName();

    // Initialize LibreHardwareMonitor for GPU and CPU temperature monitoring
    // Supports NVIDIA, AMD, and Intel GPUs
    g_lhwmAvailable = InitLHWM();
    
    // Try WMI for CPU temperature as fallback
    g_cpuTempAvailable = InitWMI();
    if (g_cpuTempAvailable) {
        // Test if we can actually get a temperature reading
        float testTemp = QueryCpuTemperature();
        g_cpuTempAvailable = (testTemp > 0.0f && testTemp < 150.0f);
    }
    
    // LHWM provides CPU temp, so mark as available if we have it
    if (g_lhwmAvailable && !g_lhwmCpuTempPath.empty()) {
        g_cpuTempAvailable = true;
    }

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    // ── ImGui context (lives for the whole app) ──
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr; io.LogFilename = nullptr;

    ImFont* font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 17.0f);
    if (!font) { io.Fonts->Clear(); ImFontConfig fc; fc.SizePixels = 16; io.Fonts->AddFontDefault(&fc); }

    ApplyStyle();
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // ── Timing ──
    using Clock = std::chrono::high_resolution_clock;
    auto lastCpuTime = Clock::now();
    auto lastGpuTime = lastCpuTime;
    float cpuUsage = 0;
    GetCpuUsage(); // seed

    // ── Main loop ──
    MSG msg = {};
    while (g_Running)
    {
        if (g_Pending == CMD_START_OVERLAY) { g_Pending = CMD_NONE; SwitchToOverlay(); }
        if (g_Pending == CMD_SHOW_SETTINGS) { g_Pending = CMD_NONE; SwitchToConfig();  }
        if (g_Pending == CMD_EXIT)          { g_Running = false; break; }

        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg); DispatchMessage(&msg);
            if (msg.message == WM_QUIT) g_Running = false;
        }
        if (!g_Running) break;

        // ══════════════════════════════════════════════════════════════
        // CONFIG MODE
        // ══════════════════════════════════════════════════════════════
        if (g_Mode == MODE_CONFIG)
        {
            // ── Hotkey listener (runs even during config rendering) ──
            if (g_listeningFor != 0) {
                // Check if ESC was pressed to cancel
                if (GetAsyncKeyState(VK_ESCAPE) & 1) {
                    g_listeningFor = 0;
                } else {
                    for (int vk = 1; vk < 256; vk++) {
                        // Skip mouse buttons and modifier-only keys we don't want
                        if (vk == VK_LBUTTON || vk == VK_RBUTTON || vk == VK_MBUTTON) continue;
                        if (vk == VK_ESCAPE) continue;  // handled above
                        if (vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL) continue;
                        if (vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT) continue;
                        if (vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU) continue;  // Alt keys
                        
                        if (GetAsyncKeyState(vk) & 1) {
                            if (g_listeningFor == 1) g_Config.toggleKey = vk;
                            if (g_listeningFor == 2) g_Config.exitKey   = vk;
                            g_listeningFor = 0;
                            break;
                        }
                    }
                }
            }

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::Begin("##cfg", nullptr,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoSavedSettings);

            // ── Title ──
            ImGui::SetWindowFontScale(1.4f);
            ImGui::TextColored(ImVec4(.35f,.78f,1,1), "FPS Overlay");
            ImGui::SetWindowFontScale(1.0f);
            ImGui::SameLine(); ImGui::TextColored(ImVec4(.45f,.45f,.5f,1), " Beta v1.1.0");

            // Developer text
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(.45f,.45f,.5f,1), " Developed by aneeskhan47");

            ImGui::Spacing(); ImGui::Separator();

            // ── DISPLAY ──
            ImGui::Spacing(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "DISPLAY");
            ImGui::Spacing();
            ImGui::Checkbox("  FPS Counter (game)", &g_Config.showFPS);
            if (!g_isAdmin) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(.9f,.4f,.2f,1), "(needs admin!)");
            }
            ImGui::Checkbox("  CPU Usage", &g_Config.showCPU);
            ImGui::Checkbox("  GPU Usage & Temp", &g_Config.showGPU);
            if (!g_lhwmAvailable || g_gpuCount == 0) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(.9f,.4f,.2f,1), "(unavailable)");
            }
            ImGui::Checkbox("  GPU VRAM Usage", &g_Config.showVRAM);
            if (!g_lhwmAvailable || g_gpuCount == 0) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(.9f,.4f,.2f,1), "(unavailable)");
            }
            ImGui::Checkbox("  RAM Usage", &g_Config.showRAM);

            // ── GPU SELECTION ──
            if (g_gpuCount > 0) {
                ImGui::Spacing(); ImGui::Spacing();
                ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "GPU SELECTION");
                ImGui::Spacing();
                
                // Build combo preview string
                const char* previewName = (g_Config.selectedGpu >= 0 && g_Config.selectedGpu < g_gpuCount) 
                    ? g_gpuList[g_Config.selectedGpu].name 
                    : "Select GPU...";
                
                ImGui::SetNextItemWidth(-1);
                if (ImGui::BeginCombo("##gpuselect", previewName)) {
                    for (int i = 0; i < g_gpuCount; i++) {
                        bool isSelected = (g_Config.selectedGpu == i);
                        if (ImGui::Selectable(g_gpuList[i].name, isSelected)) {
                            SelectGpu(i);
                        }
                        if (isSelected) {
                            ImGui::SetItemDefaultFocus();
                        }
                    }
                    ImGui::EndCombo();
                }
                
                if (g_gpuCount > 1) {
                    ImGui::TextColored(ImVec4(.45f,.45f,.50f,1), "Multiple GPUs detected - select which to monitor");
                }
            }

            // ── POSITION ──
            ImGui::Spacing(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "POSITION");
            ImGui::Spacing();
            int prevPos = g_Config.position;
            ImGui::RadioButton("Top Left",     &g_Config.position, 0); ImGui::SameLine(0,24);
            ImGui::RadioButton("Top Right",    &g_Config.position, 1);
            ImGui::RadioButton("Bottom Left",  &g_Config.position, 2); ImGui::SameLine(0,24);
            ImGui::RadioButton("Bottom Right", &g_Config.position, 3);
            // Reset custom position when corner preset is changed
            if (g_Config.position != prevPos) {
                g_Config.customX = -1.0f;
                g_Config.customY = -1.0f;
            }
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(.45f,.45f,.50f,1), "Hold CTRL to drag or right-click overlay");

            // ── LAYOUT ──
            ImGui::Spacing(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "LAYOUT");
            ImGui::Spacing();
            ImGui::Checkbox("  Horizontal Compact View", &g_Config.horizontal);
            
            // ── TEMPERATURE UNIT ──
            ImGui::Spacing(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "TEMPERATURE");
            ImGui::Spacing();
            int tempUnit = g_Config.useFahrenheit ? 1 : 0;
            if (ImGui::RadioButton("Celsius", &tempUnit, 0)) g_Config.useFahrenheit = false;
            ImGui::SameLine(0,24);
            if (ImGui::RadioButton("Fahrenheit", &tempUnit, 1)) g_Config.useFahrenheit = true;

            // ── OPACITY ──
            ImGui::Spacing(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "OPACITY");
            ImGui::Spacing();
            ImGui::SetNextItemWidth(-1);
            ImGui::SliderInt("##opac", &g_Config.opacity, 30, 100, "%d%%");

            // ── HOTKEYS ──
            ImGui::Spacing(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "HOTKEYS");
            ImGui::Spacing();

            // Toggle key
            ImGui::Text("Toggle:");
            ImGui::SameLine(90);
            if (g_listeningFor == 1) {
                ImGui::TextColored(ImVec4(1,.8f,.2f,1), "Press any key...  ");
                ImGui::SameLine();
                if (ImGui::SmallButton("Cancel##1")) g_listeningFor = 0;
            } else {
                ImGui::Text("%-12s", GetKeyName(g_Config.toggleKey));
                ImGui::SameLine();
                if (ImGui::SmallButton("Change##1")) g_listeningFor = 1;
            }

            // Exit key
            ImGui::Text("Exit:");
            ImGui::SameLine(90);
            if (g_listeningFor == 2) {
                ImGui::TextColored(ImVec4(1,.8f,.2f,1), "Press any key...  ");
                ImGui::SameLine();
                if (ImGui::SmallButton("Cancel##2")) g_listeningFor = 0;
            } else {
                ImGui::Text("%-12s", GetKeyName(g_Config.exitKey));
                ImGui::SameLine();
                if (ImGui::SmallButton("Change##2")) g_listeningFor = 2;
            }

            // ── HARDWARE ──
            ImGui::Spacing(); ImGui::Spacing();
            ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "DETECTED HARDWARE");
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "CPU:  %s", g_cpuName);
            ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "GPU:  %s", g_gpuName);

            // ── START BUTTON ──
            ImGui::Spacing(); ImGui::Spacing(); ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(.12f,.56f,.37f,1));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,  ImVec4(.16f,.68f,.44f,1));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,   ImVec4(.10f,.48f,.32f,1));
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8);
            if (ImGui::Button("Start Overlay", ImVec2(ImGui::GetContentRegionAvail().x, 42)))
                g_Pending = CMD_START_OVERLAY;
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(3);

            ImGui::End();
            Present(0.08f, 0.08f, 0.10f, 1);
        }

        // ══════════════════════════════════════════════════════════════
        // OVERLAY MODE
        // ══════════════════════════════════════════════════════════════
        else
        {
            // ── Hotkeys (user-configurable) ──
            if (GetAsyncKeyState(g_Config.toggleKey) & 1)
                g_OvlVisible = !g_OvlVisible;
            if (GetAsyncKeyState(g_Config.exitKey) & 1)
                { g_Running = false; break; }

            // ── Show/Hide window based on visibility flag ──
            static bool wasVisible = true;
            if (g_OvlVisible != wasVisible) {
                ShowWindow(g_hwnd, g_OvlVisible ? SW_SHOWNA : SW_HIDE);
                wasVisible = g_OvlVisible;
            }

            if (!g_OvlVisible) { Sleep(50); continue; }

            // ── Update target PID (foreground window's process) ──
            HWND fg = GetForegroundWindow();
            DWORD currentPid = 0;
            if (fg && fg != g_hwnd) {
                GetWindowThreadProcessId(fg, &currentPid);
                g_targetPid.store(currentPid, std::memory_order_relaxed);
            }
            
            // ── Reset FPS when target app changes or closes ──
            if (currentPid != g_lastTargetPid) {
                g_gameFps.store(0.0f, std::memory_order_relaxed);
                g_lastTargetPid = currentPid;
                // Update process name
                GetProcessName(currentPid, g_targetProcessName, sizeof(g_targetProcessName));
            }
            // Also check if the process is still alive
            if (g_lastTargetPid != 0) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_lastTargetPid);
                if (hProc) {
                    DWORD exitCode = 0;
                    if (GetExitCodeProcess(hProc, &exitCode) && exitCode != STILL_ACTIVE) {
                        g_gameFps.store(0.0f, std::memory_order_relaxed);
                        g_lastTargetPid = 0;
                    }
                    CloseHandle(hProc);
                } else {
                    // Process no longer exists
                    g_gameFps.store(0.0f, std::memory_order_relaxed);
                    g_lastTargetPid = 0;
                }
            }

            // ── Periodic metrics (once/sec) ──
            auto now = Clock::now();

            float cpuElapsed = std::chrono::duration<float>(now - lastCpuTime).count();
            if (cpuElapsed >= 1.0f) {
                cpuUsage = GetCpuUsage();
                // Poll CPU temp - prefer LHWM over WMI
                if (g_lhwmAvailable && !g_lhwmCpuTempPath.empty()) {
                    g_cpuTemp = g_lhwmCpuTemp;
                } else if (g_cpuTempAvailable) {
                    g_cpuTemp = QueryCpuTemperature();
                }
                lastCpuTime = now;
            }

            float gpuElapsed = std::chrono::duration<float>(now - lastGpuTime).count();
            if (gpuElapsed >= 1.0f) {
                // Poll LHWM first (covers AMD, Intel, NVIDIA)
                if (g_lhwmAvailable) {
                    PollLHWMStats();
                }
                lastGpuTime = now;
            }

            // ── RAM ──
            MEMORYSTATUSEX mem = {}; mem.dwLength = sizeof(mem);
            GlobalMemoryStatusEx(&mem);
            float ramUsed  = (float)(mem.ullTotalPhys - mem.ullAvailPhys) / (1024.f*1024.f*1024.f);
            float ramTotal = (float)(mem.ullTotalPhys)                    / (1024.f*1024.f*1024.f);

            // ── Game FPS (from ETW) ──
            float gameFps = g_gameFps.load(std::memory_order_relaxed);

            // ── Handle CTRL key for dragging / right-click menu ──
            // When CTRL is held, disable click-through so user can drag or right-click
            static bool wasCtrlHeld = false;
            bool ctrlHeld = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
            if (ctrlHeld != wasCtrlHeld) {
                SetClickThrough(!ctrlHeld);
                wasCtrlHeld = ctrlHeld;
            }
            
            // Right-click context menu (when CTRL is held)
            if (ctrlHeld && (GetAsyncKeyState(VK_RBUTTON) & 1)) {
                POINT pt; GetCursorPos(&pt);
                HMENU m = CreatePopupMenu();
                AppendMenu(m, MF_STRING, IDM_HIDE, "Hide Overlay");
                AppendMenu(m, MF_SEPARATOR, 0, nullptr);
                AppendMenu(m, MF_STRING, IDM_SETTINGS, "Settings");
                AppendMenu(m, MF_STRING, IDM_EXIT, "Exit");
                SetForegroundWindow(g_hwnd);
                int cmd = TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                                         pt.x, pt.y, 0, g_hwnd, nullptr);
                DestroyMenu(m);
                switch (cmd) {
                    case IDM_HIDE:     g_OvlVisible = false;           break;
                    case IDM_SETTINGS: g_Pending = CMD_SHOW_SETTINGS;  break;
                    case IDM_EXIT:     g_Pending = CMD_EXIT;           break;
                }
            }

            // ── ImGui frame ──
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            // Position: use custom if set, otherwise use corner preset
            float margin = 16;
            int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
            ImVec2 pos, pivot = {0, 0};
            bool hasCustomPos = (g_Config.customX >= 0 && g_Config.customY >= 0);
            
            if (hasCustomPos) {
                // User has dragged the overlay - use their position
                pos = ImVec2(g_Config.customX, g_Config.customY);
            } else {
                // Use corner preset
                switch (g_Config.position) {
                    default:
                    case 0: pos={margin,margin};        pivot={0,0}; break;
                    case 1: pos={sw-margin,margin};     pivot={1,0}; break;
                    case 2: pos={margin,sh-margin};     pivot={0,1}; break;
                    case 3: pos={sw-margin,sh-margin};  pivot={1,1}; break;
                }
            }
            
            // Only force position on first frame or if using corner preset and haven't dragged
            ImGui::SetNextWindowPos(pos, hasCustomPos ? ImGuiCond_Once : ImGuiCond_Always, pivot);
            
            // Full opacity when CTRL held, otherwise user setting
            ImGui::SetNextWindowBgAlpha(ctrlHeld ? 1.0f : (g_Config.opacity / 100.f));

            // Window flags - allow dragging when CTRL is held
            ImGuiWindowFlags wf =
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar |
                ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav;
            
            if (!ctrlHeld) {
                wf |= ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoInputs;
            }

            ImGui::Begin("##ovl", nullptr, wf);
            
            // Save position when dragged
            if (ctrlHeld) {
                ImVec2 winPos = ImGui::GetWindowPos();
                g_Config.customX = winPos.x;
                g_Config.customY = winPos.y;
            }
            
            // ── Draw glowing border when CTRL is held ──
            if (ctrlHeld) {
                ImDrawList* dl = ImGui::GetWindowDrawList();
                ImVec2 wMin = ImGui::GetWindowPos();
                ImVec2 wMax = ImVec2(wMin.x + ImGui::GetWindowSize().x, wMin.y + ImGui::GetWindowSize().y);
                
                // Animated glow effect (pulsing)
                float t = (float)fmod(ImGui::GetTime() * 2.0, 3.14159 * 2.0);
                float glow = 0.6f + 0.4f * sinf(t);
                
                // Draw multiple borders for glow effect (outer to inner)
                ImU32 glowColor1 = IM_COL32(80, 180, 255, (int)(40 * glow));
                ImU32 glowColor2 = IM_COL32(80, 180, 255, (int)(80 * glow));
                ImU32 glowColor3 = IM_COL32(100, 200, 255, (int)(160 * glow));
                ImU32 coreColor  = IM_COL32(120, 220, 255, (int)(255 * glow));
                
                dl->AddRect(ImVec2(wMin.x - 4, wMin.y - 4), ImVec2(wMax.x + 4, wMax.y + 4), glowColor1, 8.0f, 0, 3.0f);
                dl->AddRect(ImVec2(wMin.x - 2, wMin.y - 2), ImVec2(wMax.x + 2, wMax.y + 2), glowColor2, 6.0f, 0, 2.0f);
                dl->AddRect(ImVec2(wMin.x - 1, wMin.y - 1), ImVec2(wMax.x + 1, wMax.y + 1), glowColor3, 4.0f, 0, 1.5f);
                dl->AddRect(wMin, wMax, coreColor, 4.0f, 0, 1.0f);
            }

            // ═══════════════════════════════════════════════════════════
            // HORIZONTAL COMPACT VIEW
            // ═══════════════════════════════════════════════════════════
            if (g_Config.horizontal) {
                bool needSep = false;
                
                // FPS
                if (g_Config.showFPS) {
                    if (g_etwAvailable && gameFps > 0) {
                        ImVec4 col = gameFps >= 60 ? ImVec4(.18f,.94f,.45f,1)
                                   : gameFps >= 30 ? ImVec4(1,.85f,.15f,1)
                                                   : ImVec4(1,.25f,.25f,1);
                        ImGui::TextColored(col, "FPS %.0f", gameFps);
                    } else {
                        ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "FPS ---");
                    }
                    needSep = true;
                }
                
                // CPU
                if (g_Config.showCPU) {
                    if (needSep) { ImGui::SameLine(); ImGui::TextColored(ImVec4(.35f,.35f,.40f,1), " | "); ImGui::SameLine(); }
                    ImGui::TextColored(ColorByLoad(cpuUsage), "CPU %.0f%%", cpuUsage);
                    if (g_cpuTempAvailable && g_cpuTemp > 0) {
                        ImGui::SameLine(0, 2);
                        float dispTemp = ToDisplayTemp(g_cpuTemp, g_Config.useFahrenheit);
                        ImVec4 tc = g_cpuTemp > 85 ? ImVec4(1,.3f,.3f,1)
                                  : g_cpuTemp > 70 ? ImVec4(1,.85f,.15f,1)
                                                   : ImVec4(.70f,.70f,.75f,1);
                        ImGui::TextColored(tc, " %.0f\xC2\xB0%s", dispTemp, g_Config.useFahrenheit ? "F" : "C");
                    }
                    needSep = true;
                }
                
                // GPU stats via LHWM
                if (g_Config.showGPU) {
                    if (needSep) { ImGui::SameLine(); ImGui::TextColored(ImVec4(.35f,.35f,.40f,1), " | "); ImGui::SameLine(); }
                    
                    float dispGpuLoad = g_gpuUsage;
                    float dispGpuTemp = g_gpuTemp;
                    bool hasGpuData = g_lhwmAvailable && g_gpuCount > 0;
                    
                    if (hasGpuData) {
                        ImGui::TextColored(ColorByLoad(dispGpuLoad), "GPU %.0f%%", dispGpuLoad);
                        if (dispGpuTemp > 0) {
                            ImGui::SameLine(0, 2);
                            float dispTemp = ToDisplayTemp(dispGpuTemp, g_Config.useFahrenheit);
                            ImVec4 tc = dispGpuTemp > 85 ? ImVec4(1,.3f,.3f,1)
                                      : dispGpuTemp > 70 ? ImVec4(1,.85f,.15f,1)
                                                         : ImVec4(.70f,.70f,.75f,1);
                            ImGui::TextColored(tc, " %.0f\xC2\xB0%s", dispTemp, g_Config.useFahrenheit ? "F" : "C");
                        }
                    } else {
                        ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "GPU N/A");
                    }
                    needSep = true;
                }
                
                // VRAM
                if (g_Config.showVRAM) {
                    float dispVramUsed = g_vramUsed;
                    float dispVramTotal = g_vramTotal;
                    if (dispVramTotal > 0) {
                        if (needSep) { ImGui::SameLine(); ImGui::TextColored(ImVec4(.35f,.35f,.40f,1), " | "); ImGui::SameLine(); }
                        float vramPct = (dispVramUsed / dispVramTotal) * 100.0f;
                        ImGui::TextColored(ColorByLoad(vramPct), "VRAM %.0f%% %.1f/%.0fG", vramPct, dispVramUsed, dispVramTotal);
                        needSep = true;
                    }
                }
                
                // RAM
                if (g_Config.showRAM) {
                    if (needSep) { ImGui::SameLine(); ImGui::TextColored(ImVec4(.35f,.35f,.40f,1), " | "); ImGui::SameLine(); }
                    float pct = (ramUsed / ramTotal) * 100;
                    ImGui::TextColored(ColorByLoad(pct), "RAM %.0f%% %.1f/%.0fG", pct, ramUsed, ramTotal);
                }
                
                // Process name on second line (compact)
                if (g_Config.showFPS && g_targetProcessName[0]) {
                    ImGui::SetWindowFontScale(0.78f);
                    ImGui::TextColored(ImVec4(.42f,.52f,.42f,1), "%s", g_targetProcessName);
                    ImGui::SetWindowFontScale(1.0f);
                }
            }
            // ═══════════════════════════════════════════════════════════
            // VERTICAL VIEW (default)
            // ═══════════════════════════════════════════════════════════
            else {
                bool needSep = false;

                // FPS
                if (g_Config.showFPS) {
                    if (g_etwAvailable && gameFps > 0) {
                        ImVec4 col = gameFps >= 60 ? ImVec4(.18f,.94f,.45f,1)
                                   : gameFps >= 30 ? ImVec4(1,.85f,.15f,1)
                                                   : ImVec4(1,.25f,.25f,1);
                        ImGui::TextColored(col, "FPS  %.0f", gameFps);
                    } else {
                        ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "FPS  ---");
                    }
                    // Show tracked process name
                    if (g_targetProcessName[0]) {
                        ImGui::SetWindowFontScale(0.82f);
                        ImGui::TextColored(ImVec4(.42f,.55f,.42f,1), "  %s", g_targetProcessName);
                        ImGui::SetWindowFontScale(1.0f);
                    } else {
                        ImGui::SetWindowFontScale(0.82f);
                        ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "  (no process)");
                        ImGui::SetWindowFontScale(1.0f);
                    }
                    needSep = true;
                }

                // CPU
                if (g_Config.showCPU) {
                    if (needSep) { ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing(); }
                    ImGui::TextColored(ColorByLoad(cpuUsage), "CPU  %.0f%%", cpuUsage);
                    // Show CPU temp if available
                    if (g_cpuTempAvailable && g_cpuTemp > 0) {
                        ImGui::SameLine();
                        float dispTemp = ToDisplayTemp(g_cpuTemp, g_Config.useFahrenheit);
                        ImVec4 tc = g_cpuTemp > 85 ? ImVec4(1,.3f,.3f,1)
                                  : g_cpuTemp > 70 ? ImVec4(1,.85f,.15f,1)
                                                   : ImVec4(.70f,.70f,.75f,1);
                        ImGui::TextColored(tc, " %.0f\xC2\xB0%s", dispTemp, g_Config.useFahrenheit ? "F" : "C");
                    }
                    ImGui::SetWindowFontScale(0.82f);
                    ImGui::TextColored(ImVec4(.42f,.42f,.48f,1), "  %s", g_cpuName);
                    ImGui::SetWindowFontScale(1.0f);
                    needSep = true;
                }

                // GPU stats via LHWM
                if (g_Config.showGPU) {
                    if (needSep) { ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing(); }
                    
                    float dispGpuLoad = g_gpuUsage;
                    float dispGpuTemp = g_gpuTemp;
                    float dispVramUsed = g_vramUsed;
                    float dispVramTotal = g_vramTotal;
                    bool hasGpuData = g_lhwmAvailable && g_gpuCount > 0;
                    
                    if (hasGpuData) {
                        ImGui::TextColored(ColorByLoad(dispGpuLoad), "GPU  %.0f%%", dispGpuLoad);
                        if (dispGpuTemp > 0) {
                            ImGui::SameLine();
                            float dispTemp = ToDisplayTemp(dispGpuTemp, g_Config.useFahrenheit);
                            ImVec4 tc = dispGpuTemp > 85 ? ImVec4(1,.3f,.3f,1)
                                      : dispGpuTemp > 70 ? ImVec4(1,.85f,.15f,1)
                                                         : ImVec4(.70f,.70f,.75f,1);
                            ImGui::TextColored(tc, " %.0f\xC2\xB0%s", dispTemp, g_Config.useFahrenheit ? "F" : "C");
                        }
                        // VRAM usage
                        if (g_Config.showVRAM && dispVramTotal > 0) {
                            float vramPct = (dispVramUsed / dispVramTotal) * 100.0f;
                            ImGui::TextColored(ColorByLoad(vramPct), "VRAM %.0f%%", vramPct);
                            ImGui::SameLine();
                            ImGui::TextColored(ImVec4(.70f,.70f,.75f,1), " %.1f / %.0f GB", dispVramUsed, dispVramTotal);
                        }
                    } else {
                        ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "GPU  N/A");
                    }
                    ImGui::SetWindowFontScale(0.82f);
                    ImGui::TextColored(ImVec4(.42f,.42f,.48f,1), "  %s", g_gpuName);
                    ImGui::SetWindowFontScale(1.0f);
                    needSep = true;
                }

                // RAM
                if (g_Config.showRAM) {
                    if (needSep) { ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing(); }
                    float pct = (ramUsed / ramTotal) * 100;
                    ImGui::TextColored(ColorByLoad(pct), "RAM  %.0f%%", pct);
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(.70f,.70f,.75f,1), " %.1f / %.1f GB", ramUsed, ramTotal);
                }
            }
            
            // ── Show helper text when CTRL is held ──
            if (ctrlHeld) {
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::SetWindowFontScale(0.85f);
                ImGui::TextColored(ImVec4(0.5f, 0.75f, 1.0f, 1.0f), "Drag to move | Right-click for menu");
                ImGui::SetWindowFontScale(1.0f);
            }

            ImGui::End();
            Present(0, 0, 0, 0);
        }
    }

    // ═══ Cleanup ═══
    SaveConfig(g_Config);  // Save settings before exit
    StopEtwSession();
    if (g_Mode == MODE_OVERLAY) RemoveTrayIcon();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(g_hwnd);
    UnregisterClass("FPSOverlay", g_hInstance);
    ShutdownWMI();

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// Window procedure
// ═══════════════════════════════════════════════════════════════════════════
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_CLOSE:
        if (g_Mode == MODE_CONFIG) g_Running = false;
        return 0;
    case WM_DESTROY:
        return 0;
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam),
                                        DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_TRAYICON:
        if (LOWORD(lParam) == WM_RBUTTONUP) {
            POINT pt; GetCursorPos(&pt);
            HMENU m = CreatePopupMenu();
            // Show/Hide toggle based on current visibility
            if (g_OvlVisible)
                AppendMenu(m, MF_STRING, IDM_HIDE, "Hide Overlay");
            else
                AppendMenu(m, MF_STRING, IDM_SHOW, "Show Overlay");
            AppendMenu(m, MF_SEPARATOR, 0, nullptr);
            AppendMenu(m, MF_STRING, IDM_SETTINGS, "Settings");
            AppendMenu(m, MF_SEPARATOR, 0, nullptr);
            AppendMenu(m, MF_STRING, IDM_EXIT, "Exit");
            SetForegroundWindow(hWnd);
            int cmd = TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                                     pt.x, pt.y, 0, hWnd, nullptr);
            DestroyMenu(m);
            // Handle the command directly
            switch (cmd) {
                case IDM_SHOW:     g_OvlVisible = true;            break;
                case IDM_HIDE:     g_OvlVisible = false;           break;
                case IDM_SETTINGS: g_Pending = CMD_SHOW_SETTINGS;  break;
                case IDM_EXIT:     g_Pending = CMD_EXIT;           break;
            }
        }
        return 0;
    case WM_CONTEXTMENU:
        // Right-click on overlay window itself
        if (g_Mode == MODE_OVERLAY) {
            POINT pt; GetCursorPos(&pt);
            HMENU m = CreatePopupMenu();
            AppendMenu(m, MF_STRING, IDM_HIDE, "Hide Overlay");
            AppendMenu(m, MF_SEPARATOR, 0, nullptr);
            AppendMenu(m, MF_STRING, IDM_SETTINGS, "Settings");
            AppendMenu(m, MF_STRING, IDM_EXIT, "Exit");
            SetForegroundWindow(hWnd);
            int cmd = TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                                     pt.x, pt.y, 0, hWnd, nullptr);
            DestroyMenu(m);
            switch (cmd) {
                case IDM_HIDE:     g_OvlVisible = false;           break;
                case IDM_SETTINGS: g_Pending = CMD_SHOW_SETTINGS;  break;
                case IDM_EXIT:     g_Pending = CMD_EXIT;           break;
            }
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
            case IDM_SHOW:     g_OvlVisible = true;            break;
            case IDM_HIDE:     g_OvlVisible = false;           break;
            case IDM_SETTINGS: g_Pending = CMD_SHOW_SETTINGS;  break;
            case IDM_EXIT:     g_Pending = CMD_EXIT;           break;
        }
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
