# FPS Overlay - Lightweight Game Performance Monitor

A lightweight, no-bloat FPS overlay for Windows. Just stats on your screen while gaming — nothing else.

![Size](https://img.shields.io/badge/size-~4MB-brightgreen) ![Platform](https://img.shields.io/badge/platform-Windows-blue) ![License](https://img.shields.io/badge/license-GNU%20GPLv3-green) ![Status](https://img.shields.io/badge/status-beta-orange)

> **⚠️ Beta Software:** This project is currently in beta and under active development. Features, UI, and behavior are subject to change. Feedback and bug reports are welcome!

## Features

- **FPS** — Real game framerate via Windows ETW (same method the pros use)
- **GPU** — Usage & temperature (NVIDIA via NVML, with fallback for others)
- **CPU** — Usage & temperature
- **RAM** — Usage percentage and used/total GB
- **Process tracking** — Shows which game/app is being monitored
- **Horizontal or vertical layout** — Your choice
- **Fully click-through** — Never interferes with your game
- **Custom hotkeys** — Bind toggle/exit to whatever you want
- **System tray integration** — Stays out of your way
- **Hold CTRL to drag** — Position it exactly where you want with visual feedback
- **4MB single .exe** — No installer, no background services, no bloat

## Screenshot

<img width="1918" height="1198" alt="2026-02-08_16-22" src="https://github.com/user-attachments/assets/b6d3ef8b-1ccb-439b-8c66-37f80f6c2b0e" />


<!-- Add your screenshot here -->
<!-- ![FPS Overlay Screenshot](screenshot.png) -->

## Why I Built This

I wanted a simple FPS overlay. That's it. Just FPS, CPU, GPU, RAM stats on my screen while gaming. Somehow this turned into a mass-uninstall session when I realized every existing solution came with baggage:

### What I tried and why I gave up:

| Tool | Why I Ditched It |
|------|------------------|
| **Xbox Game Bar** | Uninstalled it ages ago for performance reasons, now Windows won't let me reinstall it. Classic. |
| **NVIDIA GeForce Experience / Shadowplay / NVIDIA App** | I just want an FPS counter, not a 500MB "gaming platform" that wants to optimize my games, record everything, and run 3 background services. |
| **MSI Afterburner** | Powerful, yes. But I don't need overclocking tools, fan curves, voltage controls, and hardware monitoring graphs. I just want to see my FPS. |
| **NZXT CAM** | Came with my AIO, immediately became system tray bloatware that phones home and wants to "enhance my gaming experience." |
| **Steam Overlay** | Would be fine if more than 5% of my library was on Steam. |
| **Overwolf** | Still not sure what this actually does besides slow everything down and show ads. |
| **RivaTuner** | The OG, respect. But it's 2026 and I still don't need 90% of what it offers. |
| **Fraps** | Last updated in 2013. Enough said. |

### So I built my own:

- **4MB total** — Single .exe, no installer, no background services
- **C++ with DirectX 11 + Dear ImGui** — As lightweight as it gets
- **No account required. No telemetry. No "gaming optimization" features. No social integration. No ads. Just stats.**

## Download

Grab the latest release from the [Releases](../../releases) page.

Or build it yourself (see below).

## Usage

1. **Run as Administrator** (required for game FPS tracking)
2. Select which stats you want to display
3. Choose your position, layout, and hotkeys
4. Click **Start Overlay**
5. Game on!

### Controls

| Action | How |
|--------|-----|
| Move overlay | Hold **CTRL** + drag |
| Right-click menu | Hold **CTRL** + right-click |
| Toggle visibility | Your configured hotkey (default: **Insert**) |
| Exit | Your configured hotkey (default: **End**) |

### Without Admin

The overlay works without admin too — you just won't get game FPS, only system stats (CPU, GPU, RAM).

## Why ETW? Why Admin?

There are basically 3 ways to get real game FPS:

| Method | How it works | Downsides |
|--------|--------------|-----------|
| **DLL Injection** (RivaTuner/Afterburner) | Hooks directly into the game's graphics calls | Can trigger anti-cheat bans or crash games |
| **Vendor Hooks** (NVIDIA/AMD overlays) | Built into their drivers | Comes with hundreds of MB of bloatware and background services |
| **ETW** (Windows Event Tracing) | Kernel-level Windows API that fires events when any process presents a frame | Requires admin privileges |

I went with **ETW** because:

- **Anti-cheat safe** — Doesn't touch game processes at all
- **Universal** — Works with any DX10/11/12 game
- **No injection** — Nothing gets loaded into the game

The tradeoff is that ETW requires admin because it's a system-wide kernel tracing API. Windows won't let unprivileged apps listen to cross-process events for security reasons. Same reason PresentMon and CapFrameX need admin — it's a Windows security requirement, not a design choice.

### DirectX Compatibility

| DirectX Version | Supported |
|-----------------|-----------|
| DirectX 12 | ✅ Yes |
| DirectX 11 | ✅ Yes |
| DirectX 10/10.1 | ✅ Yes |
| DirectX 9 | ❌ No (predates DXGI) |
| OpenGL / Vulkan | ❌ No |

## Building from Source

### Requirements

- Windows 10/11
- MinGW-w64 (g++ with C++20 support)
- Make (mingw32-make)

### Build

```bash
git clone https://github.com/aneeskhan47/fps-overlay.git
cd fps-overlay
mingw32-make
```

The output is `overlay.exe` in the project root.

### Dependencies (included)

- [Dear ImGui](https://github.com/ocornut/imgui) — Immediate mode GUI
- DirectX 11 SDK (Windows SDK)
- NVML headers (for NVIDIA GPU stats)

## Project Structure

```
fps-overlay/
├── src/
│   ├── main.cpp        # All application code
│   └── resource.rc     # Windows resources (icon, version info)
├── libs/
│   └── imgui/          # Dear ImGui library
├── icon.ico            # Application icon
├── Makefile            # Build configuration
└── README.md
```

## Tech Stack

- **Language:** C++20
- **Graphics:** DirectX 11
- **UI:** Dear ImGui
- **FPS Tracking:** Windows ETW (Event Tracing for Windows)
- **GPU Stats:** NVML (NVIDIA Management Library)
- **CPU Temp:** WMI (Windows Management Instrumentation)
- **Windowing:** Win32 API (layered transparent window)

## License

GNU General Public License v3.0 - see [LICENSE.txt](LICENSE.txt) for details.

## Contributing

Found a bug? Want to add AMD GPU support? PRs welcome.

---

*No bloat. No telemetry. Just stats.*
