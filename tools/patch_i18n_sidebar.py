# -*- coding: utf-8 -*-
"""Patch main.cpp for i18n, opacity, and sidebar settings."""
from pathlib import Path
import re

path = Path("src/main.cpp")
text = path.read_text(encoding="utf-8")

# --- Font reload in main loop ---
needle = """        if (!g_Running) break;

        static bool s_appliedLhwmCpuTempLift = false;"""
insert = """        if (!g_Running) break;

        if (g_fontsNeedReload) {
            ImGui_ImplDX11_InvalidateDeviceObjects();
            LoadAppFonts();
            ImGui_ImplDX11_CreateDeviceObjects();
            g_fontsNeedReload = false;
        }

        static bool s_appliedLhwmCpuTempLift = false;"""
if needle in text and "g_fontsNeedReload" not in text[text.find(needle):text.find(needle)+400]:
    text = text.replace(needle, insert, 1)

# --- Steam transparent bg ---
old_steam = """            if (g_Config.layoutStyle == LAYOUT_STEAM) {
                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f * ovSc, 6.f * ovSc));
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4.f * ovSc, 2.f * ovSc));
                ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
                ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
                ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.f, 0.f, 0.f, 1.f));
                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.22f, 0.22f, 0.24f, 0.f));
            }"""
new_steam = """            if (g_Config.layoutStyle == LAYOUT_STEAM) {
                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.f * ovSc, 6.f * ovSc));
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4.f * ovSc, 2.f * ovSc));
                ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
                ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
                const float steamBgA = g_Config.transparentBackground && !ctrlHeld ? 0.f : 1.f;
                ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.f, 0.f, 0.f, steamBgA));
                ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.22f, 0.22f, 0.24f, 0.f));
            }"""
text = text.replace(old_steam, new_steam, 1)

# --- Header button labels via T() ---
text = text.replace(
    'const float githubW = CalcHeaderLinkButtonWidth("View on GitHub", kHdrBtnIconSz, kHdrBtnPadX, kHdrBtnGapIcon);\n'
    '    const float kofiW   = CalcHeaderLinkButtonWidth("Buy me a coffee", kHdrBtnIconSz, kHdrBtnPadX, kHdrBtnGapIcon);',
    'const float githubW = CalcHeaderLinkButtonWidth(locale::T("View on GitHub"), kHdrBtnIconSz, kHdrBtnPadX, kHdrBtnGapIcon);\n'
    '    const float kofiW   = CalcHeaderLinkButtonWidth(locale::T("Buy me a coffee"), kHdrBtnIconSz, kHdrBtnPadX, kHdrBtnGapIcon);',
    1)

text = text.replace(
    'DrawHeaderLinkButton("github", (ImTextureID)g_texGitHub, kHdrBtnIconSz,\n'
    '                         "View on GitHub", "https://github.com/aneeskhan47/fps-overlay", btnW);\n'
    '    ImGui::SetCursorPos(ImVec2(x, y + btnH + kHdrBtnStackGap));\n'
    '    DrawHeaderLinkButton("kofi", (ImTextureID)g_texKofi, kHdrBtnIconSz,\n'
    '                         "Buy me a coffee", "https://ko-fi.com/aneeskhan47", btnW);',
    'DrawHeaderLinkButton("github", (ImTextureID)g_texGitHub, kHdrBtnIconSz,\n'
    '                         locale::T("View on GitHub"), "https://github.com/aneeskhan47/fps-overlay", btnW);\n'
    '    ImGui::SetCursorPos(ImVec2(x, y + btnH + kHdrBtnStackGap));\n'
    '    DrawHeaderLinkButton("kofi", (ImTextureID)g_texKofi, kHdrBtnIconSz,\n'
    '                         locale::T("Buy me a coffee"), "https://ko-fi.com/aneeskhan47", btnW);',
    1)

text = text.replace(
    'ImGui::TextColored(ImVec4(.45f,.45f,.5f,1), "Developed by aneeskhan47 & ");\n'
    '    ImGui::SameLine(0, 0);\n'
    '    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(.55f,.75f,1.f,1));\n'
    '    ImGui::Text("contributors");',
    'ImGui::TextColored(ImVec4(.45f,.45f,.5f,1), "%s", locale::T("Developed by aneeskhan47 & "));\n'
    '    ImGui::SameLine(0, 0);\n'
    '    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(.55f,.75f,1.f,1));\n'
    '    ImGui::TextUnformatted(locale::T("contributors"));',
    1)

# --- Tray tooltip ---
old_tray = '''void UpdateTrayTooltip()
{
    if (g_updateAvailable) {
        snprintf(g_nid.szTip, sizeof(g_nid.szTip), "FPS Overlay - Update available! (%s)", g_latestVersion);
    } else {
        lstrcpy(g_nid.szTip, "FPS Overlay");
    }
    Shell_NotifyIcon(NIM_MODIFY, &g_nid);
}'''
new_tray = '''void UpdateTrayTooltip()
{
    if (g_updateAvailable) {
        snprintf(g_nid.szTip, sizeof(g_nid.szTip), "%s",
                 locale::TF("FPS Overlay - Update available! (%s)", g_latestVersion));
    } else {
        lstrcpy(g_nid.szTip, locale::T("FPS Overlay"));
    }
    Shell_NotifyIcon(NIM_MODIFY, &g_nid);
}'''
text = text.replace(old_tray, new_tray, 1)

# AddTrayIcon tip
text = text.replace('lstrcpy(g_nid.szTip, "FPS Overlay");',
                    'lstrcpy(g_nid.szTip, locale::T("FPS Overlay"));', 1)

# --- Replace settings body with sidebar ---
SETTINGS = r'''
            // ── Title ──
            const float headerY = ImGui::GetCursorPosY();
            ImGui::SetWindowFontScale(1.4f);
            ImGui::TextColored(ImVec4(.35f,.78f,1,1), "%s", locale::T("FPS Overlay"));
            ImGui::SetWindowFontScale(1.0f);
            ImGui::SameLine(); ImGui::TextColored(ImVec4(.45f,.45f,.5f,1), " %s", APP_VERSION);

            const float titleRowBottom = ImGui::GetCursorPosY();
            const float headerButtonsW = CalcHeaderLinkButtonsWidth();
            const float headerButtonsH = CalcHeaderLinkButtonsHeight();
            const float headerButtonsX = ImGui::GetWindowContentRegionMax().x - headerButtonsW;
            DrawHeaderExternalLinkButtonsAt(headerButtonsX, headerY);

            const float headerButtonsBottom = headerY + headerButtonsH;
            float headerNextY = (titleRowBottom > headerButtonsBottom ? titleRowBottom : headerButtonsBottom) + 4.f;

            if (g_updateAvailable) {
                ImGui::SetCursorPosY(headerNextY);
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(.2f,.9f,.4f,1));
                if (ImGui::SmallButton(locale::T("Update available!"))) {
                    ShellExecuteA(nullptr, "open",
                        "https://github.com/aneeskhan47/fps-overlay/releases/latest",
                        nullptr, nullptr, SW_SHOWNORMAL);
                }
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered())
                    TooltipWrappedFmt("%s", locale::TF("Click to download %s", g_latestVersion));
                headerNextY = ImGui::GetItemRectMax().y + 4.f;
            }

            ImGui::SetCursorPosY(headerNextY);
            DrawDeveloperAttributionLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ImGui::GetStyle().ItemSpacing.y);

            ImGui::Separator();

            const float footerH = 56.f;
            const float bodyH = ImGui::GetContentRegionAvail().y - footerH;
            const float sideW = kSettingsSidebarW;
            const bool rtl = locale::IsRtl();

            auto drawSidebar = [&]() {
                ImGui::BeginChild("##settings_nav", ImVec2(sideW, bodyH), true);
                const char* tabs[] = {
                    "Display", "GPU", "Frequency", "Appearance", "Temperature",
                    "Hotkeys", "Startup", "Language", "About"
                };
                for (int i = 0; i < SETTINGS_TAB_COUNT; ++i) {
                    bool sel = (g_Config.settingsTab == i);
                    if (ImGui::Selectable(locale::T(tabs[i]), sel))
                        g_Config.settingsTab = i;
                }
                ImGui::EndChild();
            };

            auto drawPage = [&]() {
                ImGui::BeginChild("##settings_page", ImVec2(0, bodyH), true);

                if (g_Config.settingsTab == SETTINGS_TAB_DISPLAY) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("DISPLAY"));
                    ImGui::Spacing();
                    ImGui::Checkbox(locale::T("  FPS Counter (game)"), &g_Config.showFPS);
                    if (!g_isAdmin) {
                        ImGui::SameLine();
                        ImGui::TextColored(ImVec4(.9f,.4f,.2f,1), "%s", locale::T("(needs admin!)"));
                    }
                    ImGui::Checkbox(locale::T("  CPU Usage"), &g_Config.showCpuUsage);
                    ImGui::Checkbox(locale::T("  CPU Temp"), &g_Config.showCpuTemp);
                    ImGui::Checkbox(locale::T("  CPU Power (W)"), &g_Config.showCpuPower);
                    {
                        const bool lhwmBusy = !g_lhwmInitFinished.load(std::memory_order_acquire);
                        const bool lhwmBad = !g_lhwmAvailable || g_lhwmCpuPowerPath.empty();
                        if (lhwmBusy || lhwmBad) {
                            ImGui::SameLine();
                            ImGui::TextColored(lhwmBusy ? ImVec4(.55f,.55f,.58f,1) : ImVec4(.9f,.4f,.2f,1),
                                               "%s", locale::T(lhwmBusy ? "(loading…)" : "(unavailable)"));
                        }
                    }
                    ImGui::Checkbox(locale::T("  CPU Fan (RPM)"), &g_Config.showCpuFan);
                    {
                        const bool lhwmBusy = !g_lhwmInitFinished.load(std::memory_order_acquire);
                        const bool lhwmBad = !g_lhwmAvailable || g_lhwmCpuFanPath.empty();
                        if (lhwmBusy || lhwmBad) {
                            ImGui::SameLine();
                            ImGui::TextColored(lhwmBusy ? ImVec4(.55f,.55f,.58f,1) : ImVec4(.9f,.4f,.2f,1),
                                               "%s", locale::T(lhwmBusy ? "(loading…)" : "(unavailable)"));
                        }
                    }
                    ImGui::Checkbox(locale::T("  GPU Usage"), &g_Config.showGpuUsage);
                    ImGui::Checkbox(locale::T("  GPU Temp"), &g_Config.showGpuTemp);
                    {
                        const bool lhwmBusy = !g_lhwmInitFinished.load(std::memory_order_acquire);
                        const bool lhwmBad = !g_lhwmAvailable || g_gpuCount == 0;
                        if (lhwmBusy || lhwmBad) {
                            ImGui::SameLine();
                            ImGui::TextColored(lhwmBusy ? ImVec4(.55f,.55f,.58f,1) : ImVec4(.9f,.4f,.2f,1),
                                               "%s", locale::T(lhwmBusy ? "(loading…)" : "(unavailable)"));
                        }
                    }
                    ImGui::Checkbox(locale::T("  GPU Power (W)"), &g_Config.showGpuPower);
                    {
                        const bool lhwmBusy = !g_lhwmInitFinished.load(std::memory_order_acquire);
                        const bool lhwmBad = !g_lhwmAvailable || g_gpuCount == 0 || g_lhwmGpuPowerPath.empty();
                        if (lhwmBusy || lhwmBad) {
                            ImGui::SameLine();
                            ImGui::TextColored(lhwmBusy ? ImVec4(.55f,.55f,.58f,1) : ImVec4(.9f,.4f,.2f,1),
                                               "%s", locale::T(lhwmBusy ? "(loading…)" : "(unavailable)"));
                        }
                    }
                    ImGui::Checkbox(locale::T("  GPU Fan (RPM)"), &g_Config.showGpuFan);
                    {
                        const bool lhwmBusy = !g_lhwmInitFinished.load(std::memory_order_acquire);
                        const bool lhwmBad = !g_lhwmAvailable || g_gpuCount == 0 || g_lhwmGpuFanPath.empty();
                        if (lhwmBusy || lhwmBad) {
                            ImGui::SameLine();
                            ImGui::TextColored(lhwmBusy ? ImVec4(.55f,.55f,.58f,1) : ImVec4(.9f,.4f,.2f,1),
                                               "%s", locale::T(lhwmBusy ? "(loading…)" : "(unavailable)"));
                        }
                    }
                    ImGui::Checkbox(locale::T("  GPU VRAM Usage"), &g_Config.showVRAM);
                    if (!g_lhwmInitFinished.load(std::memory_order_acquire)) {
                        ImGui::SameLine();
                        ImGui::TextColored(ImVec4(.55f,.55f,.58f,1), "%s", locale::T("(loading…)"));
                    } else if (!g_lhwmAvailable || g_gpuCount == 0) {
                        ImGui::SameLine();
                        ImGui::TextColored(ImVec4(.9f,.4f,.2f,1), "%s", locale::T("(unavailable)"));
                    }
                    ImGui::Checkbox(locale::T("  RAM Usage"), &g_Config.showRAM);
                    ImGui::Checkbox(locale::T("  Show process name"), &g_Config.showProcessName);
                    if (ImGui::IsItemHovered())
                        TooltipWrapped(locale::T("Tracked game / process label on the overlay (all layouts)."));
                    ImGui::Checkbox(locale::T("  Show Time"), &g_Config.showTime);
                    if (ImGui::IsItemHovered())
                        TooltipWrapped(locale::T("Current local time on the overlay (all layouts)."));
                    if (g_Config.showTime) {
                        ImGui::Indent(16.f);
                        const char* timeFormats[] = { locale::T("24 Hour"), locale::T("12 Hour (AM/PM)") };
                        ImGui::SetNextItemWidth(-1);
                        ImGui::Combo("##timefmt", &g_Config.timeFormat, timeFormats, 2);
                        ImGui::TextUnformatted(locale::T("  Time Format"));
                        ImGui::Checkbox(locale::T("  Show Seconds"), &g_Config.timeShowSeconds);
                        ImGui::Unindent(16.f);
                    }
                }
                else if (g_Config.settingsTab == SETTINGS_TAB_GPU) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("GPU SELECTION"));
                    ImGui::Spacing();
                    if (g_gpuCount > 0) {
                        const char* previewName = (g_Config.selectedGpu >= 0 && g_Config.selectedGpu < g_gpuCount)
                            ? g_gpuList[g_Config.selectedGpu].name
                            : locale::T("Select GPU...");
                        ImGui::SetNextItemWidth(-1);
                        if (ImGui::BeginCombo("##gpuselect", previewName)) {
                            for (int i = 0; i < g_gpuCount; i++) {
                                bool isSelected = (g_Config.selectedGpu == i);
                                if (ImGui::Selectable(g_gpuList[i].name, isSelected))
                                    SelectGpu(i);
                                if (isSelected) ImGui::SetItemDefaultFocus();
                            }
                            ImGui::EndCombo();
                        }
                        if (g_gpuCount > 1)
                            ImGui::TextColored(ImVec4(.45f,.45f,.50f,1), "%s",
                                locale::T("Multiple GPUs detected - select which to monitor"));
                    } else {
                        ImGui::TextColored(ImVec4(.55f,.55f,.58f,1), "%s",
                            locale::T(!g_lhwmInitFinished.load(std::memory_order_acquire)
                                ? "(loading…)" : "(unavailable)"));
                    }
                }
                else if (g_Config.settingsTab == SETTINGS_TAB_FREQUENCY) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("FREQUENCY"));
                    ImGui::Spacing();
                    if (!g_lhwmInitFinished.load(std::memory_order_acquire)) {
                        ImGui::TextColored(ImVec4(.55f,.55f,.58f,1), "%s", locale::T("Initializing LibreHardwareMonitor…"));
                    } else if (!g_lhwmAvailable) {
                        ImGui::TextColored(ImVec4(.55f,.55f,.58f,1), "%s", locale::T("Requires LibreHardwareMonitor."));
                    } else {
                        ImGui::Checkbox(locale::T("  Show CPU frequency"), &g_Config.showCpuFreq);
                        if (g_Config.showCpuFreq) {
                            ImGui::Indent();
                            const char* cpuPrev = locale::T("(select sensor)");
                            for (const auto& o : g_cpuClockOpts) {
                                if (strcmp(g_Config.cpuFreqPath, o.second.c_str()) == 0) {
                                    cpuPrev = o.first.c_str();
                                    break;
                                }
                            }
                            ImGui::SetNextItemWidth(-1);
                            if (ImGui::BeginCombo("##cpuclkcombo", cpuPrev)) {
                                for (const auto& o : g_cpuClockOpts) {
                                    bool isSel = (strcmp(g_Config.cpuFreqPath, o.second.c_str()) == 0);
                                    if (ImGui::Selectable(o.first.c_str(), isSel))
                                        snprintf(g_Config.cpuFreqPath, sizeof(g_Config.cpuFreqPath), "%s", o.second.c_str());
                                    if (isSel) ImGui::SetItemDefaultFocus();
                                }
                                ImGui::EndCombo();
                            }
                            if (g_cpuClockOpts.empty())
                                ImGui::TextColored(ImVec4(.85f,.45f,.35f,1), "%s",
                                    locale::T("  No CPU clock sensors found."));
                            ImGui::Unindent();
                        }
                        ImGui::Checkbox(locale::T("  Show GPU core frequency"), &g_Config.showGpuCoreFreq);
                        if (g_Config.showGpuCoreFreq && g_gpuCount > 0) {
                            ImGui::Indent();
                            GpuInfo& gg = g_gpuList[g_Config.selectedGpu];
                            const char* gpPrev = locale::T("(select sensor)");
                            for (const auto& o : gg.coreClockOpts) {
                                if (strcmp(g_Config.gpuCoreFreqPath, o.second.c_str()) == 0) {
                                    gpPrev = o.first.c_str();
                                    break;
                                }
                            }
                            ImGui::SetNextItemWidth(-1);
                            if (ImGui::BeginCombo("##gpclkcombo", gpPrev)) {
                                for (const auto& o : gg.coreClockOpts) {
                                    bool isSel = (strcmp(g_Config.gpuCoreFreqPath, o.second.c_str()) == 0);
                                    if (ImGui::Selectable(o.first.c_str(), isSel))
                                        snprintf(g_Config.gpuCoreFreqPath, sizeof(g_Config.gpuCoreFreqPath), "%s", o.second.c_str());
                                    if (isSel) ImGui::SetItemDefaultFocus();
                                }
                                ImGui::EndCombo();
                            }
                            if (gg.coreClockOpts.empty())
                                ImGui::TextColored(ImVec4(.85f,.45f,.35f,1), "%s",
                                    locale::T("  No GPU core clock sensors for this GPU."));
                            ImGui::Unindent();
                        }
                    }
                }
                else if (g_Config.settingsTab == SETTINGS_TAB_APPEARANCE) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("POSITION"));
                    ImGui::Spacing();
                    int prevPos = g_Config.position;
                    ImGui::RadioButton(locale::T("Top Left"), &g_Config.position, POS_TOP_LEFT);
                    ImGui::SameLine(0, 16);
                    ImGui::RadioButton(locale::T("Top Center"), &g_Config.position, POS_TOP_CENTER);
                    ImGui::SameLine(0, 16);
                    ImGui::RadioButton(locale::T("Top Right"), &g_Config.position, POS_TOP_RIGHT);
                    ImGui::RadioButton(locale::T("Bottom Left"), &g_Config.position, POS_BOTTOM_LEFT);
                    ImGui::SameLine(0, 16);
                    ImGui::RadioButton(locale::T("Bottom Center"), &g_Config.position, POS_BOTTOM_CENTER);
                    ImGui::SameLine(0, 16);
                    ImGui::RadioButton(locale::T("Bottom Right"), &g_Config.position, POS_BOTTOM_RIGHT);
                    if (g_Config.position != prevPos) {
                        g_Config.customX = -1.0f;
                        g_Config.customY = -1.0f;
                    }
                    ImGui::TextColored(ImVec4(.45f,.45f,.50f,1), "%s",
                        locale::T("Hold CTRL to drag or right-click overlay"));

                    ImGui::Spacing(); ImGui::Spacing();
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("LAYOUT"));
                    ImGui::Spacing();
                    ImGui::RadioButton(locale::T("  Vertical (default)"), &g_Config.layoutStyle, LAYOUT_VERTICAL);
                    ImGui::RadioButton(locale::T("  Horizontal compact"), &g_Config.layoutStyle, LAYOUT_HORIZONTAL);
                    ImGui::RadioButton(locale::T("  Steam-like bar"), &g_Config.layoutStyle, LAYOUT_STEAM);
                    if (ImGui::IsItemHovered())
                        TooltipWrapped(locale::T(
                            "Black bar with Steam-style FPS / CPU / GPU labels.\n"
                            "Same stats as horizontal compact (temps, VRAM/RAM detail, process name).\n"
                            "At 100% size, text matches vertical/horizontal scale."));
                    ImGui::Spacing();
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("Overlay size"));
                    ImGui::SetNextItemWidth(-1);
                    ImGui::SliderInt("##ovscale", &g_Config.overlayScale, 50, 200, "%d%%");
                    if (ImGui::IsItemHovered())
                        TooltipWrapped(locale::T(
                            "Text and spacing scale for vertical, horizontal, and Steam-like layouts.\n"
                            "Hold CTRL on the overlay and drag to move."));

                    ImGui::Spacing(); ImGui::Spacing();
                    ImGui::Checkbox(locale::T("No background (text only)"), &g_Config.transparentBackground);
                    if (ImGui::IsItemHovered())
                        TooltipWrapped(locale::T("Render overlay text without a background panel."));
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("Background opacity"));
                    ImGui::BeginDisabled(g_Config.transparentBackground);
                    ImGui::SetNextItemWidth(-1);
                    ImGui::SliderInt("##opac", &g_Config.opacity, 0, 100, "%d%%");
                    ImGui::EndDisabled();
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                        TooltipWrapped(locale::T("Background transparency for all layouts (0%% = invisible, default 85%%)."));
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("Text opacity"));
                    ImGui::SetNextItemWidth(-1);
                    ImGui::SliderInt("##txtopac", &g_Config.textOpacity, 20, 100, "%d%%");
                    if (ImGui::IsItemHovered())
                        TooltipWrapped(locale::T("Overlay text transparency (independent of background)."));
                }
                else if (g_Config.settingsTab == SETTINGS_TAB_TEMPERATURE) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("TEMPERATURE"));
                    ImGui::Spacing();
                    int tempUnit = g_Config.useFahrenheit ? 1 : 0;
                    if (ImGui::RadioButton(locale::T("Celsius"), &tempUnit, 0)) g_Config.useFahrenheit = false;
                    ImGui::SameLine(0,24);
                    if (ImGui::RadioButton(locale::T("Fahrenheit"), &tempUnit, 1)) g_Config.useFahrenheit = true;
                }
                else if (g_Config.settingsTab == SETTINGS_TAB_HOTKEYS) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("HOTKEYS"));
                    ImGui::Spacing();
                    ImGui::Text("%s", locale::T("Toggle:"));
                    ImGui::SameLine(90);
                    if (g_listeningFor == 1) {
                        ImGui::TextColored(ImVec4(1,.8f,.2f,1), "%s", locale::T("Press any key...  "));
                        ImGui::SameLine();
                        if (ImGui::SmallButton(locale::T("Cancel##1"))) g_listeningFor = 0;
                    } else {
                        ImGui::Text("%-12s", GetKeyName(g_Config.toggleKey));
                        ImGui::SameLine();
                        if (ImGui::SmallButton(locale::T("Change##1"))) g_listeningFor = 1;
                    }
                    ImGui::Text("%s", locale::T("Exit:"));
                    ImGui::SameLine(90);
                    if (g_listeningFor == 2) {
                        ImGui::TextColored(ImVec4(1,.8f,.2f,1), "%s", locale::T("Press any key...  "));
                        ImGui::SameLine();
                        if (ImGui::SmallButton(locale::T("Cancel##2"))) g_listeningFor = 0;
                    } else {
                        ImGui::Text("%-12s", GetKeyName(g_Config.exitKey));
                        ImGui::SameLine();
                        if (ImGui::SmallButton(locale::T("Change##2"))) g_listeningFor = 2;
                    }
                }
                else if (g_Config.settingsTab == SETTINGS_TAB_STARTUP) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("STARTUP"));
                    ImGui::Spacing();
                    ImGui::Checkbox(locale::T("  Start overlay immediately"), &g_Config.autoStart);
                    if (ImGui::IsItemHovered())
                        TooltipWrapped(locale::T("Skip this window and start the overlay directly next time"));
                }
                else if (g_Config.settingsTab == SETTINGS_TAB_LANGUAGE) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("LANGUAGE"));
                    ImGui::Spacing();
                    int langIdx = (_strnicmp(g_Config.language, "zh", 2) == 0) ? 1 : 0;
                    if (ImGui::RadioButton(locale::T("English"), &langIdx, 0))
                        ApplyLanguage("en-US");
                    if (ImGui::RadioButton(locale::T("Simplified Chinese"), &langIdx, 1))
                        ApplyLanguage("zh-CN");
                }
                else if (g_Config.settingsTab == SETTINGS_TAB_ABOUT) {
                    ImGui::TextColored(ImVec4(.55f,.70f,.95f,1), "%s", locale::T("DETECTED HARDWARE"));
                    ImGui::Spacing();
                    ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "%s", locale::TF("CPU:  %s", g_cpuName));
                    ImGui::TextColored(ImVec4(.50f,.50f,.55f,1), "%s", locale::TF("GPU:  %s", g_gpuName));
                }

                ImGui::EndChild();
            };

            if (!rtl) {
                drawSidebar();
                ImGui::SameLine();
                drawPage();
            } else {
                drawPage();
                ImGui::SameLine();
                drawSidebar();
            }

            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(.12f,.56f,.37f,1));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered,  ImVec4(.16f,.68f,.44f,1));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,   ImVec4(.10f,.48f,.32f,1));
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8);
            const bool lhwmBusy = !g_lhwmInitFinished.load(std::memory_order_acquire);
            const char* startBtnLabel = lhwmBusy
                ? locale::T("Initializing LibreHardwareMonitor…")
                : locale::T("Start Overlay");
            ImGui::BeginDisabled(lhwmBusy);
            if (ImGui::Button(startBtnLabel, ImVec2(ImGui::GetContentRegionAvail().x, 42)))
                g_Pending = CMD_START_OVERLAY;
            ImGui::EndDisabled();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor(3);

'''

start = text.find('            // ── Title ──')
end = text.find('            Present(0.08f, 0.08f, 0.10f, 1);')
if start < 0 or end < 0:
    raise SystemExit(f'Could not find settings block start={start} end={end}')
# Keep Present line
text = text[:start] + SETTINGS + text[end:]

# --- Overlay CTRL help ---
text = text.replace(
    'ImGui::TextColored(ImVec4(0.5f, 0.75f, 1.0f, 1.0f), "Drag to move | Right-click for menu");',
    'ImGui::TextColored(OvCol(0.5f, 0.75f, 1.0f, 1.0f), "%s", locale::T("Drag to move | Right-click for menu"));',
)

# --- Menu strings (common) ---
replacements = [
    ('AppendMenu(m, MF_STRING, IDM_HIDE, "Hide Overlay");',
     'AppendMenuA(m, MF_STRING, IDM_HIDE, locale::T("Hide Overlay"));'),
    ('AppendMenu(m, MF_STRING, IDM_SHOW, "Show Overlay");',
     'AppendMenuA(m, MF_STRING, IDM_SHOW, locale::T("Show Overlay"));'),
    ('AppendMenu(m, MF_STRING, IDM_SETTINGS, "Settings");',
     'AppendMenuA(m, MF_STRING, IDM_SETTINGS, locale::T("Settings"));'),
    ('AppendMenu(m, MF_STRING, IDM_EXIT, "Exit");',
     'AppendMenuA(m, MF_STRING, IDM_EXIT, locale::T("Exit"));'),
    ('AppendMenu(m, MF_STRING, IDM_RESET_POS, "Reset Position");',
     'AppendMenuA(m, MF_STRING, IDM_RESET_POS, locale::T("Reset Position"));'),
]
for a,b in replacements:
    text = text.replace(a,b)

# Download update menu - need snprintf then AppendMenuA
text = text.replace(
    'snprintf(updateText, sizeof(updateText), "Download Update (%s)", g_latestVersion);\n'
    '                AppendMenu(m, MF_STRING, IDM_UPDATE, updateText);',
    'snprintf(updateText, sizeof(updateText), "%s", locale::TF("Download Update (%s)", g_latestVersion));\n'
    '                AppendMenuA(m, MF_STRING, IDM_UPDATE, updateText);',
)

# DirectX message
text = text.replace(
    'MessageBox(g_hwnd, "DirectX 11 initialisation failed.", "FPS Overlay", MB_OK | MB_ICONERROR);',
    'MessageBoxW(g_hwnd,\n'
    '            locale::ToWide(locale::DialogBody("directx_init_failed", "DirectX 11 initialisation failed.")).c_str(),\n'
    '            locale::ToWide(locale::DialogTitle("directx_init_failed", "FPS Overlay")).c_str(),\n'
    '            MB_OK | MB_ICONERROR);',
)

# Spark helpers
text = text.replace(
    'ImGui::TextColored(ImVec4(.72f, .72f, .76f, 1), "%.0f MHz", mhz);',
    'ImGui::TextColored(OvCol(.72f, .72f, .76f, 1), "%s", locale::TF("%.0f MHz", mhz));',
)
text = text.replace(
    'ImGui::TextColored(ImVec4(.45f, .45f, .50f, 1), "--- MHz");',
    'ImGui::TextColored(OvCol(.45f, .45f, .50f, 1), "%s", locale::T("--- MHz"));',
)
text = text.replace(
    'ImGui::TextColored(txtCol, "%.0f MHz", mhz);',
    'ImGui::TextColored(OvColV(txtCol), "%s", locale::TF("%.0f MHz", mhz));',
)

# Bulk: wrap common overlay TextColored patterns with OvCol - careful selective
# Vertical FPS
patterns = [
    (r'ImGui::TextColored\(col, "FPS  %.0f", gameFps\);',
     'ImGui::TextColored(OvColV(col), "%s", locale::TF("FPS  %.0f", gameFps));'),
    (r'ImGui::TextColored\(ImVec4\(\.50f,\.50f,\.55f,1\), "FPS  ---"\);',
     'ImGui::TextColored(OvCol(.50f,.50f,.55f,1), "%s", locale::T("FPS  ---"));'),
    (r'ImGui::TextColored\(col, "FPS %.0f", gameFps\);',
     'ImGui::TextColored(OvColV(col), "%s", locale::TF("FPS %.0f", gameFps));'),
    (r'ImGui::TextColored\(ImVec4\(\.50f,\.50f,\.55f,1\), "FPS ---"\);',
     'ImGui::TextColored(OvCol(.50f,.50f,.55f,1), "%s", locale::T("FPS ---"));'),
    (r'ImGui::TextColored\(ImVec4\(\.42f,\.55f,\.42f,1\), "  %s", g_targetProcessName\);',
     'ImGui::TextColored(OvCol(.42f,.55f,.42f,1), "  %s", g_targetProcessName);'),
    (r'ImGui::TextColored\(ImVec4\(\.50f,\.50f,\.55f,1\), "  \(no process\)"\);',
     'ImGui::TextColored(OvCol(.50f,.50f,.55f,1), "%s", locale::T("  (no process)"));'),
    (r'ImGui::TextColored\(ImVec4\(\.55f,\.65f,\.78f,1\), "  %s", timeBuf\);',
     'ImGui::TextColored(OvCol(.55f,.65f,.78f,1), "  %s", timeBuf);'),
    (r'ImGui::TextColored\(ImVec4\(\.55f,\.65f,\.78f,1\), "TIME  %s", timeBuf\);',
     'ImGui::TextColored(OvCol(.55f,.65f,.78f,1), "%s", locale::TF("TIME  %s", timeBuf));'),
    (r'ImGui::TextColored\(ColorByLoad\(cpuUsage\), "CPU  %.0f%%", cpuUsage\);',
     'ImGui::TextColored(OvColV(ColorByLoad(cpuUsage)), "%s", locale::TF("CPU  %.0f%%", cpuUsage));'),
    (r'ImGui::TextColored\(ColorByLoad\(cpuUsage\), "CPU %.0f%%", cpuUsage\);',
     'ImGui::TextColored(OvColV(ColorByLoad(cpuUsage)), "%s", locale::TF("CPU %.0f%%", cpuUsage));'),
    (r'ImGui::TextColored\(ImVec4\(\.82f, \.82f, \.88f, 1\), "CPU  "\);',
     'ImGui::TextColored(OvCol(.82f, .82f, .88f, 1), "%s", locale::T("CPU  "));'),
    (r'ImGui::TextColored\(ImVec4\(\.78f, \.78f, \.82f, 1\), "CPU"\);',
     'ImGui::TextColored(OvCol(.78f, .78f, .82f, 1), "%s", locale::T("CPU"));'),
    (r'ImGui::TextColored\(ImVec4\(\.50f, \.50f, \.55f, 1\), "---"\);',
     'ImGui::TextColored(OvCol(.50f, .50f, .55f, 1), "%s", locale::T("---"));'),
    (r'ImGui::TextColored\(ImVec4\(\.48f, \.58f, \.65f, 1\), "CPU MHz"\);',
     'ImGui::TextColored(OvCol(.48f, .58f, .65f, 1), "%s", locale::T("CPU MHz"));'),
    (r'ImGui::TextColored\(ImVec4\(\.48f, \.58f, \.65f, 1\), "GPU MHz"\);',
     'ImGui::TextColored(OvCol(.48f, .58f, .65f, 1), "%s", locale::T("GPU MHz"));'),
    (r'ImGui::TextColored\(ImVec4\(\.85f, \.78f, \.55f, 1\), "PWR  %.0f W", g_cpuPower\);',
     'ImGui::TextColored(OvCol(.85f, .78f, .55f, 1), "%s", locale::TF("PWR  %.0f W", g_cpuPower));'),
    (r'ImGui::TextColored\(ImVec4\(\.85f, \.78f, \.55f, 1\), "PWR  %.0f W", g_gpuPower\);',
     'ImGui::TextColored(OvCol(.85f, .78f, .55f, 1), "%s", locale::TF("PWR  %.0f W", g_gpuPower));'),
    (r'ImGui::TextColored\(ImVec4\(\.60f, \.80f, \.90f, 1\), "FAN  %.0f RPM", g_cpuFanRpm\);',
     'ImGui::TextColored(OvCol(.60f, .80f, .90f, 1), "%s", locale::TF("FAN  %.0f RPM", g_cpuFanRpm));'),
    (r'ImGui::TextColored\(ImVec4\(\.60f, \.80f, \.90f, 1\), "FAN  %.0f RPM", g_gpuFanRpm\);',
     'ImGui::TextColored(OvCol(.60f, .80f, .90f, 1), "%s", locale::TF("FAN  %.0f RPM", g_gpuFanRpm));'),
    (r'ImGui::TextColored\(ColorByLoad\(dispGpuLoad\), "GPU  %.0f%%", dispGpuLoad\);',
     'ImGui::TextColored(OvColV(ColorByLoad(dispGpuLoad)), "%s", locale::TF("GPU  %.0f%%", dispGpuLoad));'),
    (r'ImGui::TextColored\(ColorByLoad\(dispGpuLoad\), "GPU %.0f%%", dispGpuLoad\);',
     'ImGui::TextColored(OvColV(ColorByLoad(dispGpuLoad)), "%s", locale::TF("GPU %.0f%%", dispGpuLoad));'),
    (r'ImGui::TextColored\(ImVec4\(\.82f, \.82f, \.88f, 1\), "GPU  "\);',
     'ImGui::TextColored(OvCol(.82f, .82f, .88f, 1), "%s", locale::T("GPU  "));'),
    (r'ImGui::TextColored\(ImVec4\(\.50f, \.50f, \.55f, 1\), "GPU  ---"\);',
     'ImGui::TextColored(OvCol(.50f, .50f, .55f, 1), "%s", locale::T("GPU  ---"));'),
    (r'ImGui::TextColored\(ImVec4\(\.50f,\.50f,\.55f,1\), "GPU N/A"\);',
     'ImGui::TextColored(OvCol(.50f,.50f,.55f,1), "%s", locale::T("GPU N/A"));'),
    (r'ImGui::TextColored\(ImVec4\(\.50f, \.50f, \.55f, 1\), "GPU  N/A"\);',
     'ImGui::TextColored(OvCol(.50f, .50f, .55f, 1), "%s", locale::T("GPU  N/A"));'),
    (r'ImGui::TextColored\(ColorByLoad\(pct\), "RAM  %.0f%%", pct\);',
     'ImGui::TextColored(OvColV(ColorByLoad(pct)), "%s", locale::TF("RAM  %.0f%%", pct));'),
    (r'ImGui::TextColored\(ColorByLoad\(pct\), "RAM %.0f%% %.1f/%.0fG", pct, ramUsed, ramTotal\);',
     'ImGui::TextColored(OvColV(ColorByLoad(pct)), "%s", locale::TF("RAM %.0f%% %.1f/%.0fG", pct, ramUsed, ramTotal));'),
    (r'ImGui::TextColored\(ColorByLoad\(vramPct\), "VRAM %.0f%%", vramPct\);',
     'ImGui::TextColored(OvColV(ColorByLoad(vramPct)), "%s", locale::TF("VRAM %.0f%%", vramPct));'),
    (r'ImGui::TextColored\(ColorByLoad\(vramPct\), "VRAM %.0f%% %.1f/%.0fG", vramPct, dispVramUsed, dispVramTotal\);',
     'ImGui::TextColored(OvColV(ColorByLoad(vramPct)), "%s", locale::TF("VRAM %.0f%% %.1f/%.0fG", vramPct, dispVramUsed, dispVramTotal));'),
    (r'ImGui::TextColored\(labFps, "FPS"\);',
     'ImGui::TextColored(OvColV(labFps), "%s", locale::T("FPS"));'),
    (r'ImGui::TextColored\(labCpu, "CPU"\);',
     'ImGui::TextColored(OvColV(labCpu), "%s", locale::T("CPU"));'),
    (r'ImGui::TextColored\(labGpu, "GPU"\);',
     'ImGui::TextColored(OvColV(labGpu), "%s", locale::T("GPU"));'),
    (r'ImGui::TextColored\(ImVec4\(\.85f, \.78f, \.55f, 1\), "%.0fW", g_cpuPower\);',
     'ImGui::TextColored(OvCol(.85f, .78f, .55f, 1), "%s", locale::TF("%.0fW", g_cpuPower));'),
    (r'ImGui::TextColored\(ImVec4\(\.85f, \.78f, \.55f, 1\), "%.0fW", g_gpuPower\);',
     'ImGui::TextColored(OvCol(.85f, .78f, .55f, 1), "%s", locale::TF("%.0fW", g_gpuPower));'),
    (r'ImGui::TextColored\(ImVec4\(\.60f, \.80f, \.90f, 1\), "%.0frpm", g_cpuFanRpm\);',
     'ImGui::TextColored(OvCol(.60f, .80f, .90f, 1), "%s", locale::TF("%.0frpm", g_cpuFanRpm));'),
    (r'ImGui::TextColored\(ImVec4\(\.60f, \.80f, \.90f, 1\), "%.0frpm", g_gpuFanRpm\);',
     'ImGui::TextColored(OvCol(.60f, .80f, .90f, 1), "%s", locale::TF("%.0frpm", g_gpuFanRpm));'),
    (r'ImGui::TextColored\(ImVec4\(\.85f, \.78f, \.55f, 1\), " %.0fW", g_cpuPower\);',
     'ImGui::TextColored(OvCol(.85f, .78f, .55f, 1), " %s", locale::TF("%.0fW", g_cpuPower));'),
    (r'ImGui::TextColored\(ImVec4\(\.85f, \.78f, \.55f, 1\), " %.0fW", g_gpuPower\);',
     'ImGui::TextColored(OvCol(.85f, .78f, .55f, 1), " %s", locale::TF("%.0fW", g_gpuPower));'),
    (r'ImGui::TextColored\(ImVec4\(\.60f, \.80f, \.90f, 1\), " %.0frpm", g_cpuFanRpm\);',
     'ImGui::TextColored(OvCol(.60f, .80f, .90f, 1), " %s", locale::TF("%.0frpm", g_cpuFanRpm));'),
    (r'ImGui::TextColored\(ImVec4\(\.60f, \.80f, \.90f, 1\), " %.0frpm", g_gpuFanRpm\);',
     'ImGui::TextColored(OvCol(.60f, .80f, .90f, 1), " %s", locale::TF("%.0frpm", g_gpuFanRpm));'),
]
for a,b in patterns:
    text, n = re.subn(a, b, text)
    print(a[:40], '->', n)

# Remaining ColorByLoad / TextColored in overlay that still use raw ImVec4 for temps - apply OvColV to ColorByLoad results and tc
# Simple: ColorByLoad( -> OvColV(ColorByLoad(  but only in overlay - risky if settings use ColorByLoad (they don't)

# Process name / time meta lines already partially done

path.write_text(text, encoding='utf-8')
print('Wrote', path, 'len', len(text))
