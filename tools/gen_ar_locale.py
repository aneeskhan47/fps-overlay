#!/usr/bin/env python3
"""Generate locales/ar.json (Modern Standard Arabic / fusha) from en-US structure."""
import json
from pathlib import Path

AR = {
    # settings_window
    "FPS Overlay": "FPS Overlay",
    "View on GitHub": "عرض على GitHub",
    "Buy me a coffee": "ادعمني بقهوة",
    "Developed by aneeskhan47 & ": "طوّره aneeskhan47 و",
    "contributors": "المساهمون",
    "Update available!": "يتوفر تحديث!",
    "Click to download %s": "انقر لتنزيل %s",
    "DISPLAY": "العرض",
    "  FPS Counter (game)": "  عداد الإطارات (اللعبة)",
    "(needs admin!)": "(يتطلب صلاحيات المسؤول!)",
    "  CPU Usage": "  استخدام المعالج",
    "  CPU Temp": "  حرارة المعالج",
    "  CPU Power (W)": "  استهلاك المعالج (واط)",
    "(loading…)": "(جارٍ التحميل…)",
    "(unavailable)": "(غير متاح)",
    "  CPU Fan (RPM)": "  مروحة المعالج (دورة/د)",
    "  GPU Usage": "  استخدام البطاقة الرسومية",
    "  GPU Temp": "  حرارة البطاقة الرسومية",
    "  GPU Power (W)": "  استهلاك البطاقة الرسومية (واط)",
    "  GPU Fan (RPM)": "  مروحة البطاقة الرسومية (دورة/د)",
    "  GPU VRAM Usage": "  استخدام ذاكرة الفيديو",
    "  RAM Usage": "  استخدام الذاكرة",
    "  Show process name": "  إظهار اسم العملية",
    "Tracked game / process label on the overlay (all layouts).": "تسمية اللعبة / العملية المتتبَّعة على الطبقة (جميع التخطيطات).",
    "  Show Time": "  إظهار الوقت",
    "Current local time on the overlay (all layouts).": "الوقت المحلي الحالي على الطبقة (جميع التخطيطات).",
    "  Time Format": "  تنسيق الوقت",
    "24 Hour": "24 ساعة",
    "12 Hour (AM/PM)": "12 ساعة (ص/م)",
    "  Show Seconds": "  إظهار الثواني",
    "GPU SELECTION": "اختيار البطاقة الرسومية",
    "Select GPU...": "اختر البطاقة الرسومية...",
    "Multiple GPUs detected - select which to monitor": "تم اكتشاف عدة بطاقات رسومية — اختر ما تريد مراقبته",
    "FREQUENCY": "التردد",
    "Initializing LibreHardwareMonitor…": "جارٍ تهيئة LibreHardwareMonitor…",
    "Requires LibreHardwareMonitor.": "يتطلب LibreHardwareMonitor.",
    "  Show CPU frequency": "  إظهار تردد المعالج",
    "(select sensor)": "(اختر المستشعر)",
    "  No CPU clock sensors found.": "  لم يُعثر على مستشعرات تردد للمعالج.",
    "  Show GPU core frequency": "  إظهار تردد نواة البطاقة الرسومية",
    "  No GPU core clock sensors for this GPU.": "  لا توجد مستشعرات تردد لهذه البطاقة الرسومية.",
    "POSITION": "الموضع",
    "Top Left": "أعلى اليسار",
    "Top Center": "أعلى الوسط",
    "Top Right": "أعلى اليمين",
    "Bottom Left": "أسفل اليسار",
    "Bottom Center": "أسفل الوسط",
    "Bottom Right": "أسفل اليمين",
    "Hold CTRL to drag or right-click overlay": "اضغط CTRL للسحب أو انقر بزر الفأرة الأيمن على الطبقة",
    "LAYOUT": "التخطيط",
    "  Vertical (default)": "  عمودي (افتراضي)",
    "  Horizontal compact": "  أفقي مضغوط",
    "  Steam-like bar": "  شريط بأسلوب Steam",
    "Black bar with Steam-style FPS / CPU / GPU labels.\nSame stats as horizontal compact (temps, VRAM/RAM detail, process name).\nAt 100% size, text matches vertical/horizontal scale.": "شريط أسود بتسميات FPS / CPU / GPU بأسلوب Steam.\nنفس إحصاءات التخطيط الأفقي المضغوط (الحرارة، تفاصيل الذاكرة، اسم العملية).\nعند الحجم 100٪ يطابق مقياس النص التخطيط العمودي/الأفقي.",
    "Overlay size": "حجم الطبقة",
    "Text and spacing scale for vertical, horizontal, and Steam-like layouts.\nHold CTRL on the overlay and drag to move.": "مقياس النص والمسافات للتخطيطات العمودية والأفقية وشبه Steam.\nاضغط CTRL على الطبقة واسحب للتحريك.",
    "Overlay opacity": "شفافية الطبقة",
    "Background transparency for all layouts (default 85%).": "شفافية الخلفية لجميع التخطيطات (الافتراضي 85٪).",
    "TEMPERATURE": "درجة الحرارة",
    "Celsius": "مئوية",
    "Fahrenheit": "فهرنهايت",
    "HOTKEYS": "اختصارات لوحة المفاتيح",
    "Toggle:": "إظهار/إخفاء:",
    "Exit:": "خروج:",
    "Press any key...  ": "اضغط أي مفتاح...  ",
    "Change##1": "تغيير##1",
    "Cancel##1": "إلغاء##1",
    "Change##2": "تغيير##2",
    "Cancel##2": "إلغاء##2",
    "STARTUP": "بدء التشغيل",
    "  Start overlay immediately": "  تشغيل الطبقة فوراً",
    "Skip this window and start the overlay directly next time": "تخطَّ هذه النافذة وابدأ الطبقة مباشرة في المرة القادمة",
    "DETECTED HARDWARE": "الأجهزة المكتشفة",
    "CPU:  %s": "المعالج:  %s",
    "GPU:  %s": "البطاقة الرسومية:  %s",
    "Start Overlay": "تشغيل الطبقة",
    "LANGUAGE": "اللغة",
    "Language": "اللغة",
    "English": "الإنجليزية",
    "Simplified Chinese": "الصينية المبسطة",
    "Arabic": "العربية",
    "APPEARANCE": "المظهر",
    "ABOUT": "حول",
    "No background (text only)": "بدون خلفية (نص فقط)",
    "Render overlay text without a background panel.": "عرض نص الطبقة دون لوحة خلفية.",
    "Background opacity": "شفافية الخلفية",
    "Text opacity": "شفافية النص",
    "Overlay text transparency (independent of background).": "شفافية نص الطبقة (مستقلة عن الخلفية).",
    "Background transparency for all layouts (0%% = invisible, default 85%%).": "شفافية الخلفية لجميع التخطيطات (0٪٪ = غير مرئية، الافتراضي 85٪٪).",
    "Display": "العرض",
    "GPU": "GPU",
    "Frequency": "التردد",
    "Appearance": "المظهر",
    "Temperature": "درجة الحرارة",
    "Hotkeys": "الاختصارات",
    "Startup": "بدء التشغيل",
    "About": "حول",
    # overlay
    "FPS": "FPS",
    "FPS %.0f": "FPS %.0f",
    "FPS ---": "FPS ---",
    "FPS  %.0f": "FPS  %.0f",
    "FPS  ---": "FPS  ---",
    "CPU": "CPU",
    "CPU %.0f%%": "CPU %.0f%%",
    "CPU  %.0f%%": "CPU  %.0f%%",
    "CPU  ": "CPU  ",
    "CPU  ---": "CPU  ---",
    "GPU %.0f%%": "GPU %.0f%%",
    "GPU  %.0f%%": "GPU  %.0f%%",
    "GPU  ": "GPU  ",
    "GPU  ---": "GPU  ---",
    "GPU N/A": "GPU غير متاح",
    "GPU  N/A": "GPU  غير متاح",
    "N/A": "غير متاح",
    "---": "---",
    "--- MHz": "--- MHz",
    "%.0f MHz": "%.0f MHz",
    "CPU MHz": "تردد المعالج",
    "GPU MHz": "تردد البطاقة",
    "PWR  %.0f W": "استهلاك  %.0f W",
    "FAN  %.0f RPM": "مروحة  %.0f RPM",
    "%.0fW": "%.0fW",
    "%.0frpm": "%.0frpm",
    "VRAM %.0f%%": "VRAM %.0f%%",
    "VRAM %.0f%% %.1f/%.0fG": "VRAM %.0f%% %.1f/%.0fG",
    " %.1f / %.0f GB": " %.1f / %.0f GB",
    "RAM  %.0f%%": "RAM  %.0f%%",
    "RAM %.0f%% %.1f/%.0fG": "RAM %.0f%% %.1f/%.0fG",
    " %.1f / %.1f GB": " %.1f / %.1f GB",
    "TIME  %s": "الوقت  %s",
    "  (no process)": "  (لا توجد عملية)",
    "Drag to move | Right-click for menu": "اسحب للتحريك | انقر يميناً للقائمة",
    "AM": "ص",
    "PM": "م",
    # menus
    "Hide Overlay": "إخفاء الطبقة",
    "Show Overlay": "إظهار الطبقة",
    "Reset Position": "إعادة ضبط الموضع",
    "Settings": "الإعدادات",
    "Exit": "خروج",
    "Download Update (%s)": "تنزيل التحديث (%s)",
    "FPS Overlay - Update available! (%s)": "FPS Overlay - يتوفر تحديث! (%s)",
    "Anees": "Anees",
    "FPS Overlay - Lightweight Performance Monitor": "FPS Overlay - مراقب أداء خفيف",
    "FPSOverlay": "FPSOverlay",
    "Copyright (c) 2026 Anees. MIT License.": "حقوق النشر (c) 2026 Anees. رخصة MIT.",
    "overlay.exe": "overlay.exe",
}

DIALOGS_AR = {
    "welcome": {
        "title": "FPS Overlay",
        "body": (
            "مرحباً بك في FPS Overlay!\n\n"
            "لأفضل تجربة، يُفضَّل تعطيل طبقات FPS الأخرى:\n\n"
            "  - طبقة Steam (Steam > الإعدادات > داخل اللعبة)\n"
            "  - شريط ألعاب Xbox (إعدادات Windows > الألعاب)\n"
            "  - طبقة NVIDIA GeForce Experience / ShadowPlay / تطبيق NVIDIA\n"
            "  - طبقة برنامج AMD Radeon\n"
            "  - طبقة Discord\n\n"
            "هذا يمنع التعارض ويضمن قراءات إطارات دقيقة.\n\n"
            "استمتع!"
        ),
    },
    "directx_init_failed": {
        "title": "FPS Overlay",
        "body": "فشل تهيئة DirectX 11.",
    },
    "pawnio_required": {
        "title": "FPS Overlay — مطلوب PawnIO",
        "body": (
            "برنامج تشغيل PawnIO مطلوب لـ FPS Overlay.\n\n"
            "يستخدمه LibreHardwareMonitor لقراءة حرارة المعالج والبطاقة الرسومية. "
            "لا يمكن متابعة التشغيل بدونه.\n\n"
            "انقر موافق لتثبيت PawnIO.\n"
            "انقر إلغاء للخروج."
        ),
    },
    "pawnio_install_failed": {
        "title": "FPS Overlay",
        "body": (
            "لم يكتمل تثبيت PawnIO بنجاح. أُغلق المُثبِّت بخطأ "
            "(مثلاً يجب إزالة إصدار PawnIO موجود أولاً).\n\n"
            "أزل PawnIO من إعدادات Windows ← التطبيقات ← التطبيقات المثبتة، ثم انقر موافق هنا مجدداً."
        ),
    },
    "pawnio_save_restart_failed_install": {
        "title": "FPS Overlay",
        "body": (
            "تعذّر على FPS Overlay حفظ متطلب إعادة التشغيل (config.ini أو "
            "fpsoverlay-pawnio-reboot.state بجانب overlay.exe). تأكد أن المجلد قابل للكتابة، ثم أعد تثبيت PawnIO."
        ),
    },
    "pawnio_outdated": {
        "title": "FPS Overlay — يلزم تحديث PawnIO",
        "body": (
            "إصدار برنامج تشغيل PawnIO لديك أقدم من الإصدار المرفق مع FPS Overlay.\n\n"
            "قد يعطل الإصدار القديم LibreHardwareMonitor (حرارة ناقصة أو خاطئة). يجب التحديث للمتابعة.\n\n"
            "انقر موافق للتحديث الآن (يستبدل التثبيت الحالي).\n"
            "انقر إلغاء للخروج."
        ),
    },
    "pawnio_update_failed": {
        "title": "FPS Overlay",
        "body": (
            "لم يكتمل تحديث PawnIO بنجاح. أُغلق المُثبِّت بخطأ "
            "(مثلاً يجب إزالة الإصدار القديم قبل التثبيت مجدداً).\n\n"
            "أزل PawnIO من إعدادات Windows ← التطبيقات ← التطبيقات المثبتة، ثم انقر موافق هنا مجدداً."
        ),
    },
    "pawnio_save_restart_failed_update": {
        "title": "FPS Overlay",
        "body": (
            "تعذّر على FPS Overlay حفظ متطلب إعادة التشغيل (config.ini أو "
            "fpsoverlay-pawnio-reboot.state بجانب overlay.exe). تأكد أن المجلد قابل للكتابة، ثم أعد تحديث PawnIO."
        ),
    },
    "restart_required": {
        "title": "FPS Overlay — يلزم إعادة التشغيل",
        "body": (
            "مهم: احفظ عملك في التطبيقات الأخرى قبل إعادة التشغيل. قد تُفقد البيانات غير المحفوظة.\n\n"
            "يلزم إعادة تشغيل النظام بالكامل قبل تشغيل FPS Overlay.\n\n"
            "نعم — أعد تشغيل هذا الجهاز الآن (يُغلق FPS Overlay أولاً)\n"
            "لا — أعد التشغيل لاحقاً (يُغلق FPS Overlay؛ استخدم ابدأ ← الطاقة ← إعادة التشغيل عند الجاهزية)\n\n"
        ),
    },
    "restart_marker_invalid": {
        "title": "",
        "body": (
            "ينتظر FPS Overlay إعادة تشغيل النظام بعد تثبيت أو تحديث PawnIO، "
            "لكن علامة إعادة التشغيل في config.ini مفقودة أو غير صالحة.\n\n"
            "إذا استمر الأمر بعد إعادة تشغيل Windows، احذف PawnIORequiresReboot و "
            "PawnIOInstallUtcHex تحت [App] في config.ini واحذف fpsoverlay-pawnio-reboot.state بجانب overlay.exe."
        ),
    },
    "cannot_verify_boot": {
        "title": "",
        "body": (
            "تعذّر على FPS Overlay التحقق من أن هذا الجهاز أُعيد تشغيله منذ تثبيت أو تحديث PawnIO "
            "(تعذّر على Windows الإبلاغ عن وقت آخر إقلاع). ما زالت إعادة التشغيل الكاملة مطلوبة."
        ),
    },
    "must_restart_windows": {
        "title": "",
        "body": (
            "يجب إعادة تشغيل Windows قبل استخدام FPS Overlay.\n\n"
            "ثُبّت أو حُدّث PawnIO سابقاً، ولم تكتمل إعادة تشغيل كاملة في هذه الجلسة بعد."
        ),
    },
    "pawnio_installed_success": {
        "title": "",
        "body": "ثُبّت أو حُدّث PawnIO بنجاح.",
    },
    "restart_failed": {
        "title": "FPS Overlay",
        "body": (
            "تعذّر بدء إعادة تشغيل تلقائية. أعد تشغيل جهازك يدوياً "
            "(ابدأ ← الطاقة ← إعادة التشغيل)، ثم شغّل FPS Overlay مجدداً."
        ),
    },
}


def main():
    en = json.loads(Path("locales/en-US.json").read_text(encoding="utf-8"))
    out = {
        "meta": {
            "file_purpose": "تعريب FPS Overlay بالعربية الفصحى العامة (MSA).",
            "file_purpose_en": "General Modern Standard Arabic (fusha) localization for FPS Overlay.",
            "target_application": "FPS Overlay",
            "application_version": "v1.8.0",
            "source_language": "en-US",
            "target_language": "ar",
            "target_language_display_name": "العربية",
            "primary_source_file": "src/main.cpp",
            "encoding": "UTF-8 (valid JSON)",
            "rtl": True,
        },
        "developer_notes": [
            "Modern Standard Arabic (fusha), not a regional dialect.",
            "Locale code is 'ar'. RTL layout is enabled via locale::IsRtl().",
            "JSON keys are exact English source strings from src/main.cpp.",
            "Dialog fields use title_ar / body_ar (with title_en / body_en retained for reference).",
        ],
        "translations": {},
    }

    missing = []
    for section, content in en["translations"].items():
        if section == "dialogs":
            dialogs = []
            for d in content:
                did = d["id"]
                ar = DIALOGS_AR.get(did, {})
                nd = {
                    "id": did,
                    "title_en": d.get("title_en", ""),
                    "title_ar": ar.get("title", d.get("title_en", "")),
                    "body_en": d.get("body_en", ""),
                    "body_ar": ar.get("body", d.get("body_en", "")),
                }
                if "context" in d:
                    nd["context"] = d["context"]
                if "note" in d:
                    nd["note"] = d["note"]
                dialogs.append(nd)
            out["translations"]["dialogs"] = dialogs
        else:
            mapped = {}
            for k in content.keys():
                if k in AR:
                    mapped[k] = AR[k]
                else:
                    mapped[k] = k
                    missing.append(f"{section}:{k}")
            out["translations"][section] = mapped

    Path("locales/ar.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print("wrote locales/ar.json")
    if missing:
        print("fallback identity for", len(missing), "keys:")
        for m in missing:
            print(" ", m)


if __name__ == "__main__":
    main()
