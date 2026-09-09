import re
from pathlib import Path

p = Path("src/main.cpp")
t = p.read_text(encoding="utf-8")
pat = r'ImGui::TextColored\(ImVec4\(\.55f,\.70f,\.95f,1\), "%s", locale::T\(("([^"\\]|\\.)*")\)\);'
t2, n = re.subn(pat, r"RtlSectionTitle(locale::T(\1));", t)
print("section titles", n)
pat2 = r'ImGui::TextColored\(ImVec4\(\.45f,\.45f,\.50f,1\), "%s",\s*locale::T\(("([^"\\]|\\.)*")\)\);'
t2, n2 = re.subn(pat2, r"RtlMutedText(locale::T(\1));", t2)
print("muted", n2)
# Also multi-line muted with locale::T on next line
pat3 = r'ImGui::TextColored\(ImVec4\(\.45f,\.45f,\.50f,1\), "%s",\s*\n\s*locale::T\(("([^"\\]|\\.)*")\)\);'
t2, n3 = re.subn(pat3, r"RtlMutedText(locale::T(\1));", t2)
print("muted multiline", n3)
p.write_text(t2, encoding="utf-8", newline="\n")
