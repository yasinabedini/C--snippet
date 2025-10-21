# C++ Snippet Collection

A collection of small Windows-focused C++ snippets for system programming, security research, and API exploration.

This repository includes diverse mini examples demonstrating low-level concepts such as:
- Process and thread enumeration
- Access token handling and impersonation
- Windows Service and privilege control
- Handle duplication / OpenProcess token usage
- Miscellaneous Win32 and security-related internals

All snippets are standalone and minimal, designed for educational and research purposes — useful for learning Windows internals, red teaming, or exploit development foundations.

---

## 🧩 Structure

Each `.cpp` file represents an isolated concept (no external dependencies other than Win32 API).  
Snippets can be compiled directly using **MSVC** or **MinGW**:
```bash
cl /EHsc /W4 sample.cpp
