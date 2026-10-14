// ControlInfiniteRespec.cpp
// CONTROL Resonant - keep one Respec Item forever.
//
// The mod signature-scans the game's executable for the three known respec
// spending paths (Talent, Melee, Ability). It changes only the amount passed
// to the game's currency-spend routine from 1 to 0. The Ability screen also
// maintains a local cached count, so its matching decrement instruction is
// neutralized after the surrounding code shape is verified.
//
// No fixed absolute addresses are used. If a signature is missing or
// ambiguous, that patch is not applied.

extern "C" {
using BOOL = int;
using DWORD = unsigned long;
using SIZE_T = unsigned long long;
using HANDLE = void*;
using HMODULE = void*;
using LPVOID = void*;
using LPCVOID = const void*;
using WCHAR = wchar_t;

__declspec(dllimport) HMODULE __stdcall GetModuleHandleW(const WCHAR* name);
__declspec(dllimport) BOOL __stdcall VirtualProtect(LPVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect);
__declspec(dllimport) BOOL __stdcall FlushInstructionCache(HANDLE process, LPCVOID baseAddress, SIZE_T size);
__declspec(dllimport) HANDLE __stdcall GetCurrentProcess();
__declspec(dllimport) DWORD __stdcall GetModuleFileNameW(HMODULE module, WCHAR* filename, DWORD size);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR* filename, DWORD desiredAccess, DWORD shareMode,
                                                   LPVOID securityAttributes, DWORD creationDisposition,
                                                   DWORD flagsAndAttributes, HANDLE templateFile);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE file, LPCVOID buffer, DWORD bytesToWrite,
                                               DWORD* bytesWritten, LPVOID overlapped);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE object);
__declspec(dllimport) BOOL __stdcall DisableThreadLibraryCalls(HMODULE module);
}

static constexpr DWORD DLL_PROCESS_ATTACH = 1;
static constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;
static constexpr DWORD GENERIC_WRITE = 0x40000000;
static constexpr DWORD FILE_SHARE_READ = 0x00000001;
static constexpr DWORD CREATE_ALWAYS = 2;
static constexpr DWORD FILE_ATTRIBUTE_NORMAL = 0x00000080;
static HANDLE const INVALID_HANDLE_VALUE_ = (HANDLE)(long long)-1;
static constexpr DWORD IMAGE_SCN_MEM_EXECUTE = 0x20000000;

struct Pattern {
    const unsigned char* bytes;
    const unsigned char* mask; // 1 = compare, 0 = wildcard
    unsigned int length;
};

struct ScanResult {
    unsigned char* address;
    unsigned int count;
};

static HANDLE g_log = INVALID_HANDLE_VALUE_;

static unsigned int cstrlen(const char* s) {
    unsigned int n = 0;
    while (s && s[n]) ++n;
    return n;
}

static void log_text(const char* s) {
    if (g_log == INVALID_HANDLE_VALUE_ || !s) return;
    DWORD written = 0;
    WriteFile(g_log, s, (DWORD)cstrlen(s), &written, nullptr);
}

static void log_hex_u64(unsigned long long v) {
    char buf[19];
    static const char hex[] = "0123456789ABCDEF";
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 16; ++i) {
        int shift = (15 - i) * 4;
        buf[2 + i] = hex[(v >> shift) & 0xF];
    }
    buf[18] = 0;
    log_text(buf);
}

static void open_log(HMODULE self) {
    WCHAR path[1024];
    DWORD n = GetModuleFileNameW(self, path, 1024);
    if (n == 0 || n >= 1024) return;

    int slash = -1;
    for (DWORD i = 0; i < n; ++i) {
        if (path[i] == L'\\' || path[i] == L'/') slash = (int)i;
    }
    int pos = slash + 1;
    const WCHAR name[] = L"ControlInfiniteRespec.log";
    int j = 0;
    while (name[j] && pos + j < 1023) {
        path[pos + j] = name[j];
        ++j;
    }
    path[pos + j] = 0;

    g_log = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static bool bytes_match(const unsigned char* p, const Pattern& pat) {
    for (unsigned int i = 0; i < pat.length; ++i) {
        if (pat.mask[i] && p[i] != pat.bytes[i]) return false;
    }
    return true;
}

static ScanResult scan_executable_sections(unsigned char* module, const Pattern& pat) {
    ScanResult out{nullptr, 0};
    if (!module) return out;

    // Minimal PE parsing. We only need NumberOfSections, SizeOfOptionalHeader,
    // VirtualAddress, VirtualSize, and Characteristics.
    const unsigned int peOff = *(unsigned int*)(module + 0x3C);
    unsigned char* nt = module + peOff;
    if (*(unsigned int*)nt != 0x00004550u) return out; // "PE\\0\\0"

    const unsigned short numberOfSections = *(unsigned short*)(nt + 6);
    const unsigned short sizeOfOptionalHeader = *(unsigned short*)(nt + 20);
    unsigned char* section = nt + 24 + sizeOfOptionalHeader;

    for (unsigned int s = 0; s < numberOfSections; ++s, section += 40) {
        const unsigned int virtualSize = *(unsigned int*)(section + 8);
        const unsigned int virtualAddress = *(unsigned int*)(section + 12);
        const unsigned int characteristics = *(unsigned int*)(section + 36);
        if ((characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        if (virtualSize < pat.length) continue;

        unsigned char* begin = module + virtualAddress;
        const unsigned int last = virtualSize - pat.length;
        for (unsigned int i = 0; i <= last; ++i) {
            if (!bytes_match(begin + i, pat)) continue;
            ++out.count;
            if (out.count == 1) out.address = begin + i;
            else out.address = nullptr;
        }
    }
    return out;
}

static bool patch_bytes(void* address, const unsigned char* replacement, unsigned int length) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;

    volatile unsigned char* dst = (volatile unsigned char*)address;
    for (unsigned int i = 0; i < length; ++i) dst[i] = replacement[i];

    FlushInstructionCache(GetCurrentProcess(), address, length);
    DWORD ignored = 0;
    VirtualProtect(address, length, oldProtect, &ignored);
    return true;
}

static void report_scan(const char* name, const ScanResult& r, unsigned char* module) {
    log_text(name);
    if (r.count == 1 && r.address) {
        log_text(": found at RVA ");
        log_hex_u64((unsigned long long)(r.address - module));
        log_text("\r\n");
    } else if (r.count == 0) {
        log_text(": FAIL - signature not found\r\n");
    } else {
        log_text(": FAIL - signature ambiguous\r\n");
    }
}

static bool apply_mod(HMODULE self) {
    open_log(self);
    log_text("Control Infinite Respec v0.1.0\r\n");
    log_text("Mode: keep one legitimate Respec Item; suppress consumption\r\n\r\n");

    unsigned char* game = (unsigned char*)GetModuleHandleW(nullptr);
    if (!game) {
        log_text("FAIL - could not obtain CONTROLResonant.exe module base\r\n");
        return false;
    }

    // Wildcards cover RIP-relative global loads and call displacements.
    // Talent path, beginning at observed RVA 0x1E16F0B on the researched build.
    static const unsigned char talentBytes[] = {
        0x4C,0x8B,0x8B,0xA8,0x00,0x00,0x00, 0xBA,0x01,0x00,0x00,0x00,
        0x4C,0x8B,0x83,0xA0,0x00,0x00,0x00, 0x8B,0x0D,0,0,0,0,
        0xC6,0x44,0x24,0x20,0x01
    };
    static const unsigned char talentMask[] = {
        1,1,1,1,1,1,1, 1,1,1,1,1,
        1,1,1,1,1,1,1, 1,1,0,0,0,0,
        1,1,1,1,1
    };

    // Melee path, beginning at observed RVA 0x1F0434A.
    static const unsigned char meleeBytes[] = {
        0x4C,0x8B,0x8F,0xA0,0x00,0x00,0x00, 0xBA,0x01,0x00,0x00,0x00,
        0x4C,0x8B,0x87,0x98,0x00,0x00,0x00, 0x8B,0x0D,0,0,0,0,
        0xC6,0x44,0x24,0x20,0x01
    };
    static const unsigned char meleeMask[] = {
        1,1,1,1,1,1,1, 1,1,1,1,1,
        1,1,1,1,1,1,1, 1,1,0,0,0,0,
        1,1,1,1,1
    };

    // Ability path includes the local cached-count decrement after the spend call.
    static const unsigned char abilityBytes[] = {
        0x4C,0x8B,0x8B,0x98,0x00,0x00,0x00, 0xBA,0x01,0x00,0x00,0x00,
        0x4C,0x8B,0x83,0x90,0x00,0x00,0x00, 0x8B,0x0D,0,0,0,0,
        0xC6,0x44,0x24,0x20,0x01, 0xE8,0,0,0,0,
        0x48,0x8B,0x83,0xA0,0x00,0x00,0x00, 0xFF,0x88,0x90,0x00,0x00,0x00
    };
    static const unsigned char abilityMask[] = {
        1,1,1,1,1,1,1, 1,1,1,1,1,
        1,1,1,1,1,1,1, 1,1,0,0,0,0,
        1,1,1,1,1, 1,0,0,0,0,
        1,1,1,1,1,1,1, 1,1,1,1,1,1
    };

    static_assert(sizeof(talentBytes) == sizeof(talentMask), "talent signature size mismatch");
    static_assert(sizeof(meleeBytes) == sizeof(meleeMask), "melee signature size mismatch");
    static_assert(sizeof(abilityBytes) == sizeof(abilityMask), "ability signature size mismatch");

    const Pattern talentPat{talentBytes, talentMask, (unsigned int)sizeof(talentBytes)};
    const Pattern meleePat{meleeBytes, meleeMask, (unsigned int)sizeof(meleeBytes)};
    const Pattern abilityPat{abilityBytes, abilityMask, (unsigned int)sizeof(abilityBytes)};

    ScanResult talent = scan_executable_sections(game, talentPat);
    ScanResult melee = scan_executable_sections(game, meleePat);
    ScanResult ability = scan_executable_sections(game, abilityPat);

    report_scan("Talent respec", talent, game);
    report_scan("Melee respec", melee, game);
    report_scan("Ability respec", ability, game);

    if (talent.count != 1 || melee.count != 1 || ability.count != 1 ||
        !talent.address || !melee.address || !ability.address) {
        log_text("\r\nFAIL - no patches applied. Game code did not match all expected signatures.\r\n");
        return false;
    }

    // In all three paths, pattern+7 is BA 01 00 00 00 (mov edx, 1).
    // Change only the immediate low byte at +8: amount 1 -> amount 0.
    const unsigned char zero = 0x00;
    if (!patch_bytes(talent.address + 8, &zero, 1)) {
        log_text("FAIL - could not patch Talent consumption amount\r\n");
        return false;
    }
    if (!patch_bytes(melee.address + 8, &zero, 1)) {
        log_text("FAIL - could not patch Melee consumption amount\r\n");
        return false;
    }
    if (!patch_bytes(ability.address + 8, &zero, 1)) {
        log_text("FAIL - could not patch Ability consumption amount\r\n");
        return false;
    }

    // Ability path additionally does: FF 88 90 00 00 00 = dec dword ptr [rax+90h]
    // Pattern verification above guarantees the exact surrounding structure.
    static const unsigned char nops6[] = {0x90,0x90,0x90,0x90,0x90,0x90};
    if (!patch_bytes(ability.address + 42, nops6, 6)) {
        log_text("FAIL - could not suppress Ability cached-count decrement\r\n");
        return false;
    }

    log_text("\r\nACTIVE - all three respec consumption paths patched.\r\n");
    log_text("The game should still require >= 1 Respec Item, but successful respecs should not consume it.\r\n");
    return true;
}

extern "C" __declspec(dllexport) BOOL __stdcall DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        apply_mod(module);
    }
    return 1;
}
