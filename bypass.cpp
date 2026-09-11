#include <windows.h>

// ── Original bytes storage (only WDA hook)
BYTE origSetWDA[5] = {0};

// ── Hook: SetWindowDisplayAffinity → always return TRUE without setting WDA
// This prevents javaw from re-applying WDA_EXCLUDEFROMCAPTURE
BOOL WINAPI MySetWindowDisplayAffinity(HWND hwnd, DWORD affinity) {
    return TRUE; // pretend success, do nothing
}

// ── Install a 5-byte JMP hook (x64 compatible)
void InstallHook(void* target, void* detour, BYTE* original) {
    DWORD old;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(original, target, 5);
    *(BYTE*)target = 0xE9; // JMP opcode
    *(DWORD*)((BYTE*)target + 1) = (DWORD)((BYTE*)detour - (BYTE*)target - 5);
    VirtualProtect(target, 5, old, &old);
}

// ── Strip WDA from all windows immediately
BOOL CALLBACK StripWDACb(HWND hwnd, LPARAM) {
    SetWindowDisplayAffinity(hwnd, WDA_NONE);
    return TRUE;
}

// ── Install hooks
void InstallAllHooks() {
    HMODULE u32 = GetModuleHandleA("user32.dll");
    if (!u32) return;

    // Hook SetWindowDisplayAffinity — javaw can never re-apply WDA
    void* pSWDA = (void*)GetProcAddress(u32, "SetWindowDisplayAffinity");
    if (pSWDA) InstallHook(pSWDA, (void*)MySetWindowDisplayAffinity, origSetWDA);

    // Strip WDA from all existing windows immediately
    EnumWindows(StripWDACb, 0);
}

// ── DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, [](LPVOID) -> DWORD {
            Sleep(300);
            InstallAllHooks();
            return 0;
        }, NULL, 0, NULL);
    }
    return TRUE;
}
