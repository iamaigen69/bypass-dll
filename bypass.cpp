#include <windows.h>

BYTE origSetWDA[5] = {0};

BOOL WINAPI MySetWindowDisplayAffinity(HWND hwnd, DWORD affinity) {
    return TRUE;
}

void InstallHook(void* target, void* detour, BYTE* original) {
    DWORD old;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(original, target, 5);
    *(BYTE*)target = 0xE9;
    *(DWORD*)((BYTE*)target + 1) = (DWORD)((BYTE*)detour - (BYTE*)target - 5);
    VirtualProtect(target, 5, old, &old);
}

void InstallAllHooks() {
    HMODULE u32 = GetModuleHandleA("user32.dll");
    if (!u32) return;
    void* pSWDA = (void*)GetProcAddress(u32, "SetWindowDisplayAffinity");
    if (pSWDA) InstallHook(pSWDA, (void*)MySetWindowDisplayAffinity, origSetWDA);
}

// Safe process check using PEB — no Win32 calls, no loader lock risk
bool IsTargetProcess() {
    wchar_t* cmdLine = GetCommandLineW(); // safe in DllMain
    if (!cmdLine) return false;
    // lowercase comparison manually
    wchar_t buf[512] = {0};
    for (int i = 0; i < 511 && cmdLine[i]; i++)
        buf[i] = (cmdLine[i] >= L'A' && cmdLine[i] <= L'Z') ? cmdLine[i] + 32 : cmdLine[i];
    return wcsstr(buf, L"javaw") != NULL ||
           wcsstr(buf, L"browserlock") != NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (!IsTargetProcess()) return TRUE;
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, [](LPVOID) -> DWORD {
            Sleep(300);
            InstallAllHooks();
            return 0;
        }, NULL, 0, NULL);
    }
    return TRUE;
}
