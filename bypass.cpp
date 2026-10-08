#include <windows.h>

// Original bytes
BYTE origSetWDA[5] = {0};

// Hook: SetWindowDisplayAffinity → always return TRUE without setting WDA
BOOL WINAPI MySetWindowDisplayAffinity(HWND hwnd, DWORD affinity) {
    return TRUE;
}

// Install 5-byte JMP hook
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

// Check if current process is a target we should hook
bool IsTargetProcess() {
    char procPath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, procPath, MAX_PATH);
    CharLowerA(procPath);
    return strstr(procPath, "javaw") != NULL ||
           strstr(procPath, "browserlock") != NULL;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (!IsTargetProcess()) return TRUE; // Exit immediately for svchost etc.
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, [](LPVOID) -> DWORD {
            Sleep(300);
            InstallAllHooks();
            return 0;
        }, NULL, 0, NULL);
    }
    return TRUE;
}
