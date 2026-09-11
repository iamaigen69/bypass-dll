#include <windows.h>

// ── Original bytes storage
BYTE origGetForeground[5]  = {0};
BYTE origSetWindowPos[5]   = {0};
BYTE origBringToTop[5]     = {0};
BYTE origSetFocus[5]       = {0};
BYTE origSetWDA[5]         = {0};

// ── Helper: find main window of current process
BOOL CALLBACK FindMainCb(HWND hwnd, LPARAM lp) {
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(hwnd) &&
        GetWindow(hwnd, GW_OWNER) == NULL) {
        *(HWND*)lp = hwnd;
        return FALSE;
    }
    return TRUE;
}

HWND FindMainWindow() {
    HWND hwnd = NULL;
    EnumWindows(FindMainCb, (LPARAM)&hwnd);
    return hwnd;
}

// ── Hook: GetForegroundWindow → always return our window
HWND WINAPI MyGetForegroundWindow() {
    HWND hwnd = FindMainWindow();
    return hwnd ? hwnd : NULL;
}

// ── Hook: SetWindowPos → do nothing
BOOL WINAPI MySetWindowPos(HWND h, HWND i, int x, int y, int cx, int cy, UINT f) {
    return TRUE;
}

// ── Hook: BringWindowToTop → do nothing
BOOL WINAPI MyBringWindowToTop(HWND h) {
    return TRUE;
}

// ── Hook: SetFocus → return our window
HWND WINAPI MySetFocus(HWND h) {
    return FindMainWindow();
}

// ── Hook: SetWindowDisplayAffinity → always set WDA_NONE
BOOL WINAPI MySetWindowDisplayAffinity(HWND hwnd, DWORD affinity) {
    // Ignore protection requests — always return success
    return TRUE;
}

// ── Install a 5-byte JMP hook (x64 compatible)
void InstallHook(void* target, void* detour, BYTE* original) {
    DWORD old;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(original, target, 5);
    *(BYTE*)target = 0xE9; // JMP
    *(DWORD*)((BYTE*)target + 1) = (DWORD)((BYTE*)detour - (BYTE*)target - 5);
    VirtualProtect(target, 5, old, &old);
}

// ── Strip WDA from all windows
BOOL CALLBACK StripWDACb(HWND hwnd, LPARAM) {
    SetWindowDisplayAffinity(hwnd, WDA_NONE);
    return TRUE;
}

void StripAllWDA() {
    EnumWindows(StripWDACb, 0);
}

// ── Install all hooks
void InstallAllHooks() {
    HMODULE u32 = GetModuleHandleA("user32.dll");
    if (!u32) return;

    // 1. Hook GetForegroundWindow
    void* pGetFG = (void*)GetProcAddress(u32, "GetForegroundWindow");
    if (pGetFG) InstallHook(pGetFG, (void*)MyGetForegroundWindow, origGetForeground);

    // 2. Hook SetWindowPos
    void* pSWP = (void*)GetProcAddress(u32, "SetWindowPos");
    if (pSWP) InstallHook(pSWP, (void*)MySetWindowPos, origSetWindowPos);

    // 3. Hook BringWindowToTop
    void* pBWT = (void*)GetProcAddress(u32, "BringWindowToTop");
    if (pBWT) InstallHook(pBWT, (void*)MyBringWindowToTop, origBringToTop);

    // 4. Hook SetFocus
    void* pSF = (void*)GetProcAddress(u32, "SetFocus");
    if (pSF) InstallHook(pSF, (void*)MySetFocus, origSetFocus);

    // 5. Hook SetWindowDisplayAffinity — prevents re-applying WDA
    void* pSWDA = (void*)GetProcAddress(u32, "SetWindowDisplayAffinity");
    if (pSWDA) InstallHook(pSWDA, (void*)MySetWindowDisplayAffinity, origSetWDA);

    // 6. Strip WDA from all existing windows immediately
    StripAllWDA();
}

// ── DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // Run in new thread to keep DllMain non-blocking
        CreateThread(NULL, 0, [](LPVOID) -> DWORD {
            Sleep(500); // wait for process to initialize
            InstallAllHooks();
            return 0;
        }, NULL, 0, NULL);
    }
    return TRUE;
}
