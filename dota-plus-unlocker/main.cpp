#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <string>
#include <cstdarg>
#include <ctime>

#pragma comment(lib, "psapi.lib")

#include "minhook/MinHook.h"

#define PAD(size) char __pad_##__LINE__[size]

static FILE* g_pLogFile = nullptr;
static CRITICAL_SECTION g_LogCS;

static void InitLog()
{
    InitializeCriticalSection(&g_LogCS);
    CreateDirectoryA("C:\\dota-plus-unlocker", nullptr);
    g_pLogFile = fopen("C:\\dota-plus-unlocker\\log.txt", "a");
    if (g_pLogFile)
    {
        time_t now = time(nullptr);
        struct tm tm_info;
        localtime_s(&tm_info, &now);
        fprintf(g_pLogFile, "\nLog started %02d.%02d.%04d %02d:%02d:%02d\n",
            tm_info.tm_mday, tm_info.tm_mon + 1, tm_info.tm_year + 1900,
            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);
        fflush(g_pLogFile);
    }
}

static void Log(const char* format, ...)
{
    EnterCriticalSection(&g_LogCS);
    if (g_pLogFile)
    {
        va_list args;
        va_start(args, format);
        vfprintf(g_pLogFile, format, args);
        va_end(args);
        fflush(g_pLogFile);
    }
    LeaveCriticalSection(&g_LogCS);
}

static void CloseLog()
{
    if (g_pLogFile)
    {
        Log("Log closed\n");
        fclose(g_pLogFile);
        g_pLogFile = nullptr;
    }
    DeleteCriticalSection(&g_LogCS);
}

class CDOTAGameAccountPlus
{
private:
    PAD(0x2C);
public:
    enum EDotaPlusStatus : int32_t
    {
        STATUS_INVALID = -1,
        STATUS_SUBSCRIBED = 1,
        STATUS_UNSUBSCRIBED = 2,
    };
    int32_t m_nStatus;
};

using GetProtoCDOTAGameAccountPlus_t = CDOTAGameAccountPlus * (__fastcall*)(void*);
static GetProtoCDOTAGameAccountPlus_t g_pOriginalGetProto = nullptr;

static uintptr_t FindPattern(HMODULE hModule, const char* szSignature)
{
    if (!hModule || !szSignature)
        return 0;

    auto pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    auto pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(hModule) + pDOSHeader->e_lfanew);
    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    uintptr_t textSectionBase = 0;
    DWORD textSectionSize = 0;

    auto pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaders);
    for (WORD i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++)
    {
        if (strncmp(reinterpret_cast<const char*>(pSectionHeader[i].Name), ".text", 8) == 0)
        {
            textSectionBase = reinterpret_cast<uintptr_t>(hModule) + pSectionHeader[i].VirtualAddress;
            textSectionSize = pSectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textSectionBase || !textSectionSize)
        return 0;

    const char* patCurrent = szSignature;
    uintptr_t matchAddress = 0;
    uintptr_t endAddress = textSectionBase + textSectionSize;

    for (uintptr_t pCur = textSectionBase; pCur < endAddress; pCur++)
    {
        if (!*patCurrent)
            return matchAddress;

        if (*patCurrent == '?')
        {
            if (!matchAddress)
                matchAddress = pCur;

            if (patCurrent[1] == '?') patCurrent += 2;
            else patCurrent += 1;

            if (*patCurrent == ' ') patCurrent++;
        }
        else
        {
            char* szEnd;
            uint8_t bytePattern = static_cast<uint8_t>(strtoul(patCurrent, &szEnd, 16));

            if (*reinterpret_cast<uint8_t*>(pCur) == bytePattern)
            {
                if (!matchAddress)
                    matchAddress = pCur;

                patCurrent = szEnd;
                if (*patCurrent == ' ') patCurrent++;
            }
            else
            {
                patCurrent = szSignature;
                if (matchAddress)
                {
                    pCur = matchAddress;
                    matchAddress = 0;
                }
            }
        }
    }

    if (!*patCurrent && matchAddress)
        return matchAddress;

    return 0;
}

static CDOTAGameAccountPlus* __fastcall HookedGetProtoCDOTAGameAccountPlus(void* pCDOTAGCClientSystem)
{
    Log("GetProtoCDOTAGameAccountPlus called\n");

    CDOTAGameAccountPlus* pResult = g_pOriginalGetProto(pCDOTAGCClientSystem);

    Log("Original returned: 0x%p, Status: %d\n", pResult, pResult ? pResult->m_nStatus : -1);

    if (pResult)
    {
        Log("Setting Dota Plus status to SUBSCRIBED\n");
        pResult->m_nStatus = CDOTAGameAccountPlus::EDotaPlusStatus::STATUS_SUBSCRIBED;
    }

    return pResult;
}

static DWORD WINAPI MainThread(LPVOID)
{
    InitLog();
    Log("Dota Plus Unlocker loaded\n");
    Log("Waiting for client.dll...\n");

    while (!GetModuleHandleA("client.dll"))
        Sleep(1000);

    Log("client.dll loaded\n");

    if (MH_Initialize() != MH_OK)
    {
        Log("MinHook init failed\n");
        CloseLog();
        return 1;
    }

    Log("MinHook initialized\n");

    HMODULE hClient = GetModuleHandleA("client.dll");
    Log("client.dll base: 0x%p\n", hClient);

    uintptr_t pGetProtoAddr = FindPattern(hClient,
        "48 83 EC 38 48 8B 89 10 05 00 00 48 85 C9 74 ? BA DC 07 00 00 E8 ? ? ? ? 48 85 C0 74 ? 8B 48 08 85 C9 74 ? 48 8B 40 10");

    if (pGetProtoAddr)
    {
        Log("Hooking GetProtoCDOTAGameAccountPlus at: 0x%p\n", (void*)pGetProtoAddr);

        MH_STATUS status = MH_CreateHook((void*)pGetProtoAddr, HookedGetProtoCDOTAGameAccountPlus, (void**)&g_pOriginalGetProto);
        if (status == MH_OK)
        {
            Log("Hook created\n");
            MH_EnableHook((void*)pGetProtoAddr);
            Log("Hook enabled\n");
        }
        else
        {
            Log("Hook creation failed: %d\n", status);
        }
    }
    else
    {
        Log("Pattern not found\n");
    }

    Log("Ready, waiting for Dota Plus checks...\n");

    return 0;
}

static DWORD WINAPI ManualMapEntry(LPVOID lpParam)
{
    return MainThread(lpParam);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        if (lpReserved == nullptr)
        {
            CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
        }
        else
        {
            CreateThread(nullptr, 0, ManualMapEntry, lpReserved, 0, nullptr);
        }
    }
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL WINAPI ManualMap(LPVOID lpParam)
{
    return MainThread(lpParam);
}