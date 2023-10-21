#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <UserEnv.h>
#include <tchar.h>
#include "EnablePriv.h"

BOOL console = FALSE;

#define MAX_PATH 35
#define MAX_ARRAY 35
#define NAME_ARRAY 200

int protected_check(DWORD pid, char* cmd);
int  protected_check_console(DWORD pid);
void token_elevation(HANDLE process, char* cmd);
void token_elevation_console(HANDLE process);
BOOL system_check(PROCESSENTRY32 process);


typedef struct _process {
	PROCESSENTRY32 pprocess;
	struct process* next;
} process;

typedef struct _protected_process {
	PROCESSENTRY32 pprotected;
} protected_process;

int system_check_flag = 0;
DWORD WINAPI ThreadProc(LPVOID lpParam) {
	BYTE b[1030];
	DWORD d = 0;
	while (ReadFile((HANDLE)lpParam, b, 1024, &d, 0))
	{
		b[d] = '\0';
		printf("%s", b);
		fflush(stdout);
	}
	return 0;
}


BOOL system_check(PROCESSENTRY32 process) {
	CHAR* system_process = "System";
	int comparison = 0;

	for (int i = 0; i < MAX_PATH; i++) {
		if (process.szExeFile[i] == '\0')
			break;
		else if (process.szExeFile[i] == *system_process) {
			system_process++;
			comparison++;
		}
		else
			break;
	}
	if (wcslen(process.szExeFile) == comparison) {
		system_check_flag++;
		return FALSE;
	}
	return TRUE;
}

//This function's objective is to get the user of a process and check if
//it is SYSTEM
BOOL GetUserInfo(HANDLE token, PTCHAR account_name, PTCHAR domain_name) {
	DWORD token_size, name_size = NAME_ARRAY, domain_size = NAME_ARRAY;
	PTOKEN_USER token_user;
	SID_NAME_USE sid_type;
	int comparison = 0;
	PTCHAR arr_cmp = L"SYSTEM";

	GetTokenInformation(token, TokenUser, NULL, 0, &token_size);
	token_user = (PTOKEN_USER)malloc(token_size);
	BOOL result = GetTokenInformation(token, TokenUser, token_user, token_size, &token_size);
	if (!result) {
		printf("[!] Error: Could not obtain user token information!\n");
		return 1;
	}
	else {
		result = LookupAccountSid(NULL, token_user->User.Sid, account_name, &name_size, domain_name, &domain_size, &sid_type);
		if (!result) {
			printf("[!] Error: Could not get user details!\n");
		}
	}
	free(token_user);

	int arr_length = wcslen(account_name);

	for (int z = 0; z < NAME_ARRAY; z++) {
		if (*account_name == '\0')
			break;
		else if (*account_name == *arr_cmp) {
			comparison++;
			account_name++;
			arr_cmp++;
		}
		else
			break;
	}
	if (comparison == arr_length)
		return TRUE;
	else
		return FALSE;
}

//this function's objective is to get the owner of the process and check if
//it is part of the Administrators group
BOOL GetOwnerInfo(HANDLE token, PTCHAR account_name, PTCHAR domain_name) {
	DWORD token_size = NULL, name_size = NAME_ARRAY, domain_size = NAME_ARRAY;
	PTOKEN_OWNER token_owner;
	SID_NAME_USE sid_type;
	int comparison = 0;
	PTCHAR arr_cmp = L"Administrators";
	SecureZeroMemory(account_name, NAME_ARRAY);
	SecureZeroMemory(domain_name, NAME_ARRAY);

	GetTokenInformation(token, TokenOwner, NULL, 0, &token_size);
	token_owner = (PTOKEN_OWNER)malloc(token_size);
	BOOL result = GetTokenInformation(token, TokenOwner, token_owner, token_size, &token_size);
	if (!result) {
		printf("[!] Error: Could not obtain owner token information!\n");
	}
	else {
		result = LookupAccountSid(NULL, token_owner->Owner, account_name, &name_size, domain_name, &domain_size, &sid_type);
		if (!result) {
			printf("[!] Error: Could not get user details!\n");
		}
	}
	free(token_owner);

	int arr_length = wcslen(account_name);

	for (int z = 0; z < NAME_ARRAY; z++) {
		if (*account_name == '\0')
			break;
		else if (*account_name == *arr_cmp) {
			comparison++;
			account_name++;
			arr_cmp++;
		}
		else
			break;
	}
	if (comparison == arr_length)
		return TRUE;
	else
		return FALSE;
}
