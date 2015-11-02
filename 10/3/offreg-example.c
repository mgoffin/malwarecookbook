#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#pragma comment (lib, "offreg.lib")

#define MAX_KEY_NAME 255     //longest key name
#define MAX_VALUE_NAME 16383 //longest value name
#define MAX_DATA 1024000     //longest data amount

int EnumerateKeys(ORHKEY OffKey, LPWSTR szKeyName)
{
	DWORD    nSubkeys;
	DWORD    nValues;
	DWORD    nSize;
	DWORD    dwType;
	DWORD    cbData;
	ORHKEY   OffKeyNext;
	WCHAR    szValue[MAX_VALUE_NAME];
	WCHAR    szSubKey[MAX_KEY_NAME];
	WCHAR    szNextKey[MAX_KEY_NAME];
	int i;

	// get the number of keys and values
	if (ORQueryInfoKey(OffKey, NULL, NULL, &nSubkeys, 
		NULL, NULL, &nValues, NULL, 
		NULL, NULL, NULL) != ERROR_SUCCESS)
	{
		return 0;
	}

	printf("%ws\n", szKeyName);

    // loop for each of the values
	for(i=0; i<nValues; i++) { 

		memset(szValue, 0, sizeof(szValue));
		nSize  = MAX_VALUE_NAME;
		dwType = 0;
		cbData = 0;

		// get the value's name and required data size
		if (OREnumValue(OffKey, i, szValue, &nSize, 
			&dwType, NULL, &cbData) != ERROR_MORE_DATA)
		{
			continue;
		}

        // allocate memory to store the name
		LPBYTE pData = new BYTE[cbData+2];
		if (!pData) { 
			continue;
		}
		memset(pData, 0, cbData+2);

		// get the name, type, and data 
		if (OREnumValue(OffKey, i, szValue, &nSize, 
			&dwType, pData, &cbData) != ERROR_SUCCESS)
		{
			delete[] pData;
			continue;
		}

		// Here you would check if the Windows API can access a
		// value named named szValue in the active system registry 
		// that with a data type of dwType, a size of cbData and 
		// data that matches the contents of pData. 

		printf("  %-12ws\n", szValue);
		delete[] pData;
	}

    // loop for each of the subkeys...do recursion 
	for(i=0; i<nSubkeys; i++) {
		memset(szSubKey, 0, sizeof(szSubKey));
		nSize = MAX_KEY_NAME;

		// get the name of the subkey
		if (OREnumKey(OffKey, i, szSubKey, &nSize, 
			NULL, NULL, NULL) != ERROR_SUCCESS)
		{
			continue;
		}

		swprintf(szNextKey, MAX_KEY_NAME, L"%s\\%s", 
			szKeyName, szSubKey);

		// open the subkey
		if (OROpenKey(OffKey, szSubKey, &OffKeyNext) 
			== ERROR_SUCCESS)
		{
		    // Here you would check if the Windows API can access a 
		    // subkey named szSubKey in the active system registry
		    
			EnumerateKeys(OffKeyNext, szNextKey);
			ORCloseKey(OffKeyNext);
		}	
	}

	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	ORHKEY OffHive; 

    // open the extracted hive file
	if (OROpenHive(L"software.bin", &OffHive) != ERROR_SUCCESS)
	{
		printf("[ERROR] Cannot open hive: %d\n", GetLastError());
		return -1;
	}

    // begin to enumerate from the root key and prepend  
    // "HKEY_LOCAL_MACHINE\\Software" to all keys since that's
    // where they are located in the active system registry
    EnumerateKeys(OffHive, L"HKEY_LOCAL_MACHINE\\Software");
}