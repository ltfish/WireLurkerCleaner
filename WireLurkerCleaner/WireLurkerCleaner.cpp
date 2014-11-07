#include "stdafx.h"

#include <conio.h>
#include <locale.h>

#define BLOCK_SIZE 655360

char SPACES[140] = {0};

void msg(char* fmt, ...)
{
	// TODO: support argc
	printf(fmt);
}

bool dataCompare(FILE *f, BYTE *buffer, int bufferSize, int i, long offset, char* toCompare, int size)
{
	bool ret = false;

	if (i + size < bufferSize)
	{
		// Directly compare inside memory
		ret = !memcmp(toCompare, buffer + i, size);
	}
	else
	{
		long oldOffset = ftell(f);
		BYTE buf[30];
		long bytesRead;

		// Load from file		
		fseek(f, offset + i, SEEK_SET);
		bytesRead = fread(buf, 1, size, f);

		if (bytesRead == size && !memcmp(toCompare, buf, size))
		{
			ret = true;
		}

		// Recover the original offset
		fseek(f, oldOffset, SEEK_SET);
	}

	return ret;
}

bool checkFile(TCHAR* fileDir, TCHAR* fileName)
{
	bool ret = false;
	TCHAR path[MAX_PATH];
	FILE* f;

	// Construct the file path
	wcscpy(path, fileDir);
	wcscat(path, fileName);

	// Try to open the file
	char filepath[MAX_PATH];
	wcstombs(filepath, path, MAX_PATH);

	// Print it out...
	printf(SPACES);
	printf("\r");
	printf("Scanning file %.80s...\r", filepath);
	printf("\r");

	f = fopen(filepath, "rb");
	if (f)
	{
		// Detection logic
		int eocdCounter = 0; // "\x50\x4b\x05\x06" 
		bool str1Exists = false; // "Payload/apps.app/sfbase.dylib"
		bool str2Exists = false; // "Payload/apps.app/sfbase.plist"

		BYTE buffer[BLOCK_SIZE];
		size_t size = fread(buffer, 1, BLOCK_SIZE, f);;
		long offset = 0;

		while (true)
		{
			// Scan for '\x50' first
			for (int i = 0; i < size; ++i)
			{
				if (buffer[i] == '\x50')
				{
					// Compare with "\x50\x4b\x05\x06"
					if (dataCompare(f, buffer, size, i, offset, "\x50\x4b\x05\x06", 4))
					{
						++eocdCounter;
					}
					// Compare with those two strings (length = 29)
					else if (dataCompare(f, buffer, size, i, offset, "Payload/apps.app/sfbase.dylib", strlen("Payload/apps.app/sfbase.dylib")))
					{
						str1Exists = true;
					}
					else if(dataCompare(f, buffer, size, i, offset, "Payload/apps.app/sfbase.plist", strlen("Payload/apps.app/sfbase.plist")))
					{
						str2Exists = true;
					}
				}
			}

			offset += size;
			if (size == BLOCK_SIZE)
			{
				size = fread(buffer, 1, BLOCK_SIZE, f);
			}
			else
			{
				break;
			}
		}

		fclose(f);
		ret = (eocdCounter == 4 && str1Exists && str2Exists);
	}

	return ret;
}

void prompt(TCHAR* dirName, TCHAR* filename)
{
	printf("[-] Infected file found: %ls%ls.\n", dirName, filename);
}

void scanDir(TCHAR* dirName)
{
	WIN32_FIND_DATA findFileData;
	HANDLE hFile, hDir;
	TCHAR path[MAX_PATH];

	wcscpy(path, dirName); 
	wcscat(path, _T("*.exe"));

	// All executables
	hFile = FindFirstFileEx(
		path,
		FindExInfoStandard,
		&findFileData,
		FindExSearchNameMatch,
		NULL,
		0
		);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			TCHAR *filename = findFileData.cFileName;
			bool infected = checkFile(dirName, filename);

			if (infected)
			{
				prompt(dirName, filename);
			}

		} while (FindNextFile(hFile, &findFileData));

		FindClose(hFile);
	}

	// All directories
	wcscpy(path, dirName);
	wcscat(path, _T("*"));

	hDir = FindFirstFile(path, &findFileData);
	if (hDir != INVALID_HANDLE_VALUE)
	{
		do
		{
			// Check if it is a directory
			if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
				!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
			{
				if (wcscmp(findFileData.cFileName, _T(".")) && wcscmp(findFileData.cFileName, _T("..")))
				{
					TCHAR newDirPath[MAX_PATH];

					wcscpy(newDirPath, dirName);
					wcscat(newDirPath, findFileData.cFileName);
					wcscat(newDirPath, _T("\\"));
					scanDir(newDirPath);
				}
			}
		} while (FindNextFile(hDir, &findFileData));

		FindClose(hDir);
	}
}

void detect()
{
	TCHAR driveName[4] = _T("C:\\");

	// Traverse all partitions
	for(TCHAR i = _T('C'); i <= _T('Z'); ++i)
	{
		driveName[0] = i;

		UINT driveType = GetDriveType(driveName);

		if (driveType == DRIVE_FIXED)
		{
			// Local drive

			scanDir(driveName);
		}
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	// Prepare the console window
	system("mode 150, 30");

	setlocale(LC_ALL, "");
	memset(SPACES, ' ', sizeof(SPACES));
	msg("==== WireLurkerCleaner ====\n");
	msg("Read README.md before continue. Use at your own risk.\n");
	msg("Press any key to start scan:\n");
	_getch();

	detect();

	printf(SPACES);
	printf("\n");
	msg("Scan finished.\n");

	system("pause");
	return 0;
}

