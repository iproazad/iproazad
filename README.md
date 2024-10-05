
#include <iostream>
#include "api/Swifty.hpp"
#include "pch.h"
#include "resource.h"
#include <filesystem>
#include "mem.h"
#include <fstream>
#include <Windows.h>
#include <tlhelp32.h>
#include <thread>
#include <filesystem> 
#include "Discord.h"
#include <urlmon.h>
#include"Memx.h"
#include "gui.h"
#include <psapi.h>
#include <shellapi.h>

#include"Settings.h"

#include <thread>
#include "main.h"
#include <Windows.h>"
#include "imgui\imgui.h"
#include "mem.h"


#include <Windows.h>
#include "auth.hpp"
#include <string>
#include "skStr.h"
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

//using namespace KeyAuth;
//
//std::string name = "Mustafa Bypass"; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
//std::string ownerid = "6fT4gDrJi8"; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
//std::string secret = "ba0803ca95f691bf2fbf3374281e8c00727ee2a03e083fbcc32cb6d48acba6b0"; // app secret, the blurred text on licenses tab and other tabs
//std::string version = "1.0"; // leave alone unless you've changed version on website
//std::string url = "https://keyauth.win/api/1.1/"; // change if you're self-hosting
//std::string sslPin = "ssl pin key (optional)"; // don't change unless you intend to pin public certificate key. you can get here in the "Pin SHA256" field https://www.ssllabs.com/ssltest/analyze.html?d=keyauth.win&latest. If you do this you need to be aware of when SSL key expires so you can update it
//
//
//api KeyAuthApp(name, ownerid, secret, version, url, sslPin);




#pragma comment(lib, "urlmon.lib")

Discord* g_Discord;
using namespace std;

int progress_func(void* ptr, double TotalToDownload, double NowDownloaded,
	double TotalToUpload, double NowUploaded)
{
	// ensure that the file to be downloaded is not empty
	// because that would cause a division by zero error later on
	if (TotalToDownload <= 0.0) {
		return 0;
	}

	// how wide you want the progress meter to be
	int totaldotz = 40;
	double fractiondownloaded = NowDownloaded / TotalToDownload;
	// part of the progressmeter that's already "full"
	int dotz = (int)round(fractiondownloaded * totaldotz);

	// create the "meter"
	int ii = 0;
	//printf("%3.0f%% [", fractiondownloaded * 100);
	// part  that's full already
	for (; ii < dotz; ii++) {
		//printf("-");
	}
	for (; ii < totaldotz; ii++) {
		//printf(" ");
	}
	fflush(stdout);
	return 0;
}

class DownloadProgress : public IBindStatusCallback {
public:
	HRESULT __stdcall QueryInterface(const IID&, void**) {
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef(void) {
		return 1;
	}
	ULONG STDMETHODCALLTYPE Release(void) {
		return 1;
	}
	HRESULT STDMETHODCALLTYPE OnStartBinding(DWORD dwReserved, IBinding* pib) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE GetPriority(LONG* pnPriority) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE OnLowResource(DWORD reserved) {
		return S_OK;
	}
	virtual HRESULT STDMETHODCALLTYPE OnStopBinding(HRESULT hresult, LPCWSTR szError) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE GetBindInfo(DWORD* grfBINDF, BINDINFO* pbindinfo) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE OnDataAvailable(DWORD grfBSCF, DWORD dwSize, FORMATETC* pformatetc, STGMEDIUM* pstgmed) {
		return E_NOTIMPL;
	}
	virtual HRESULT STDMETHODCALLTYPE OnObjectAvailable(REFIID riid, IUnknown* punk) {
		return E_NOTIMPL;
	}

	virtual HRESULT __stdcall OnProgress(ULONG ulProgress, ULONG ulProgressMax, ULONG ulStatusCode, LPCWSTR szStatusText)
	{
		progress_func(0, ulProgressMax, ulProgress, 0, 0);

		wcout << endl;
		return S_OK;
	}
};


std::string tm_to_readable_time(tm ctx) {
	char buffer[25];

	strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

	return std::string(buffer);
}





string readFile(string location)
{
	string myText;
	ifstream MyReadFile(location);
	while (getline(MyReadFile, myText)) {
		cout << myText;
	}
	MyReadFile.close();
	return myText;
}
void writeToFile(string filepath, string credentials)
{
	ofstream MyFile(filepath);
	MyFile << credentials;
	MyFile.close();
}

inline bool FileExist(const std::string& name) {
	if (FILE* file = fopen(name.c_str(), "r")) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}

typedef struct _MEMORY_REGION {
	DWORD_PTR dwBaseAddr;
	DWORD_PTR dwMemorySize;
}MEMORY_REGION;

HANDLE ProcessHandle;
DWORD pid;

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(WINAPI* RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);


typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);


void resume(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(
		GetModuleHandleA("ntdll"), "NtResumeProcess");

	pfnNtResumeProcess(processHandle);
	CloseHandle(processHandle);
}

DWORD dGet(DWORD base) {
	DWORD val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}
float fGet(DWORD base) {
	float val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}
int iGet(DWORD base) {
	int val;
	ReadProcessMemory(ProcessHandle, (void*)(base), &val, sizeof(val), NULL);
	return val;
}
int iwrit(long int addr, float value) {
	int val;
	WriteProcessMemory(ProcessHandle, (void*)(addr), &value, sizeof(value), NULL);
	//pwrite64(handle, &value, 4, addr);
	return val;
}

bool WriteMemory(long addr, SIZE_T siz, DWORD write) {
	WriteProcessMemory(ProcessHandle, (void*)addr, &write, siz, NULL);
	return true;
}

bool replaced(long addr, BYTE write) {
	WriteProcessMemory(ProcessHandle, (void*)addr, &write, 1, NULL);
	return true;
}

bool patcher(long addr, BYTE write[], SIZE_T sizee) {
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (void*)addr, sizee, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (void*)addr, write, sizee, NULL);
	VirtualProtectEx(phandle, (void*)addr, sizee, OldProtect, NULL);
	return true;
}
void suspend(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
		GetModuleHandleA("ntdll"), "NtSuspendProcess");

	pfnNtSuspendProcess(processHandle);
	CloseHandle(processHandle);
}

HANDLE processHandle;

template <typename T>
T ReadMemoryEx(DWORD BaseAddress, HANDLE phandle)
{
	T Buffer;
	ReadProcessMemory(phandle, (LPCVOID)BaseAddress, &Buffer, sizeof(Buffer), nullptr);

	return Buffer;
}

void WriteUE4Float(DWORD offset, float replace, DWORD pidd, DWORD ue4Header, HANDLE phandle)
{


	DWORD oldprotect;
	VirtualProtectEx(phandle, (LPVOID)(ue4Header + offset), sizeof(float), PAGE_EXECUTE_READWRITE, &oldprotect);
	WriteProcessMemory(phandle, (LPVOID)(ue4Header + offset), &replace, sizeof(float), NULL);
	VirtualProtectEx(phandle, (LPVOID)(ue4Header + offset), sizeof(float), PAGE_READONLY, &oldprotect);
}
//DWORD UE4 = ReadMemoryEx<int>(0xE0C3260);
//DWORD TERSAFE = ReadMemoryEx<int>(0xE0C1220);


template<typename T>
T read(uintptr_t ptrAddress)
{
	T val = T();
	ReadProcessMemory(ProcessHandle, (void*)ptrAddress, &val, sizeof(T), NULL);
	return val;
}


template<typename T>
T read(uintptr_t ptrAddress, T val)
{
	ReadProcessMemory(ProcessHandle, (void*)ptrAddress, &val, sizeof(val), NULL);
	return val;
}


template<typename T>
bool write(uintptr_t ptrAddress, LPVOID value)
{
	return WriteProcessMemory(ProcessHandle, (LPVOID)ptrAddress, &value, sizeof(T), NULL);
}


std::string exec(const char* cmd)
{
	char buffer[128]; std::string result = "";
	FILE* pipe = _popen(cmd, "r");
	if (!pipe)
		throw std::runtime_error("popen() failed!");
	try {
		while (fgets(buffer, sizeof buffer, pipe) != NULL)
		{
			result += buffer;
		}
	}
	catch (...)
	{
		_pclose(pipe);
		throw;
	}
	_pclose(pipe);
	return result;
}


std::string removeSpaces(std::string str)
{
	str.erase(remove(str.begin(), str.end(), ' '), str.end());
	return str;
}




int MemFind(BYTE* buffer, int dwBufferSize, BYTE* bstr, DWORD dwStrLen)
{
	if (dwBufferSize < 0)
	{
		return -1;
	}
	DWORD  i, j;
	for (i = 0; i < dwBufferSize; i++)
	{
		for (j = 0; j < dwStrLen; j++)
		{
			if (buffer[i + j] != bstr[j] && bstr[j] != '?')
				break;
		}
		if (j == dwStrLen)
			return i;
	}
	return -1;
}

int SundaySearch(BYTE* bStartAddr, int dwSize, BYTE* bSearchData, DWORD dwSearchSize)
{
	if (dwSize < 0)
	{
		return -1;
	}
	int iIndex[256] = { 0 };
	int i, j;
	DWORD k;

	for (i = 0; i < 256; i++)
	{
		iIndex[i] = -1;
	}

	j = 0;
	for (i = dwSearchSize - 1; i >= 0; i--)
	{
		if (iIndex[bSearchData[i]] == -1)
		{
			iIndex[bSearchData[i]] = dwSearchSize - i;
			if (++j == 256)
				break;
		}
	}
	i = 0;
	BOOL bFind = FALSE;
	//j=dwSize-dwSearchSize+1;
	j = dwSize - dwSearchSize + 1;
	while (i < j)
	{
		for (k = 0; k < dwSearchSize; k++)
		{
			if (bStartAddr[i + k] != bSearchData[k])
				break;
		}
		if (k == dwSearchSize)
		{
			//ret=bStartAddr+i;
			bFind = TRUE;
			break;
		}
		if (i + dwSearchSize >= dwSize)
		{

			return -1;
		}
		k = iIndex[bStartAddr[i + dwSearchSize]];
		if (k == -1)
			i = i + dwSearchSize + 1;
		else
			i = i + k;
	}
	if (bFind)
	{
		return i;
	}
	else
		return -1;

}


BOOL MemSearch(BYTE* bSearchData, int nSearchSize, DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr, BOOL bIsCurrProcess, int iSearchMode, std::vector<DWORD_PTR>& vRet)
{
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	BYTE* pCurrMemoryData = NULL;
	MEMORY_BASIC_INFORMATION	mbi;
	std::vector<MEMORY_REGION> m_vMemoryRegion;
	mbi.RegionSize = 0x1000;
	DWORD dwAddress = dwStartAddr;



	while (VirtualQueryEx(phandle, (LPCVOID)dwAddress, &mbi, sizeof(mbi)) && (dwAddress < dwEndAddr) && ((dwAddress + mbi.RegionSize) > dwAddress))
	{

		if ((mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_GUARD) == 0) && (mbi.Protect != PAGE_NOACCESS) && ((mbi.AllocationProtect & PAGE_NOCACHE) != PAGE_NOCACHE))
		{

			MEMORY_REGION mData = { 0 };
			mData.dwBaseAddr = (DWORD_PTR)mbi.BaseAddress;
			mData.dwMemorySize = mbi.RegionSize;
			m_vMemoryRegion.push_back(mData);

		}
		dwAddress = (DWORD)mbi.BaseAddress + mbi.RegionSize;

	}


	std::vector<MEMORY_REGION>::iterator it;
	for (it = m_vMemoryRegion.begin(); it != m_vMemoryRegion.end(); it++)
	{
		MEMORY_REGION mData = *it;


		DWORD_PTR dwNumberOfBytesRead = 0;

		if (bIsCurrProcess)
		{
			pCurrMemoryData = (BYTE*)mData.dwBaseAddr;
			dwNumberOfBytesRead = mData.dwMemorySize;
		}
		else
		{

			pCurrMemoryData = new BYTE[mData.dwMemorySize];
			ZeroMemory(pCurrMemoryData, mData.dwMemorySize);
			ReadProcessMemory(phandle, (LPCVOID)mData.dwBaseAddr, pCurrMemoryData, mData.dwMemorySize, &dwNumberOfBytesRead);

			if ((int)dwNumberOfBytesRead <= 0)
			{
				delete[] pCurrMemoryData;
				continue;
			}
		}
		if (iSearchMode == 0)
		{
			DWORD_PTR dwOffset = 0;
			int iOffset = MemFind(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);
			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}
		}
		else if (iSearchMode == 1)
		{

			DWORD_PTR dwOffset = 0;
			int iOffset = SundaySearch(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);

			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}

		}

		if (!bIsCurrProcess && (pCurrMemoryData != NULL))
		{
			delete[] pCurrMemoryData;
			pCurrMemoryData = NULL;
		}

	}
	return TRUE;
}

int SINGLEAOBSCAN6969(BYTE BypaRep[], SIZE_T size)
{
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x00000000, 0x7fffffff, false, 0, Bypassdo);
	if (Bypassdo.size() == 1)
	{
		//MessageBoxA(0, "wtf", 0, 0);
	}
	if (Bypassdo.size() == 2)
	{
		//MessageBoxA(0, "ok here we go", 0, 0);
	}
	if (Bypassdo.size() != 0) {
		return Bypassdo[1];
	}
}
//int SINGLEAOBSCAN69691(BYTE BypaRep[], SIZE_T size)
//{
//	DWORD pid = getAowProcId22();
//	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
//	std::vector<DWORD_PTR> Bypassdo;
//	MemSearch(BypaRep, size, 0x00000000, 0x7fffffff, false, 0, Bypassdo);
//	if (Bypassdo.size() == 1)
//	{
//		//MessageBoxA(0, "wtf", 0, 0);
//	}
//	if (Bypassdo.size() == 2)
//	{
//		//MessageBoxA(0, "ok here we go", 0, 0);
//	}
//	if (Bypassdo.size() != 0) {
//		return Bypassdo[1];
//	}
//}

int SINGLEAOBSCAN(BYTE BypaRep[], SIZE_T size)
{
	if (Settings::Smartgaga)
	{

		DWORD pid = getProcId2();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassdo;
		//MemSearch(BypaRep, size, 0x70000000, 0x90000000, false, 0, Bypassdo);
		MemSearch(BypaRep, size, 0x26000000, 0xB0000000, false, 0, Bypassdo);

		if (Bypassdo.size() != 0) {
			return Bypassdo[0];
		}
	}
	else if (Settings::Gameloop)
	{
		DWORD pid = getProcId2();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassdo;
		//MemSearch(BypaRep, size, 0x40000000, 0x60000000, false, 0, Bypassdo);
		MemSearch(BypaRep, size, 0x26000000, 0xB0000000, false, 0, Bypassdo);

		if (Bypassdo.size() != 0) {
			return Bypassdo[0];
		}

	}
}




int SINGLEAOBSCAN2(BYTE BypaRep[], SIZE_T size)//this is for tersafe
{

	if (Settings::Smartgaga)//For smartgaga
	{
		int pid = getGagaProcId();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassdo;
		MemSearch(BypaRep, size, 0x04000000, 0x05000000, false, 0, Bypassdo);

		if (Bypassdo.size() != 0) {
			return Bypassdo[0];
		}

	}
	else if (Settings::Gameloop)//change
	{
		DWORD pid = getProcId2();
		HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
		std::vector<DWORD_PTR> Bypassdo;
		MemSearch(BypaRep, size, 0x40000000, 0x41000000, false, 0, Bypassdo);

		if (Bypassdo.size() != 0) {
			return Bypassdo[0];
		}

	}

}
int Keraftonaddr()
{
	int libtersafeheader = 0;
	BYTE tersafehead[] = { 0x4B, 0x00, 0x52, 0x00, 0x41, 0x00, 0x46, 0x00, 0x54, 0x00, 0x4F, 0x00, 0x4E };
	libtersafeheader = SINGLEAOBSCAN6969(tersafehead, sizeof(tersafehead));
	return libtersafeheader;
}

int gettersafeheader()
{
	int libtersafeheader = 0;
	//old //BYTE tersafehead[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x08,0xBD,0x3C };
	BYTE tersafehead[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xC0,0xDA,0x3D,0x00,0x00,0x02,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x1D,0x00,0x1C,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00 };
	libtersafeheader = SINGLEAOBSCAN2(tersafehead, sizeof(tersafehead));
	return libtersafeheader;
}
int getGCloud()
{
	int libtprtheader = 0;
	BYTE GCloud[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xE4,0xA0,0x37,0x00,0x00,0x00,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x18,0x00,0x17,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x34,0x01,0x00,0x00,0x34,0x01,0x00,0x00,0x34,0x01,0x00,0x00,0x13,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	libtprtheader = SINGLEAOBSCAN2(GCloud, sizeof(GCloud));
	return libtprtheader;
}

int getue4header()
{
	unsigned long  libue4header = 0;
	//BYTE ue4head[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x24,0x66,0x67 };
	BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x26, 0x8A, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00, 0x1A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00 };
	libue4header = SINGLEAOBSCAN(ue4head, sizeof(ue4head));
	return libue4header;
}


int getue4headerVn()
{
	unsigned long  libue4header = 0;
	//BYTE ue4head[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x24,0x66,0x67 };
	BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x56, 0x8A, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00, 0x1A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	libue4header = SINGLEAOBSCAN(ue4head, sizeof(ue4head));
	return libue4header;
}

//int gettrptheader()
//{
//	int libtprtheader = 0;
//	BYTE tprt[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xA0,0x50,0x07,0x00,0x00,0x02,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x1B,0x00,0x1A,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70 };
//	libtprtheader = SINGLEAOBSCAN2(tprt, sizeof(tprt));
//	return libtprtheader;
//}
int gettrptheader()
{
	int libtprtheader = 0;
	BYTE tprt[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xA0,0x50,0x07,0x00,0x00,0x02,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x1B,0x00,0x1A,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x07,0x07,0x00,0x70,0x07,0x07,0x00,0x05,0x00,0x00,0x00 };
	libtprtheader = SINGLEAOBSCAN2(tprt, sizeof(tprt));
	return libtprtheader;
}
int getlibTDataMaster()
{
	int libTDataMaste = 0;
	BYTE masterhead[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0xF0, 0x25, 0x00, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x08, 0x00, 0x28, 0x00, 0x1C, 0x00, 0x1B, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00 };
	libTDataMaste = SINGLEAOBSCAN2(masterhead, sizeof(masterhead));
	return libTDataMaste;
}

int getUEend()
{

	unsigned long libue4end = 0;
	BYTE ue4end[] = { 0xB0, 0xAF, 0x00, 0x80, 0xFF, 0x00, 0xE3, 0x80, 0x00, 0x03, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0xA8, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x48, 0x02, 0x00 };
	libue4end = SINGLEAOBSCAN(ue4end, sizeof(ue4end));
	return libue4end;

}

int getTERSend()
{
	int libuTERSend = 0;
	BYTE TERSend[] = { 0xFF, 0x00, 0xBC, 0x00, 0x03, 0x34, 0x30, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x01, 0x5C, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
	libuTERSend = SINGLEAOBSCAN2(TERSend, sizeof(TERSend));
	return libuTERSend;
}


void offsetsearch2(int offset, BYTE write[], SIZE_T size, int header)
{
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	int addr = header + offset;
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (BYTE*)addr, write, size, NULL);
	VirtualProtectEx(phandle, (BYTE*)addr, size, OldProtect, NULL);

}


void AOBREP(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers)
{
	DWORD pid = getProcId2();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x00000000, 0x7fffffff, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}
	}
	else
	{

	}
}
DWORD MyGetProcessId(LPCTSTR ProcessName) // non-conflicting function name
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) { // must call this first
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap); // close handle on failure
	return 0;
}
void AOBREP2(BYTE BypaRep[], BYTE write[], SIZE_T size, SIZE_T sizee, int numbers)
{
	DWORD pid = MyGetProcessId("AndroidEmulatorEx.exe");
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x00000000, 0x7fffffff, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		for (int i = 0; i < Bypassdo.size() && i < numbers; i++)
		{
			int results = Bypassdo[i];
			patcher(results, write, sizee);
		}
	}
	else
	{

	}
}

void findAndReplaceAll(std::string& data, std::string toSearch, std::string replaceStr)
{
	size_t pos = data.find(toSearch);
	while (pos != std::string::npos)
	{
		data.replace(pos, toSearch.size(), replaceStr);
		pos = data.find(toSearch, pos + replaceStr.size());
	}
}

void cmdd(string text)
{
	string prim = "/c " + text;
	const char* primm = prim.c_str();
	ShellExecute(0, "open", "cmd.exe", (LPCSTR)primm, 0, SW_HIDE);
}

void startEmulator(int choices)
{
	if (choices == 1)
	{
		HKEY key;
		LONG succeeded;
		std::string keyname = "SOFTWARE\\WOW6432Node\\Tencent\\MobileGamePC\\";
		std::string processor_name;
		vector<string> processor_list;

		succeeded = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname.c_str(), NULL, KEY_READ, &key);
		if (succeeded == ERROR_SUCCESS)
		{
			const char* value = "";
			DWORD value_size = 0;
			char buf[255];
			HKEY key1;
			string name = keyname + "UI";
			succeeded = RegOpenKey(HKEY_LOCAL_MACHINE, name.c_str(), &key1);
			if (succeeded == ERROR_SUCCESS)
			{
				value_size = sizeof(buf);
				memset(buf, 0, sizeof(buf));
				succeeded = RegQueryValueEx(key1, "InstallPath", 0, 0, (unsigned char*)buf, &value_size);
				if (succeeded == ERROR_SUCCESS)
				{
					string emudir = buf;
					string aedir = emudir + "\\AndroidEmulatorEx.exe";
					//findAndReplaceAll(aedir, "C:", "\"C:");
					aedir.insert(0, 1, '"');
					findAndReplaceAll(aedir, ".exe", ".exe\"");
					string aedirx = aedir + " -vm 100";
					//std::cout << aedirx << std::endl;
					cmdd(aedirx.c_str());
				}
				RegCloseKey(key1);
			}
		}
		else
		{
			cout << "Your Choice Of Emulator Isn't Installed" << endl;
		}
		RegCloseKey(key);
	}
	if (choices == 2)
	{
		HKEY key;
		LONG succeeded;
		std::string keyname = "SOFTWARE\\WOW6432Node\\Tencent\\MobileGamePC\\";
		std::string processor_name;
		vector<string> processor_list;

		succeeded = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname.c_str(), NULL, KEY_READ, &key);
		if (succeeded == ERROR_SUCCESS)
		{
			const char* value = "";
			DWORD value_size = 0;
			char buf[255];
			HKEY key1;
			string name = keyname + "UI";
			succeeded = RegOpenKey(HKEY_LOCAL_MACHINE, name.c_str(), &key1);
			if (succeeded == ERROR_SUCCESS)
			{
				value_size = sizeof(buf);
				memset(buf, 0, sizeof(buf));
				succeeded = RegQueryValueEx(key1, "InstallPath", 0, 0, (unsigned char*)buf, &value_size);
				if (succeeded == ERROR_SUCCESS)
				{
					string emudir = buf;
					string aedir = emudir + "\\AndroidEmulatorEn.exe";//AndroidEmulatorEn
					aedir.insert(0, 1, '"');
					string aedirx = aedir + " x";
					findAndReplaceAll(aedir, ".exe", ".exe\"");
					//std::cout << aedir << std::endl;
					cmdd(aedir.c_str());
				}
				RegCloseKey(key1);
			}

		}
		else
		{
			cout << "Your Choice Of Emulator Isn't Installed" << endl;
		}
		RegCloseKey(key);
	}
	if (choices == 3)
	{
		HKEY key;
		LONG succeeded;
		std::string keyname = "SOFTWARE\\WOW6432Node\\SmartGaGa\\ProjectTitan\\";
		std::string processor_name;
		vector<string> processor_list;

		succeeded = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname.c_str(), NULL, KEY_READ, &key);
		if (succeeded == ERROR_SUCCESS)
		{
			const char* value = "";
			DWORD value_size = 0;
			char buf[255];
			HKEY key1;
			string name = keyname;
			succeeded = RegOpenKey(HKEY_LOCAL_MACHINE, name.c_str(), &key1);
			if (succeeded == ERROR_SUCCESS)
			{
				value_size = sizeof(buf);
				memset(buf, 0, sizeof(buf));
				succeeded = RegQueryValueEx(key1, "InstallDir", 0, 0, (unsigned char*)buf, &value_size);
				if (succeeded == ERROR_SUCCESS)
				{
					string emudir = buf;
					string aedir = emudir + "\\Engine\\ProjectTitan.exe";
					aedir.insert(0, 1, '"');
					findAndReplaceAll(aedir, ".exe", ".exe\"");
					//std::cout << aedir << std::endl;
					cmdd(aedir.c_str());
				}
				RegCloseKey(key1);
			}

		}
		else
		{
			cout << "Your Choice Of Emulator Isn't Installed" << endl;
		}
		RegCloseKey(key);
	}

}




string  gen_random(int len) {
	string s;
	static const char alphanum[] =
		"0123456789";
	for (int i = 0; i < len; ++i) {
		s += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return s;
}

string  gen_random2(int len) {
	string s;
	static const char alphanum[] =
		"0123456789"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return s;
}
std::string random_string(size_t length)
{
	auto randchar = []() -> char
		{
			const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
			const size_t max_index = (sizeof(charset) - 1);
			return charset[rand() % max_index];
		};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}
void fixemuid()
{
	std::ofstream outfile("C:\\device_id.txt");
	outfile << " <?xml version='1.0' encoding='utf-8' standalone='yes' ?> \n<map>\n    <string name=\"install\">dc33f8d6-a036-45d3-ae00-d13eb6cb46b9</string>\n    <string name=\"uuid\">" + gen_random2(32) + "</string>\n    <string name = \"random\"></string>\n</map>" << std::endl;
	outfile.close();
	string did = "adb shell settings put secure android_id " + gen_random(31);

}

int Bypass(std::string command)
{
	command.insert(0, "/C ");

	SHELLEXECUTEINFOA ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = NULL;
	ShExecInfo.lpFile = "cmd.exe";
	ShExecInfo.lpParameters = command.c_str();
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;

	if (ShellExecuteExA(&ShExecInfo) == FALSE)
		return -1;

	WaitForSingleObject(ShExecInfo.hProcess, INFINITE);

	DWORD rv;
	GetExitCodeProcess(ShExecInfo.hProcess, &rv);
	CloseHandle(ShExecInfo.hProcess);

	return rv;
}
void writememx()
{
	DWORD pid = getProcId2();




	Memory memory;
	if (!memory.AttachProcess(pid))
	{
		MessageBoxA(0, "error attache proccess.", "Error", MB_ICONERROR);
		return;
	}

entrypoint:

	std::string dri = "sc create BUSHIDO binPath= \"C:\\hookdrv.sys\" start=demand type=filesys > nul 2> nul";
	Bypass(dri.c_str());
	Bypass("sc start BUSHIDO > nul 2> nul");
	//DWORD pid = getGagaProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);


	int UE4Base, ANOGSBase;
	int PTRBase;
	int TDMBase;
	int GCLBase;
	int UE4Base1;
	int IGBase;
	int GCLOUDCORE;
	int ANORTBase;
	int CSBase;
	UE4Base = ReadMemoryEx<int>(0xE0C3868, phandle);
	ANOGSBase = ReadMemoryEx<int>(0xE0C1228, phandle);
	PTRBase = ReadMemoryEx<int>(0xE0C0928, phandle);
	TDMBase = ReadMemoryEx<int>(0xE0C0F28, phandle);
	GCLBase = ReadMemoryEx<int>(0xE0C10A8, phandle);
	IGBase = ReadMemoryEx <int>(0xE0C1828, phandle);
	GCLOUDCORE = ReadMemoryEx<int>(0xE0C0DA8, phandle);
	ANORTBase = ReadMemoryEx<int>(0xE0C07A8, phandle);
	CSBase = ReadMemoryEx<int>(0xE0C3268, phandle);
	if (ANOGSBase == 0 || UE4Base == 0)
	{


		std::cout << "try again" << std::endl;


		goto entrypoint;
	}


	else
	{




		//CString str1;// to print header agous
		//str1.Format(_T("%d"), ANOGSBase);
		//string s = to_string(ANOGSBase);
		//MessageBoxA(0, "fuck ANOGSBase ", s.c_str(), 0);
		//SAFE 2.0 O


//suspend(pid);
		Sleep(3000);


		//put your offest here 
//memory.WriteBytes(ANOGSBase + 0x443536, new BYTE[]{ 0x00, 0x00, 0x00, 0x00 }, true);
		WriteUE4Float(0x5483064, 250.000f, pid, UE4Base, phandle);//ipad


		//resume(pid);

		CloseHandle(memory.ProcessHandle);




		Settings::bypassDone = true;





	}

}
void writememx2()
{
	DWORD pid = getProcId2();




	Memory memory;
	if (!memory.AttachProcess(pid))
	{
		MessageBoxA(0, "error attache proccess.", "Error", MB_ICONERROR);
		return;
	}

entrypoint:

	std::string dri = "sc create BUSHIDO binPath= \"C:\\hookdrv.sys\" start=demand type=filesys > nul 2> nul";
	Bypass(dri.c_str());
	Bypass("sc start BUSHIDO > nul 2> nul");
	//DWORD pid = getGagaProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

	short c = 10;
	DWORD libtersafeheader = gettersafeheader();
	DWORD trptheader = gettrptheader();
	unsigned long libue4header = getue4header();
	unsigned long libue4header2 = getue4headerVn();

	if (libtersafeheader == 0 || libue4header == 0)
	{


		std::cout << "try again" << std::endl;


		goto entrypoint;
	}

	else
	{



		memory.WriteBytes(libtersafeheader + 0x342C0, new BYTE[]{ 0x00,0x00,0xA0,0xE3,0x1E,0xFF,0x2F }, true);
		memory.WriteBytes(libtersafeheader + 0x371FA, new BYTE[]{ 0x59 }, true);
		memory.WriteBytes(libtersafeheader + 0x37214, new BYTE[]{ 0x59,0x00 }, true);
		memory.WriteBytes(libtersafeheader + 0x3722A, new BYTE[]{ 0x59,0x00,0x59,0x00,0x59,0x00 }, true);
		CloseHandle(memory.ProcessHandle);




		Settings::bypassDone = true;

		//}



	}

}

int nsystem(std::string command)
{
	command.insert(0, "/C ");

	SHELLEXECUTEINFOA ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = NULL;
	ShExecInfo.lpFile = "cmd.exe";
	ShExecInfo.lpParameters = command.c_str();
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;

	if (ShellExecuteExA(&ShExecInfo) == FALSE)
		return -1;

	WaitForSingleObject(ShExecInfo.hProcess, INFINITE);

	DWORD rv;
	GetExitCodeProcess(ShExecInfo.hProcess, &rv);
	CloseHandle(ShExecInfo.hProcess);

	return rv;
}
void Stealth()
{
	HWND Stealth;
	AllocConsole();
	Stealth = FindWindowA("ConsoleWindowClass", NULL);
	ShowWindow(Stealth, 0);
}
void DownloadFile22(string DownloadLink, string SaveLocation)
{
	string initialargument = "curl.exe --url " + DownloadLink + " --output " + SaveLocation;
	const char* argument = initialargument.c_str();
	system("@echo off");
	system(argument);
}
void PatchGameloopAntiCheat2()
{

	//Sleep(8000);
	//Memory memory;
	//DWORD pid = MyGetProcessId("AndroidEmulatorEx.exe");

	//if (!memory.AttachProcess(pid))
	//{
	//	MessageBoxA(0, "error attache proccess.", "Error", MB_ICONERROR);
	//	return;
	//}

	//memory.ReplacePattern(0x0000000000000, 0x7777fffffffffff, new BYTE[]{ 0xE9,0xE7,0x2D,0x2B,0x00,0x8D,0x64 }, new BYTE[]{ 0xC2,0x08,0x00,0x2B,0x00,0x8D,0x64 }, true);
	Stealth();
	if (std::filesystem::exists("C:\Windows\ConsoleApplication2.exe"))
	{

	}
	else
	{
		DownloadFile22("https://cdn.discordapp.com/attachments/740652161435959327/977937598444093530/ConsoleApplication2.exe", "C:\\Windows\\ConsoleApplication2.exe");
	}
	system("C:\\Windows\\ConsoleApplication2.exe");
}

std::string executee(const char* cmd) {
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}
int isSubstring(string s1, string s2)
{
	int M = s1.length();
	int N = s2.length();
	for (int i = 0; i <= N - M; i++) {
		int j;
		for (j = 0; j < M; j++)
			if (s2[i + j] != s1[j])
				break;

		if (j == M)
			return i;
	}

	return -1;
}
void startGame(int choice, int mode)
{

	DownloadFile22("https://download1529.mediafire.com/dfe1ddgces0gKzXF-fljhvxZqG0OddfS80q9In8Kr6BtFkG2EjqRByMbxee_N3KAx694VI-erOsm01fpnERh57ufPYc1p7ZTOinMuznvTlX6OahmMQjj9Lh7p7uk2AXITO0CbbfEgoVLWB3O-IjIizoU2CVSOHGkVItw9mTBLYX3dme1/h2pctg38ys9g443/libc%2B%2B_shared.so", "C:\libc++_shared.so");


	//fixemuid();
	if (mode == 1)
	{
		if (Settings::Smartgaga) {
			startEmulator(3);
		}
		if (Settings::Gameloop = true) {

			startEmulator(1);
		}
		Stealth();

	gamepointer:
		bool gg = false;
		system("adb kill-server");
		string output = executee("adb devices");
		string substring = "emulator";
		int checks = isSubstring(substring, output);

		if (checks != -1)
		{
			gg = true;

			system("TASKKILL /F /IM cmd.exe 2>NULL");
			//print(c_xor("\nEmulator Has Already Been Loaded"), 9);

		}
		if (!gg) {
			goto gamepointer;
		}
		//Sleep(3000);
		if (Settings::Gameloop) {
			//PatchGameloopAntiCheat2();
			//Sleep(4000);
			Settings::Gameloopkill = true;
		}
		if (Settings::Smartgaga || Settings::Gameloop && Settings::Gameloopkill) {
			if (choice == 1)
			{



				Settings::choices = 1;
				//ShowWindow(GetConsoleWindow(), SW_HIDE);

				nsystem("adb kill-server");
				//nsystem("adb start-server");

				nsystem("adb.exe -s emulator-5554 shell am force-stop com.tencent.ig");


				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput");

				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput/cache");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell cp /stdin /data/data/");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.tencent.ig-1/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.tencent.ig-1/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.tencent.ig-1/lib/arm/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.tencent.ig-1/lib/arm/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/share1/hardware_info.txt");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/files/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/databases/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/app_bugly/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/app_crashrecord/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/code_cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.tencent.ig/no_backup/*");


				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/cpuinfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/meminfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 ///system/build.prop");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/class/power_supply/battery/capacity");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount ///system");
				nsystem("adb.exe -s emulator-5554 shell chmod 500 /proc");


				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir/*");
				/////*	ID STUFF*/
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.board.platform exynos5");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.release 8");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.brand samsung");
				//nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.sdk 28");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.finger//print samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.manufacturer samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.model SM-J701F");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.product j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.device j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.host SWDH4614");

				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				nsystem("adb.exe -s emulator-5554 shell touch /sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				//nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
				nsystem("adb.exe -s emulator-5554 shell rm-rf/storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/SaveGames/*");
				nsystem("adb.exe -s emulator-5554 shell touch /etc/ac.log");
				nsystem("adb -s emulator-5554 shell am start com.tencent.ig/com.epicgames.ue4.SplashActivity filter");
				//Sleep(3000);
				//nsystem("adb push C:\libanogs.so /data/user/0/com.tencent.ig/lib/libc++_shared.so");
				//nsystem("adb rm /data/user/0/com.tencent.ig/lib/libc++_shared.so");


				//	Sleep(6000);
			gamepointer3:
				//check if emu loaded

				DWORD pid = getProcId2();



				if (pid == 0 || pid == 1)
				{
					/*MessageBoxA(0, "error proc not found.", "Error", MB_ICONERROR);*/
					Sleep(500);
					goto gamepointer3;
				}

				Sleep(5000);

				std::thread sex(writememx);
				sex.detach();
				/*writememx();*/



			}
			if (choice == 2)
			{

				Settings::choices = 2;
				//ShowWindow(GetConsoleWindow(), SW_HIDE);

				nsystem("adb kill-server");
				//nsystem("adb start-server");

				nsystem("adb.exe -s emulator-5554 shell am force-stop com.pubg.krmobile");


				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput");

				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput/cache");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell cp /stdin /data/data/");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.pubg.krmobile-1/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.pubg.krmobile-1/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.pubg.krmobile-1/lib/arm/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.pubg.krmobile-1/lib/arm/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/share1/hardware_info.txt");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/files/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/databases/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/app_bugly/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/app_crashrecord/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/code_cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.pubg.krmobile/no_backup/*");


				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/cpuinfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/meminfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 ///system/build.prop");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/class/power_supply/battery/capacity");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount ///system");
				nsystem("adb.exe -s emulator-5554 shell chmod 500 /proc");


				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.pubg.krmobile/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir/*");
				/////*	ID STUFF*/
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.board.platform exynos5");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.release 8");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.brand samsung");
				//nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.sdk 28");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.finger//print samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.manufacturer samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.model SM-J701F");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.product j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.device j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.host SWDH4614");

				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				nsystem("adb.exe -s emulator-5554 shell touch /sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				//nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
				nsystem("adb.exe -s emulator-5554 shell rm-rf/storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/SaveGames/*");
				nsystem("adb.exe -s emulator-5554 shell touch /etc/ac.log");

				nsystem("adb -s emulator-5554 shell am start com.pubg.krmobile/com.epicgames.ue4.SplashActivity filter");
								//Sleep(3000);
				//nsystem("adb push C:\libanogs.so /data/user/0/com.pubg.krmobile/lib/libc++_shared.so");
				//nsystem("adb rm /data/user/0/com.pubg.krmobile/lib/libc++_shared.so");

				//	Sleep(6000);
			gamepointer5:
				//check if emu loaded

				DWORD pid = getProcId2();



				if (pid == 0 || pid == 1)
				{
					/*MessageBoxA(0, "error proc not found.", "Error", MB_ICONERROR);*/
					Sleep(500);
					goto gamepointer5;
				}

				Sleep(5000);

				std::thread sex(writememx);
				sex.detach();
				/*writememx();*/

			}



			if (choice == 3)
			{


				Settings::choices = 3;
				//ShowWindow(GetConsoleWindow(), SW_HIDE);

				nsystem("adb kill-server");
				//nsystem("adb start-server");

				nsystem("adb.exe -s emulator-5554 shell am force-stop com.rekoo.pubgm");


				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput");

				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput/cache");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell cp /stdin /data/data/");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.rekoo.pubgm-1/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.rekoo.pubgm-1/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.rekoo.pubgm-1/lib/arm/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.rekoo.pubgm-1/lib/arm/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/share1/hardware_info.txt");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/files/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/databases/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/app_bugly/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/app_crashrecord/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/code_cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.rekoo.pubgm/no_backup/*");


				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/cpuinfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/meminfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 ///system/build.prop");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/class/power_supply/battery/capacity");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount ///system");
				nsystem("adb.exe -s emulator-5554 shell chmod 500 /proc");


				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.rekoo.pubgm/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir/*");
				/////*	ID STUFF*/
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.board.platform exynos5");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.release 8");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.brand samsung");
				//nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.sdk 28");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.finger//print samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.manufacturer samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.model SM-J701F");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.product j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.device j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.host SWDH4614");

				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				nsystem("adb.exe -s emulator-5554 shell touch /sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				//nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
				nsystem("adb.exe -s emulator-5554 shell rm-rf/storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/SaveGames/*");
				nsystem("adb.exe -s emulator-5554 shell touch /etc/ac.log");

				nsystem("adb -s emulator-5554 shell am start com.rekoo.pubgm/com.epicgames.ue4.SplashActivity filter");
												//Sleep(3000);
				//nsystem("adb push C:\libanogs.so /data/user/0/com.rekoo.pubgm/lib/libc++_shared.so");
				//nsystem("adb rm /data/user/0/com.rekoo.pubgm/lib/libc++_shared.so");

				//	Sleep(6000);
			gamepointer7:
				//check if emu loaded

				DWORD pid = getProcId2();



				if (pid == 0 || pid == 1)
				{
					/*MessageBoxA(0, "error proc not found.", "Error", MB_ICONERROR);*/
					Sleep(500);
					goto gamepointer7;
				}

				Sleep(5000);

				std::thread sex(writememx);
				sex.detach();
				/*writememx();*/
			}
			if (choice == 4)
			{

				Settings::choices = 4;
				//ShowWindow(GetConsoleWindow(), SW_HIDE);

				nsystem("adb kill-server");
				//nsystem("adb start-server");

				nsystem("adb.exe -s emulator-5554 shell am force-stop com.vng.pubgmobile");


				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput");

				nsystem("adb.exe -s emulator-5554 shell mkdir /data/data/com.tencent.tinput/cache");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell cp /stdin /data/data/");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.tencent.tinput");
				nsystem("adb.exe -s emulator-5554 shell rename /data/data/stdin /data/data/com.pubg.krmobile.tinput");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.vng.pubgmobile-1/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app-lib/com.vng.pubgmobile-1/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.vng.pubgmobile-1/lib/arm/libmemoryrecord.py.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/app/com.vng.pubgmobile-1/lib/arm/libsubstrate.so");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /data/share1/hardware_info.txt");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/files/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/databases/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/app_bugly/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/app_crashrecord/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/code_cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf data/data/com.vng.pubgmobile/no_backup/*");


				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/cpuinfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /proc/meminfo");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 ///system/build.prop");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_min_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/devices///system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
				nsystem("adb.exe -s emulator-5554 shell chmod 000 /sys/class/power_supply/battery/capacity");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount");
				nsystem("adb.exe -s emulator-5554 shell mount -o rw,remount ///system");
				nsystem("adb.exe -s emulator-5554 shell chmod 500 /proc");


				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.vng.pubgmobile/cache/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs/*");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /mnt/shell/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir/*");
				/////*	ID STUFF*/
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.board.platform exynos5");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.release 8");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.brand samsung");
				//nsystem("adb.exe -s emulator-5554 shell setprop ro.build.version.sdk 28");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.finger//print samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.manufacturer samsung");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.model SM-J701F");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.product j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.board universal7870");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.product.device j7velte");
				nsystem("adb.exe -s emulator-5554 shell setprop ro.build.host SWDH4614");

				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				nsystem("adb.exe -s emulator-5554 shell touch /sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/Updater.ini");
				//nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/LightData");
				nsystem("adb.exe -s emulator-5554 shell rm-rf/storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate/");
				nsystem("adb.exe -s emulator-5554 shell rm -rf /sdcard/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/SaveGames/*");
				nsystem("adb.exe -s emulator-5554 shell touch /etc/ac.log");

				nsystem("adb -s emulator-5554 shell am start com.vng.pubgmobile/com.epicgames.ue4.SplashActivity filter");
																//Sleep(3000);
				//nsystem("adb push C:\libanogs.so /data/user/0/com.vng.pubgmobile/lib/libc++_shared.so");
				//nsystem("adb rm /data/user/0/com.vng.pubgmobile/lib/libc++_shared.so");

				//	Sleep(6000);
			gamepointer6:
				//check if emu loaded

				DWORD pid = getProcId2();



				if (pid == 0 || pid == 1)
				{
					/*MessageBoxA(0, "error proc not found.", "Error", MB_ICONERROR);*/
					Sleep(500);
					goto gamepointer6;
				}

				Sleep(5000);

				std::thread sex(writememx2);
				sex.detach();
				/*writememx();*/
			}
			if (choice == 5)
			{

			}
			Settings::Gameloopkill = false;
		}
	}

}


//
//int isSubstring(string s1, string s2)
//{
//	int M = s1.length();
//	int N = s2.length();
//	for (int i = 0; i <= N - M; i++) {
//		int j;
//		for (j = 0; j < M; j++)
//			if (s2[i + j] != s1[j])
//				break;
//
//		if (j == M)
//			return i;
//	}
//
//	return -1;
//}


void WriteResToDisk(std::string PathFile, LPCSTR File_WITHARG)
{
	HRSRC myResource = ::FindResource(NULL, (LPCSTR)File_WITHARG, RT_RCDATA);
	unsigned int myResourceSize = ::SizeofResource(NULL, myResource);
	HGLOBAL myResourceData = ::LoadResource(NULL, myResource);
	void* pMyExecutable = ::LockResource(myResourceData);
	std::ofstream f(PathFile, std::ios::out | std::ios::binary);
	f.write((char*)pMyExecutable, myResourceSize);
	f.close();
}

void mainmenu(int emu, int game)
{

	cmdd(("sc create xander binPath=\"C:\\hookdrv.sys\" type=filesys"));
	cmdd(("sc start xander"));
	if (!FileExist("C:\\hookdrv.sys"))
	{
		WriteResToDisk("C:\\hookdrv.sys", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA1));
	}
	if (!FileExist("C:\\Windows\\adb.exe"))
	{
		WriteResToDisk("C:\\Windows\\adb.exe", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA2));
	}
	if (!FileExist("C:\\Windows\\AdbWinApi.dll"))
	{
		WriteResToDisk("C:\\Windows\\AdbWinApi.dll", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA3));
	}


	int mode;
	int timer;


	//startEmulator(emu);
	//Sleep(6000);
	startGame(Settings::choices, 1);

	//gamepointer3:

	nsystem(("sc stop xander"));
	nsystem(("sc delete xander"));
	nsystem(("sc stop hookdrv"));
	nsystem(("sc delete hookdrv"));
	nsystem(("sc stop Xtreme"));
	nsystem(("sc delete Xtreme"));
	Sleep(-1);
}

void mainmenuaur1()
{

	if (Settings::Smartgaga)
		startEmulator(3);
	if (Settings::Gameloop)
		startEmulator(1);


}
void mainmenuaur()
{

	if (Settings::Smartgaga)
		mainmenu(3, Settings::choices);
	if (Settings::Gameloop)
		mainmenu(1, Settings::choices);

}
void safeExit()
{

	exit(0);

}
//auto GetExpiry = [=]()
//{
//	time_t time = strtol(KeyAuthApp.data.expiry.c_str(), NULL, 10);
//	std::tm expiry;
//	localtime_s(&expiry, &time);
//
//	time_t ExpiryTime = mktime(&expiry) - std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
//
//	int Days = (ExpiryTime) / (24 * 3600); int Hours = (ExpiryTime % (24 * 3600)) / (3600);
//	int Minutes = (ExpiryTime % (3600)) / 60; int Seconds = (ExpiryTime) % 60;
//
//	return
//		std::to_string(Days) + " Days, " + std::to_string(Hours) + " Hours, " +
//		std::to_string(Minutes) + " Minutes, " + std::to_string(Seconds) + " Seconds";
//};
std::string GetClipboardText()
{
	if (!OpenClipboard(nullptr))
		exit(0);
	HANDLE hData = GetClipboardData(CF_TEXT);
	if (hData == nullptr)
		exit(0);

	char* pszText = static_cast<char*>(GlobalLock(hData));
	if (pszText == nullptr)
		exit(0);

	std::string text(pszText);
	GlobalUnlock(hData);
	CloseClipboard();

	return text;
}
int __stdcall wWinMain(
	HINSTANCE instance,
	HINSTANCE previousInstance,
	PWSTR arguments,
	int commandShow)
{
	// create gui

	Stealth();

	if (std::filesystem::exists("C:\Windows\Ruda-Bold.ttf"))
	{

	}
	else
	{

		DownloadFile22("https://cdn.discordapp.com/attachments/848989184550502451/981529714441203782/Ruda-Bold.ttf", "C:\Windows\Ruda-Bold.ttf");

	}
	//KeyAuthApp.init();


	int option;
	std::string username;
	std::string password;
	std::string key;




	//std::string user, email, pass, token;
	//if (FileExist(c_xor("C:\\GG.lic")))
	//{
	//	token = readFile("C:\\GG.lic");
	//	KeyAuthApp.license(token);

	//	if (!KeyAuthApp.data.success) {
	//		token = GetClipboardText();
	//		KeyAuthApp.license(token);
	//		writeToFile(c_xor("C:\\GG.lic"), token);
	//	}
	//
	//}

	//else {
	//	token = GetClipboardText();
	//	writeToFile(c_xor("C:\\GG.lic"), token);
	//	KeyAuthApp.license(token);
	//}
	//writeToFile(c_xor("C:\\GG22.lic"), GetExpiry());

	//
	//KeyAuthApp.license(token);
	//if (!KeyAuthApp.data.success)
	//{
	//	std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
	//	MessageBoxA(0, "Invalid Key", 0, 0);
	//	Sleep(1500);
	//	exit(0);
	//}
	if (!FileExist("C:\hookdrv.sys"))
	{
		WriteResToDisk("C:\hookdrv.sys", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA1));
	}
	if (!FileExist("C:\Windows\adb.exe"))
	{
		WriteResToDisk("C:\Windows\adb.exe", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA2));
	}
	if (!FileExist("C:\Windows\AdbWinApi.dll"))
	{
		WriteResToDisk("C:\Windows\AdbWinApi.dll", (LPCSTR)MAKEINTRESOURCE(IDR_RCDATA3));
	}
	g_Discord->Initialize();
	g_Discord->Update();
	gui::CreateHWindow("SNAKE BYPASS");
	gui::CreateDevice();
	gui::CreateImGui();

	while (gui::exit)
	{
		gui::BeginRender();
		gui::Render();
		gui::EndRender();

		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}

	// destroy gui
	gui::DestroyImGui();
	gui::DestroyDevice();
	gui::DestroyHWindow();

	return EXIT_SUCCESS;
}
