#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>

#define RETURN return

wchar_t NtosVersionName[4][128] = { L"\\??\\C:\\Windows\\System32\\ntoskrnl.exe",		//单处理器，不支持PAE
L"\\??\\C:\\WINDOWS\\system32\\ntkrnlpa.exe",											//单处理器，支持PAE
L"\\??\\C:\\WINDOWS\\system32\\ntkrnlmp.exe",											//多处理器，不支持PAE
L"\\??\\C:\\WINDOWS\\system32\\ntkrpamp.exe" };											//多处理器，支持PAE

wchar_t NtNtdll[] = L"\\SystemRoot\\system32\\ntdll.dll";								//ntdll的绝对地址

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

extern __declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;	//从ntoskrnl导出来的SSDT表

USHORT NtosVersion;																		//用来记录当前内核的版本号。

ULONG OldImageBase;																		//得到原本的系统基址

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
	PBYTE Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_MODULE_INFO_LIST
{
	ULONG ulCount;
	SYSTEM_MODULE_INFORMATION smi[1];
} SYSTEM_MODULE_INFO_LIST, *PSYSTEM_MODULE_INFO_LIST;

typedef struct _ZTY
{
	CHAR  FunctionName[20];											//函数的名称										
	ULONG OldAddress;												//SSDT的原本的地址，也就是我们新开的ntoskrnl的SSDT的地址，SSDT是包含在ntoskrnl里面的。
	ULONG NewAddress;												//SSDT的新的地址
	BOOLEAN Hook;													//判断是否被HOOK的东西。
}ZTY, *PZTY;

typedef struct _ZTYLIST
{
	LIST_ENTRY list_entry;
	ULONG i;														//在SSDT里面的数组的下标。
	ZTY message;
}ZTYLIST, *PZTYLIST;												//这个模块用来保存所有被hook的函数的信息

LIST_ENTRY ListEntry;

KSPIN_LOCK SpinLock;

ZTY GodMe[500];														//经过测试，win7-32有401个，win10-32有455个，为了避免兼容问题这里定义500个。

extern NTSTATUS __stdcall ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

void PageProtectOff()//关闭页面保护
{
	__asm {
		cli
		mov  eax, cr0
		and  eax, not 10000h					//把第17位置0，17位是页面保护位，这一位为1代表不允许进行操作
		mov  cr0, eax
	}
}

void PageProtectOn()//打开页面保护
{
	__asm {
		mov  eax, cr0
		or eax, 10000h							//把第17位置1，打开页面保护，让别人不允许修改。
		mov  cr0, eax
		sti
	}
}

LONG TurnRvaIntoRaw(PIMAGE_NT_HEADERS temp, LONG Rva)
{
	INT NumbersOfSections = temp->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(temp);
	for (int i = 0; i < NumbersOfSections; ++i)
	{
		LONG StartAddress = SectionHeader->VirtualAddress;						//这里是区块的开始地址
		LONG EndAddress = StartAddress + SectionHeader->Misc.VirtualSize;		//这里是区块的终止地址
		if (Rva >= StartAddress && Rva <= EndAddress)
			RETURN Rva - StartAddress + SectionHeader->PointerToRawData;
		++SectionHeader;
	}
	RETURN 0;
}

NTSTATUS GetKernelModuleInfo()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSYSTEM_MODULE_INFO_LIST pSysModInfoList = NULL;
	ULONG ulLength = 0;

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysModInfoList, ulLength, &ulLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return STATUS_UNSUCCESSFUL;
	}

	pSysModInfoList = (PSYSTEM_MODULE_INFO_LIST)ExAllocatePool(NonPagedPool, ulLength);
	if (NULL == pSysModInfoList)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysModInfoList, ulLength, &ulLength);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pSysModInfoList);
		return STATUS_UNSUCCESSFUL;
	}

	OldImageBase = (ULONG)pSysModInfoList->smi[0].Base;  //得到当前内核的基址

	if (strstr(pSysModInfoList->smi[0].ImageName, "ntoskrnl.exe"))
	{
		NtosVersion = 0;
	}
	else if (strstr(pSysModInfoList->smi[0].ImageName, "ntkrnlpa.exe"))
	{
		NtosVersion = 1;
	}
	else if (strstr(pSysModInfoList->smi[0].ImageName, "ntkrnlmp.exe"))
	{
		NtosVersion = 2;
	}
	else if (strstr(pSysModInfoList->smi[0].ImageName, "ntkrpamp.exe"))
	{
		NtosVersion = 3;
	}
	ExFreePool(pSysModInfoList);

	return STATUS_SUCCESS;
}

NTSTATUS InitSSDTName()													//初始化所有SSDT函数的名字
{
	IO_STATUS_BLOCK				IoBlock;								//函数的IO状态
	NTSTATUS					status;									//函数返回的状态
	HANDLE						FileHandle;								//文件的句柄
	OBJECT_ATTRIBUTES			FileAttributes;							//文件的属性
	UNICODE_STRING				FileName;								//文件的名字
	FILE_STANDARD_INFORMATION	FileInformation;						//文件的所有信息
	LARGE_INTEGER				ReadBytes;								//看错了，这里不是返回读取的字符数而是偏移量，从哪个位置开始读取
	ReadBytes.HighPart = ReadBytes.LowPart = 0;							//把楼上的变量初始化一下。。

	RtlInitUnicodeString(&FileName, NtNtdll);

	InitializeObjectAttributes(&FileAttributes,
		&FileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	status = ZwCreateFile(&FileHandle,
		GENERIC_READ | SYNCHRONIZE,										//SYNCHRONIZE表示同步操作
		&FileAttributes,
		&IoBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,			//FILE_SYNCHARONOUS_IO_NONALERT表示让文件读取的时候一次读完再返回而不是返回Pending
		NULL,
		0
	);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("打开Ntdll失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	status = ZwQueryInformationFile(FileHandle,
		&IoBlock,
		&FileInformation,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwQueryInofmationFile失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	//EndOfFile是指文件结尾字符的偏移，就是文件的大小，微软这群人时常不说人话。。。由于这个结构是一个64位的结构因此划分为两个32位的LONG变量，如果高地址不为0说明文件超过2^32次方字节即4G。不予读取。。。
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		KdPrint(("文件过大，加载失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	CHAR *FileContent = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, FileInformation.EndOfFile.LowPart, 'ytz');
	//分配对应大小的内存出来，接下来的事情跟应用层没太大差距了。
	ULONG FileSize = FileInformation.EndOfFile.LowPart;

	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, (PVOID)FileContent, sizeof(IMAGE_DOS_HEADER), &ReadBytes, NULL);

	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, (PVOID)FileContent, FileSize, &ReadBytes, NULL);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(FileContent);
		KdPrint(("ReadFile失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER*)FileContent;
	if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(FileContent + DosHeader->e_lfanew);
		if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			if (NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size <= 0)
			{
				KdPrint(("导出表为空！\n"));
				RETURN STATUS_UNSUCCESSFUL;
			}
			IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(FileContent + TurnRvaIntoRaw(NtHeader, NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
			USHORT * NameOridinals = (USHORT *)(FileContent + TurnRvaIntoRaw(NtHeader, ExportDirectory->AddressOfNameOrdinals));
			ULONG  * NameAddress = (ULONG *)(FileContent + TurnRvaIntoRaw(NtHeader, ExportDirectory->AddressOfNames));
			ULONG  * FunctionAddress = (ULONG *)(FileContent + TurnRvaIntoRaw(NtHeader, ExportDirectory->AddressOfFunctions));
			ULONG	 NumberOfNameFunction = ExportDirectory->NumberOfNames;

			//上面的四个元素前三个代表数组，具体什么意思要看我整理的东西了，第四个是表示用名字导出的函数的数目
			for (ULONG i = 0; i < NumberOfNameFunction; ++i)
			{
				CHAR *FunctionName = (CHAR *)(FileContent + TurnRvaIntoRaw(NtHeader, NameAddress[i]));
				ULONG *Function = (ULONG*)(FileContent + TurnRvaIntoRaw(NtHeader, FunctionAddress[NameOridinals[i]]));			//这里是找到函数在文件中的具体位置
				if (FunctionName[0] == 'Z' && FunctionName[1] == 'w')
				{
					FunctionName[0] = 'N';
					FunctionName[1] = 't';
					ULONG FunctionInSSDT = *(ULONG *)((ULONG)Function + 1);												//把函数地址加1跳过mov eax指令获取的就是该函数在SSDT的地址。
																														//KdPrint(("%s在SSDT的标号为%lu\n", FunctionName, FunctionInSSDT));
					strncpy(GodMe[FunctionInSSDT].FunctionName, FunctionName, 15 * sizeof(CHAR));
				}
			}
		}
		else
		{
			KdPrint(("不是PE文件，读取错误！\n"));
			RETURN STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		KdPrint(("不是PE文件，读取错误！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	ExFreePool(FileContent);
	status = ZwClose(FileHandle);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("CloseHandle失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	RETURN STATUS_SUCCESS;
}

NTSTATUS InitSSDT()													//初始化其他的SSDT的信息,这个函数跟InitSSDTName大体上没有差别，区别在于一个是ntdll一个是ntoskrnl
{
	IO_STATUS_BLOCK				IoBlock;								//函数的IO状态
	NTSTATUS					status;									//函数返回的状态
	HANDLE						FileHandle;								//文件的句柄
	OBJECT_ATTRIBUTES			FileAttributes;							//文件的属性
	UNICODE_STRING				FileName;								//文件的名字
	FILE_STANDARD_INFORMATION	FileInformation;						//文件的所有信息
	LARGE_INTEGER				ReadBytes;								//看错了，这里不是返回读取的字符数而是偏移量，从哪个位置开始读取
	ReadBytes.HighPart = ReadBytes.LowPart = 0;							//把楼上的变量初始化一下。。

	RtlInitUnicodeString(&FileName, NtosVersionName[NtosVersion]);

	InitializeObjectAttributes(&FileAttributes,
		&FileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	status = ZwCreateFile(&FileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&FileAttributes,
		&IoBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("打开%s失败！\n", NtosVersionName[NtosVersion]));
		RETURN STATUS_UNSUCCESSFUL;
	}

	status = ZwQueryInformationFile(FileHandle,
		&IoBlock,
		&FileInformation,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwQueryInofmationFile失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	//EndOfFile是指文件结尾字符的偏移，就是文件的大小，微软这群人时常不说人话。。。由于这个结构是一个64位的结构因此划分为两个32位的LONG变量，如果高地址不为0说明文件超过2^32次方字节即4G。不予读取。。。
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		KdPrint(("文件过大，加载失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	CHAR *FileContent = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, FileInformation.EndOfFile.LowPart, 'ytz');

	ULONG FileSize = FileInformation.EndOfFile.LowPart;

	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, (PVOID)FileContent, FileSize, &ReadBytes, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ReadFile失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER*)FileContent;
	if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)(FileContent + DosHeader->e_lfanew);
		if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			CHAR *PE = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, NtHeader->OptionalHeader.SizeOfImage, 'ytz');
			memcpy(PE, FileContent, NtHeader->OptionalHeader.SizeOfHeaders);
			IMAGE_SECTION_HEADER * SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
			for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
				memcpy(PE + SectionHeader->VirtualAddress, FileContent + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);

			ServiceDescriptorTableEntry_t *NewSSDT = (ServiceDescriptorTableEntry_t *)((ULONG)&KeServiceDescriptorTable - OldImageBase + (ULONG)PE);
			NewSSDT->ServiceTableBase = (ULONG *)((ULONG)KeServiceDescriptorTable.ServiceTableBase - OldImageBase + (ULONG)PE);
			//这里有一个坑，原本我觉得只需要计算SSDT表的偏移即可，后来发现SST表也需要计算偏移，最后发现表内函数也需要计算偏移。。。。

			for (ULONG i = 0; i < KeServiceDescriptorTable.NumberOfServices; ++i)
			{
				NewSSDT->ServiceTableBase[i] = NewSSDT->ServiceTableBase[i] - NtHeader->OptionalHeader.ImageBase + OldImageBase;
				//又是一个坑，原本我以为这个偏移是基于PE的起始位置，谁知道是基于模块加载的基址。。。
				//所以这里需要减去模块加载的基址，然后加上OldImage的基址。

				GodMe[i].OldAddress = NewSSDT->ServiceTableBase[i];
				GodMe[i].NewAddress = KeServiceDescriptorTable.ServiceTableBase[i];
				if (GodMe[i].OldAddress == GodMe[i].NewAddress)
					GodMe[i].Hook = FALSE;
				else
					GodMe[i].Hook = TRUE;
			}
			ExFreePoolWithTag(PE, 'ytz');
		}
		else
		{
			KdPrint(("不是PE文件，读取错误！\n"));
			RETURN STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		KdPrint(("不是PE文件，读取错误！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	ExFreePool(FileContent);
	status = ZwClose(FileHandle);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("CloseHandle失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	RETURN STATUS_SUCCESS;
}

BOOLEAN ShowTable()						//把整个表格输出
{
	InitializeListHead(&ListEntry);

	KeInitializeSpinLock(&SpinLock);

	BOOLEAN IsInList = TRUE;

	for (ULONG i = 0; i < KeServiceDescriptorTable.NumberOfServices; ++i)
	{
		if (GodMe[i].Hook)
		{
			KdPrint(("内核模块的基址为：%lu,SSDT表中位置为：%lu的函数为：%s,原地址为：%lu,现在地址为：%lu 该函数被HOOK！\n", OldImageBase, i, GodMe[i].FunctionName, GodMe[i].OldAddress, GodMe[i].NewAddress));
			for (LIST_ENTRY *ListTemp = ListEntry.Flink; ListTemp != &ListEntry; ListTemp = ListTemp->Flink)
			{
				ZTYLIST *ZtyTemp = (ZTYLIST *)ListTemp;
				if (ZtyTemp->i == i)
				{
					IsInList = FALSE;
					break;
				}
			}
			if (IsInList)
			{
				ZTYLIST * ListTemp = (ZTYLIST *)ExAllocatePoolWithTag(NonPagedPool, sizeof(ZTYLIST), 'ytz');
				ListTemp->i = i;
				ListTemp->message = GodMe[i];
				ExInterlockedInsertTailList(&ListEntry, (PLIST_ENTRY)ListTemp, &SpinLock);
			}
			IsInList = TRUE;
		}
		else
			KdPrint(("内核模块的基址为：%lu,SSDT表中位置为：%lu的函数为：%s,原地址为：%lu,现在地址为：%lu 该函数没有HOOK！\n", OldImageBase, i, GodMe[i].FunctionName, GodMe[i].OldAddress, GodMe[i].NewAddress));
	}

	if (!IsListEmpty(&ListEntry))
	{
		KdPrint(("我是分割线-----------------------------------------------------------------------------\n"));

		for (LIST_ENTRY *ListTemp = ListEntry.Flink; ListTemp != &ListEntry; ListTemp = ListTemp->Flink)
		{
			ZTYLIST *ZtyTemp = (ZTYLIST *)ListTemp;
			KdPrint(("被HOOK的函数的为%s,在SSDT表中坐标为：%lu,原地址为：%lu，现地址为：%lu\n", ZtyTemp->message.FunctionName, ZtyTemp->i, ZtyTemp->message.OldAddress, ZtyTemp->message.NewAddress));
		}
		RETURN TRUE;
	}
	RETURN FALSE;
}

VOID ReBackSSDT()
{
	PageProtectOff();							//先把页面保护关掉，否则不能修改SSDT

	while (!IsListEmpty(&ListEntry))
	{
		ZTYLIST * ListTemp = (ZTYLIST *)ExInterlockedRemoveHeadList(&ListEntry, &SpinLock);
		GodMe[ListTemp->i].NewAddress = ListTemp->message.OldAddress;											//SSDT表中的地址进行了修改，我们也需要把我们自己的SSDT表给修改回来。
		GodMe[ListTemp->i].Hook = FALSE;																		//因为这里我们已经把hook给屏蔽掉了所以把这个设置为FALSE
		KeServiceDescriptorTable.ServiceTableBase[ListTemp->i] = ListTemp->message.OldAddress;
		ExFreePool(ListTemp);
	}

	PageProtectOn();
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("成功卸载！\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	DriverObject->DriverUnload = Unload;
	if (!NT_SUCCESS(GetKernelModuleInfo()))
	{
		KdPrint(("获取模块基址失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	if (!NT_SUCCESS(InitSSDTName()))
	{
		KdPrint(("初始化SSDT函数名失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	if (!NT_SUCCESS(InitSSDT()))
	{
		KdPrint(("初始化SSDT失败！\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	if (ShowTable())
	{
		ReBackSSDT();

		ShowTable();
	}
	RETURN STATUS_SUCCESS;
}