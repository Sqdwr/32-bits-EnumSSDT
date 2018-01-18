#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>

#define RETURN return

wchar_t NtosVersionName[4][128] = { L"\\??\\C:\\Windows\\System32\\ntoskrnl.exe",		//������������֧��PAE
L"\\??\\C:\\WINDOWS\\system32\\ntkrnlpa.exe",											//����������֧��PAE
L"\\??\\C:\\WINDOWS\\system32\\ntkrnlmp.exe",											//�ദ��������֧��PAE
L"\\??\\C:\\WINDOWS\\system32\\ntkrpamp.exe" };											//�ദ������֧��PAE

wchar_t NtNtdll[] = L"\\SystemRoot\\system32\\ntdll.dll";								//ntdll�ľ��Ե�ַ

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

extern __declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;	//��ntoskrnl��������SSDT��

USHORT NtosVersion;																		//������¼��ǰ�ں˵İ汾�š�

ULONG OldImageBase;																		//�õ�ԭ����ϵͳ��ַ

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
	CHAR  FunctionName[20];											//����������										
	ULONG OldAddress;												//SSDT��ԭ���ĵ�ַ��Ҳ���������¿���ntoskrnl��SSDT�ĵ�ַ��SSDT�ǰ�����ntoskrnl����ġ�
	ULONG NewAddress;												//SSDT���µĵ�ַ
	BOOLEAN Hook;													//�ж��Ƿ�HOOK�Ķ�����
}ZTY, *PZTY;

typedef struct _ZTYLIST
{
	LIST_ENTRY list_entry;
	ULONG i;														//��SSDT�����������±ꡣ
	ZTY message;
}ZTYLIST, *PZTYLIST;												//���ģ�������������б�hook�ĺ�������Ϣ

LIST_ENTRY ListEntry;

KSPIN_LOCK SpinLock;

ZTY GodMe[500];														//�������ԣ�win7-32��401����win10-32��455����Ϊ�˱�������������ﶨ��500����

extern NTSTATUS __stdcall ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

void PageProtectOff()//�ر�ҳ�汣��
{
	__asm {
		cli
		mov  eax, cr0
		and  eax, not 10000h					//�ѵ�17λ��0��17λ��ҳ�汣��λ����һλΪ1����������в���
		mov  cr0, eax
	}
}

void PageProtectOn()//��ҳ�汣��
{
	__asm {
		mov  eax, cr0
		or eax, 10000h							//�ѵ�17λ��1����ҳ�汣�����ñ��˲������޸ġ�
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
		LONG StartAddress = SectionHeader->VirtualAddress;						//����������Ŀ�ʼ��ַ
		LONG EndAddress = StartAddress + SectionHeader->Misc.VirtualSize;		//�������������ֹ��ַ
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

	OldImageBase = (ULONG)pSysModInfoList->smi[0].Base;  //�õ���ǰ�ں˵Ļ�ַ

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

NTSTATUS InitSSDTName()													//��ʼ������SSDT����������
{
	IO_STATUS_BLOCK				IoBlock;								//������IO״̬
	NTSTATUS					status;									//�������ص�״̬
	HANDLE						FileHandle;								//�ļ��ľ��
	OBJECT_ATTRIBUTES			FileAttributes;							//�ļ�������
	UNICODE_STRING				FileName;								//�ļ�������
	FILE_STANDARD_INFORMATION	FileInformation;						//�ļ���������Ϣ
	LARGE_INTEGER				ReadBytes;								//�����ˣ����ﲻ�Ƿ��ض�ȡ���ַ�������ƫ���������ĸ�λ�ÿ�ʼ��ȡ
	ReadBytes.HighPart = ReadBytes.LowPart = 0;							//��¥�ϵı�����ʼ��һ�¡���

	RtlInitUnicodeString(&FileName, NtNtdll);

	InitializeObjectAttributes(&FileAttributes,
		&FileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	status = ZwCreateFile(&FileHandle,
		GENERIC_READ | SYNCHRONIZE,										//SYNCHRONIZE��ʾͬ������
		&FileAttributes,
		&IoBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,			//FILE_SYNCHARONOUS_IO_NONALERT��ʾ���ļ���ȡ��ʱ��һ�ζ����ٷ��ض����Ƿ���Pending
		NULL,
		0
	);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("��Ntdllʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	status = ZwQueryInformationFile(FileHandle,
		&IoBlock,
		&FileInformation,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwQueryInofmationFileʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	//EndOfFile��ָ�ļ���β�ַ���ƫ�ƣ������ļ��Ĵ�С��΢����Ⱥ��ʱ����˵�˻���������������ṹ��һ��64λ�Ľṹ��˻���Ϊ����32λ��LONG����������ߵ�ַ��Ϊ0˵���ļ�����2^32�η��ֽڼ�4G�������ȡ������
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		KdPrint(("�ļ����󣬼���ʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	CHAR *FileContent = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, FileInformation.EndOfFile.LowPart, 'ytz');
	//�����Ӧ��С���ڴ�������������������Ӧ�ò�û̫�����ˡ�
	ULONG FileSize = FileInformation.EndOfFile.LowPart;

	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, (PVOID)FileContent, sizeof(IMAGE_DOS_HEADER), &ReadBytes, NULL);

	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, (PVOID)FileContent, FileSize, &ReadBytes, NULL);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(FileContent);
		KdPrint(("ReadFileʧ�ܣ�\n"));
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
				KdPrint(("������Ϊ�գ�\n"));
				RETURN STATUS_UNSUCCESSFUL;
			}
			IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(FileContent + TurnRvaIntoRaw(NtHeader, NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
			USHORT * NameOridinals = (USHORT *)(FileContent + TurnRvaIntoRaw(NtHeader, ExportDirectory->AddressOfNameOrdinals));
			ULONG  * NameAddress = (ULONG *)(FileContent + TurnRvaIntoRaw(NtHeader, ExportDirectory->AddressOfNames));
			ULONG  * FunctionAddress = (ULONG *)(FileContent + TurnRvaIntoRaw(NtHeader, ExportDirectory->AddressOfFunctions));
			ULONG	 NumberOfNameFunction = ExportDirectory->NumberOfNames;

			//������ĸ�Ԫ��ǰ�����������飬����ʲô��˼Ҫ��������Ķ����ˣ����ĸ��Ǳ�ʾ�����ֵ����ĺ�������Ŀ
			for (ULONG i = 0; i < NumberOfNameFunction; ++i)
			{
				CHAR *FunctionName = (CHAR *)(FileContent + TurnRvaIntoRaw(NtHeader, NameAddress[i]));
				ULONG *Function = (ULONG*)(FileContent + TurnRvaIntoRaw(NtHeader, FunctionAddress[NameOridinals[i]]));			//�������ҵ��������ļ��еľ���λ��
				if (FunctionName[0] == 'Z' && FunctionName[1] == 'w')
				{
					FunctionName[0] = 'N';
					FunctionName[1] = 't';
					ULONG FunctionInSSDT = *(ULONG *)((ULONG)Function + 1);												//�Ѻ�����ַ��1����mov eaxָ���ȡ�ľ��Ǹú�����SSDT�ĵ�ַ��
																														//KdPrint(("%s��SSDT�ı��Ϊ%lu\n", FunctionName, FunctionInSSDT));
					strncpy(GodMe[FunctionInSSDT].FunctionName, FunctionName, 15 * sizeof(CHAR));
				}
			}
		}
		else
		{
			KdPrint(("����PE�ļ�����ȡ����\n"));
			RETURN STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		KdPrint(("����PE�ļ�����ȡ����\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	ExFreePool(FileContent);
	status = ZwClose(FileHandle);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("CloseHandleʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	RETURN STATUS_SUCCESS;
}

NTSTATUS InitSSDT()													//��ʼ��������SSDT����Ϣ,���������InitSSDTName������û�в����������һ����ntdllһ����ntoskrnl
{
	IO_STATUS_BLOCK				IoBlock;								//������IO״̬
	NTSTATUS					status;									//�������ص�״̬
	HANDLE						FileHandle;								//�ļ��ľ��
	OBJECT_ATTRIBUTES			FileAttributes;							//�ļ�������
	UNICODE_STRING				FileName;								//�ļ�������
	FILE_STANDARD_INFORMATION	FileInformation;						//�ļ���������Ϣ
	LARGE_INTEGER				ReadBytes;								//�����ˣ����ﲻ�Ƿ��ض�ȡ���ַ�������ƫ���������ĸ�λ�ÿ�ʼ��ȡ
	ReadBytes.HighPart = ReadBytes.LowPart = 0;							//��¥�ϵı�����ʼ��һ�¡���

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
		KdPrint(("��%sʧ�ܣ�\n", NtosVersionName[NtosVersion]));
		RETURN STATUS_UNSUCCESSFUL;
	}

	status = ZwQueryInformationFile(FileHandle,
		&IoBlock,
		&FileInformation,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwQueryInofmationFileʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	//EndOfFile��ָ�ļ���β�ַ���ƫ�ƣ������ļ��Ĵ�С��΢����Ⱥ��ʱ����˵�˻���������������ṹ��һ��64λ�Ľṹ��˻���Ϊ����32λ��LONG����������ߵ�ַ��Ϊ0˵���ļ�����2^32�η��ֽڼ�4G�������ȡ������
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		KdPrint(("�ļ����󣬼���ʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	CHAR *FileContent = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, FileInformation.EndOfFile.LowPart, 'ytz');

	ULONG FileSize = FileInformation.EndOfFile.LowPart;

	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoBlock, (PVOID)FileContent, FileSize, &ReadBytes, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ReadFileʧ�ܣ�\n"));
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
			//������һ���ӣ�ԭ���Ҿ���ֻ��Ҫ����SSDT���ƫ�Ƽ��ɣ���������SST��Ҳ��Ҫ����ƫ�ƣ�����ֱ��ں���Ҳ��Ҫ����ƫ�ơ�������

			for (ULONG i = 0; i < KeServiceDescriptorTable.NumberOfServices; ++i)
			{
				NewSSDT->ServiceTableBase[i] = NewSSDT->ServiceTableBase[i] - NtHeader->OptionalHeader.ImageBase + OldImageBase;
				//����һ���ӣ�ԭ������Ϊ���ƫ���ǻ���PE����ʼλ�ã�˭֪���ǻ���ģ����صĻ�ַ������
				//����������Ҫ��ȥģ����صĻ�ַ��Ȼ�����OldImage�Ļ�ַ��

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
			KdPrint(("����PE�ļ�����ȡ����\n"));
			RETURN STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		KdPrint(("����PE�ļ�����ȡ����\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}

	ExFreePool(FileContent);
	status = ZwClose(FileHandle);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("CloseHandleʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	RETURN STATUS_SUCCESS;
}

BOOLEAN ShowTable()						//������������
{
	InitializeListHead(&ListEntry);

	KeInitializeSpinLock(&SpinLock);

	BOOLEAN IsInList = TRUE;

	for (ULONG i = 0; i < KeServiceDescriptorTable.NumberOfServices; ++i)
	{
		if (GodMe[i].Hook)
		{
			KdPrint(("�ں�ģ��Ļ�ַΪ��%lu,SSDT����λ��Ϊ��%lu�ĺ���Ϊ��%s,ԭ��ַΪ��%lu,���ڵ�ַΪ��%lu �ú�����HOOK��\n", OldImageBase, i, GodMe[i].FunctionName, GodMe[i].OldAddress, GodMe[i].NewAddress));
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
			KdPrint(("�ں�ģ��Ļ�ַΪ��%lu,SSDT����λ��Ϊ��%lu�ĺ���Ϊ��%s,ԭ��ַΪ��%lu,���ڵ�ַΪ��%lu �ú���û��HOOK��\n", OldImageBase, i, GodMe[i].FunctionName, GodMe[i].OldAddress, GodMe[i].NewAddress));
	}

	if (!IsListEmpty(&ListEntry))
	{
		KdPrint(("���Ƿָ���-----------------------------------------------------------------------------\n"));

		for (LIST_ENTRY *ListTemp = ListEntry.Flink; ListTemp != &ListEntry; ListTemp = ListTemp->Flink)
		{
			ZTYLIST *ZtyTemp = (ZTYLIST *)ListTemp;
			KdPrint(("��HOOK�ĺ�����Ϊ%s,��SSDT��������Ϊ��%lu,ԭ��ַΪ��%lu���ֵ�ַΪ��%lu\n", ZtyTemp->message.FunctionName, ZtyTemp->i, ZtyTemp->message.OldAddress, ZtyTemp->message.NewAddress));
		}
		RETURN TRUE;
	}
	RETURN FALSE;
}

VOID ReBackSSDT()
{
	PageProtectOff();							//�Ȱ�ҳ�汣���ص����������޸�SSDT

	while (!IsListEmpty(&ListEntry))
	{
		ZTYLIST * ListTemp = (ZTYLIST *)ExInterlockedRemoveHeadList(&ListEntry, &SpinLock);
		GodMe[ListTemp->i].NewAddress = ListTemp->message.OldAddress;											//SSDT���еĵ�ַ�������޸ģ�����Ҳ��Ҫ�������Լ���SSDT����޸Ļ�����
		GodMe[ListTemp->i].Hook = FALSE;																		//��Ϊ���������Ѿ���hook�����ε������԰��������ΪFALSE
		KeServiceDescriptorTable.ServiceTableBase[ListTemp->i] = ListTemp->message.OldAddress;
		ExFreePool(ListTemp);
	}

	PageProtectOn();
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("�ɹ�ж�أ�\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	DriverObject->DriverUnload = Unload;
	if (!NT_SUCCESS(GetKernelModuleInfo()))
	{
		KdPrint(("��ȡģ���ַʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	if (!NT_SUCCESS(InitSSDTName()))
	{
		KdPrint(("��ʼ��SSDT������ʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	if (!NT_SUCCESS(InitSSDT()))
	{
		KdPrint(("��ʼ��SSDTʧ�ܣ�\n"));
		RETURN STATUS_UNSUCCESSFUL;
	}
	if (ShowTable())
	{
		ReBackSSDT();

		ShowTable();
	}
	RETURN STATUS_SUCCESS;
}