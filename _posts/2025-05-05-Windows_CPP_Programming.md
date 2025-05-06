---
layout: post
title:  "Dynamic Function Resolution without the CRT."
date:   2025-05-02 00:23:21 -0500
categories: Windows Shellcoding
---

 

Windows is one of the most complicated operating systems out there, it's convoluted, bloated, and more importantly, it's very fun. The Linux people with their Emacs and 46 tmux sessions can sit this one out.


In this blog post, I'll explore a bit of Windows programming. Specifically, I'll be looking into making a small .exe(Portable Executable) file that:


{% highlight cpp %}
I. Launches a process (cmd.exe).
II. Configures a Pipe for IPC(InterProcessCommunication) to said process.
III. Makes the cmd.exe execute an echo command -> echo Hello from CRT-Free Parent!
IV. After which, it will go back into the void by executing the Exit command.
{% endhighlight %}




The thing is,  I'll be doing all of this, without any of the helpers that we normally have.\\
So, no strcmp, no strlen, no easy money, CreateProcessA/W/Ex linked to the binary.


The binary will be empty on imports, at least when it sits on the disk. The O.S loader, when it maps the exe into memory, will load copies of a couple of Dll's for us.
![IDA_IMPORTS](/assets/images/B1/importnada.png){:.img-medium}


Nothing will be referenced from said DLLs statically. I will be dynamically resolving these functions at runtime, w/o any obfuscation, and using some compiler intrinsics (Nerd Speak for forcing the compiler to spit out specific assembly instructions).


This is also known as making a position independent binary/code. Why position independent, well, it just means that I can place it anywhere in memory, and it'll run and do its job. This is something to yearn for(!ha), by people doing exploit development or Malware development. Take the case of exploit development, let's say you find a buffer overrun that overwrites the return pointer of some function on the stack, and now you can reroute execution to some random place, or you can run raw assembly at the point of overwrite.


But you now have found yourself in the situation where you don't know where in memory you are, courtesy of ASLR. Simply put, you want to set up variables and make some system calls and achieve some random objective.
<br>
You can totally set up the variables with assembly, but, in order to do something useful, you almost certainly have to make system calls, unless you've found some insane exploit that gets the kernel to read your userland code directly and you know where everything is at all times across all versions of windows. If you're omniscient like that, let me know, I've got a couple of questions.
<br>
But where are these system calls, and how do you make them?<br>
 Well, am I glad you didn't ask. In the case of Windows, they operate with the concept of SSN, or System Service Numbers. Right before doing the SYSCALL/SYSENTER/int 0x2e instruction, a set of instructions loads a specific number into the eax register, that number corresponds to the routine you want the kernel to run for you.
<br>
The syscall instruction tells the CPU to, among other things, save some of the current user mode states, read the MSR (which is just a register that is configured at bootup to point to a specific location, I'm almost sure it's the MSR_LSTAR). This MSR register points to kernel routines to execute system calls with KiSystemCall/kiFastSystemCall. The CPU then sets the IP to the address read from the MSR, and the handler takes over, reading the number in eax, which contains the SSN.
<br>
The SSN is like an index to the SSDT (System Service Descriptor Table), it's an array of function pointers.
The kernel handler copies the arguments from the usermode registers and stacks to where the kernel expects them, and then calls the routine pointed to by the array.


Post execution, it returns the status or return value to the volatile registers, does the sysexit, and transitions back to user mode.


But to us, they are just functions located in the DLL's , that provide the above functionality for you, the user, who is often hostile and a borderline caveman.


During the compile+linking voodoo, the program you write is translated to the final executable that you can run. There are place holders that are put in areas where the function call is supposed to take place, this is done by the front end and IL portion of the process(I think). When the back end/linking has to be done, for a specific target, the linker decides to "link" the placeholder, and put the directive in that says, from dll x, import function y, and call the imported function. This is called dynamic linking. The compiler generates code that will call through these address table entries, which get filled in at load time.


 The order of function call is usually like this:<br>
 Function in your favorite DLL -> The abyss -> NTDLL.DLL -> Transition -> Kernel code. <br>
 All roads lead to NTDLL.DLL(Almost).


Why would I want to do this, you ask? The answer is... PAIN. Ok, not really, it's that I got curious about how these malware developers go about doing what they do. If you've ever done Malware Reverse Engineering, you'd notice that a lot of the binaries you find, the imports are either junk or straight up nonexistent.


Here is a flavour of the ReVil ransomware circa 2020 that does function resolution.


![IAT_RESOLVE](/assets/images/B1/IAT_Resolve.png){:.img-medium}


The initial binary doesn't have much, as he decided to pack his binary with.. another binary. This Developer encrypted his secondary binary/payload using RC4 within the data section, decrypted it at runtime, dropped it in memory.
So he needed to resolve imports, aka functions, for the in-memory payload/exe.




![DECRYPT](/assets\images\B1\RC4DECRYPT.png){:.img-medium}




He has called this function 119 times, meaning he resolved 119 unique functions by walking the IAT to first get a few important functions. Using encrypted strings within the payload,
initializing RC4 SBOXs each time he wants to get a string of the function to find. They decide the key by offsets within the blob of encrypted text that will resolve to valid function names, post which they load the library using the LoadLibrary function. He ends up getting the in memory address of the function either by walking the DLL manually or by using the handy GetProcAddress function after loading the library, and then proceeds to encrypt your files, of course.


One way to find functions is to walk the PEB/TEB, which, if you've never encountered it before, is just something that every Windows userland process has. You can think about this structure as something that the Windows kernel uses to keep track of what the process owns, things like stack range, heaps that the process owns, debugging information and 17500 other things.


It is a very complicated structure; here are just a few fields that make it up.


{% highlight cpp %}
//0x250 bytes (sizeof)
struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsLegacyProcess:1;                                        //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR SpareBits:1;                                              //0x3
        };
    };
    VOID* Mutant;                                                           //0x4
    VOID* ImageBaseAddress;                                                 //0x8
    struct _PEB_LDR_DATA* Ldr;                                              //0xc
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
    VOID* SubSystemData;                                                    //0x14
    VOID* ProcessHeap;                                                      //0x18
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
    VOID* AtlThunkSListPtr;                                                 //0x20
    VOID* IFEOKey;


    .......................


    ....


{% endhighlight %}


The fields are either constants that can change with Windows versions, or are pointers that link to other structures, that in turn link to other structures, that in turn link to.... You get the idea.
We will be traversing the _PEB_LDR_DATA data. The above snippet, taken from Vergiliusproject, is for Windows 8. The same concept across all versions of Windows, so doing it this way is a little portable as well.


Technically "The PEB and TEB is a per-process/thread data structure that resides in memory, contain information, and is a fundamental data structure that hold process and thread-specific information. The PEB contains global process data, while the TEB stores thread-specific data and a pointer to the PEB."
According to MSDN, this field of the PEB described as "A pointer to a PEB_LDR_DATA structure that contains information about the loaded modules for the process.".


In our use case, however, we can access this structure by using something known as the segment register, in a 64-bit context its the GS:[0x60] and in the 32 bit context it FS:[0x30].
These segment registers are valid in userland, and, interestingly, even in the kernel space, they switch up to kernel representations of the process, with E/KPROCESS and E/KTHREAD, they are known as Opaque Structures, and the references change when a syscall is made (PreviousMode & CR bits, I think). This topic alone can be mad as a whole box of frogs. I'll leave that up for later to describe it in more detail. However, if youre an impatient man/woman/spacemarine, you can check out this guys blog [Connor Mcgarr](https://connormcgarr.github.io/) or this mans entire youtube channel [Offbyone](https://www.youtube.com/@OffByOneSecurity) or [OALBS](https://www.youtube.com/OALABs) or [Alexander Borges](https://exploitreversing.com/) or these peoples content [Yarden Shafir](https://windows-internals.com/author/yarden/), [Chompie](https://x.com/chompie1337?lang=en). There are a lot of incredible people working in this space, I can't even list them all.








Okay, jumping to the code, which is presumably what you're here for.










This is the core, this is what we would care about, this is also what is signatured to death, i.e, if your binary is doing this or something like this without any obfuscation, it's GG.


{%highlight cpp%}
int ResolveFuncsByHashInModule(HMODULE hModule, CONST DWORD* pTargetHashes, FARPROC* pResolvedPtrs, int numHashes)
{
    if (!hModule || !pTargetHashes || !pResolvedPtrs || numHashes <= 0)
    {
        return 0;
    }




    int foundCount = 0;
    BYTE* pBase = (BYTE*)hModule;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;


    IMAGE_DATA_DIRECTORY exportDataDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];


    if (exportDataDir.VirtualAddress == 0 || exportDataDir.Size == 0) {
        return 0; // No Export Directory in this module
    }


    if (exportDataDir.VirtualAddress + exportDataDir.Size > pNtHeaders->OptionalHeader.SizeOfImage)
    {
        return 0;
    }


    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportDataDir.VirtualAddress);
    DWORD* pNames = (DWORD*)(pBase + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)(pBase + pExportDir->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)(pBase + pExportDir->AddressOfFunctions);


    if (pExportDir->NumberOfNames > 65535)
    { //if some impossible number of exports, gtfo
        return 0;
    }


    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {


        DWORD nameRVA = pNames[i];
        if (nameRVA == 0 || nameRVA > pNtHeaders->OptionalHeader.SizeOfImage) continue;
        char* szFuncName = (char*)(pBase + nameRVA);


        //Hash the found Function name, so that we can compare to prehashed values
        DWORD runtimeHash = HasherDjb2(szFuncName);


        // for each
        for (int j = 0; j < numHashes; j++) {
            if (runtimeHash == pTargetHashes[j] && pResolvedPtrs[j] == NULL) {
                WORD ordinalIndex = pOrdinals[i];
                if (ordinalIndex >= pExportDir->NumberOfFunctions) continue;
                DWORD functionRVA = pFunctions[ordinalIndex];
                if (functionRVA == 0) continue;
                FARPROC funcPtr = (FARPROC)(pBase + functionRVA);
                DWORD eatStartRVA = exportDataDir.VirtualAddress;
                DWORD eatEndRVA = eatStartRVA + exportDataDir.Size;


                if (functionRVA >= eatStartRVA && functionRVA < eatEndRVA) {
                    continue;
                }


                pResolvedPtrs[j] = funcPtr;
                foundCount++;
                break;
            }
        }
        if (foundCount == numHashes) {
            break;
        }
    }
    return foundCount;
}
{%endhighlight%}


We care about three arrays that are available to us from within the PEB. The Names, Ordinals, and Functions Array.


The Names array points to.... function names, of course. These are name strings, so your exported function can be found here, just the name, mind you.


The Ordinals array is 1:1 mapped to the Names array, in the sense that Names\[index\] == Ordinals\[index\]. This array contains the ordinal number for each named function. Don't hate me, hate Microsoft, it's a common approach.


Finally, the Functions array, this is what we care about, the thing that we well finally use. This function's array contains the "RVA" or the relative virtual address of the actual implementation within the DLL.


So what we'll be doing is checking the Names and ordinals array, and based on the found values, we index the functions array, and voila, we have found the function we care about.


Okay, the core is out of the way, time to describe the implementation.


We are looking for these functions in two DLLs, kernel32.dll and NTDLL.dll.


{%highlight cpp%}
typedef BOOL(WINAPI* FuncCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* FuncWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FuncCreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef HANDLE(WINAPI* FuncGetStdHandle)(DWORD);
typedef BOOL(WINAPI* FuncCloseHandle)(HANDLE);
typedef DWORD(WINAPI* FuncWaitForSingleObject)(HANDLE, DWORD);
typedef VOID(WINAPI* FuncExitProcess)(UINT);
typedef BOOL(WINAPI* FuncSetHandleInformation)(HANDLE, DWORD, DWORD);
typedef DWORD(WINAPI* FuncGetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD);
typedef DWORD(WINAPI* FuncGetLastError)(VOID);
typedef VOID(WINAPI* FuncRtlZeroMemory)(PVOID Destination, SIZE_T Length);
{%endhighlight%}


The typedefs exist as we are not relying on anything that the header files provide for function signatures. This is just a keyword that creates an alias for another data type.
We do this so that we can supply correct params when calling the function, the compiler helps, and quite importantly, so that I don't pull my hair out and maintain some code readability.




Now for the helper functions


{%highlight cpp%}
size_t get_len(CONST WCHAR* str) {
    CONST WCHAR* s = str;
    while (*s) ++s;
    return (s - str);
}
size_t get_len_char(const char* str) {
    const char* s = str;
    if (!s) return 0;
    while (*s) ++s;
    return (s - str);
}


The get_len(); function helps to figure out the length of a particular wide character string or WCHAR.
WCHARS are used for Unicode text in Windows.
This function takes in a pointer to the start of the string and returns a number, or size_t.
That tells me how many chars are in it without the null terminator.


This could be done with the wcslen();, but you know, CRT.
Starts at the beginning, moves one character at a time until it finds the null terminator,
and the length is the difference between the final position and the starting position.


Similar logic for the get_len_char(); function,
but it works on normal strings or narrow character strings.
Replaces the standard strlen();.
{%endhighlight%}
<br>


{%highlight cpp%}
void copy_str(WCHAR* dest, const WCHAR* src, size_t destMaxChars, size_t srcLen) {
    if (!dest || destMaxChars == 0 || !src) {
        if (dest && destMaxChars > 0) dest[0] = L'\0';
        return;
    }
    size_t charsToCopy = srcLen;
    if (charsToCopy >= destMaxChars) charsToCopy = destMaxChars - 1;
    size_t i = 0;
    while (i < charsToCopy && src[i] != L'\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0';
}
void copy_str_char(char* dest, const char* src, size_t destMaxBytes) {
    if (!dest || destMaxBytes == 0) return;
    dest[0] = '\0';
    if (!src) return;


    size_t i = 0;
    while (src[i] != '\0' && i < (destMaxBytes - 1)) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}
The next is the copy_str and the copy_str_char. It just copies a wide/narrow character string from
source to destination, ensures null termination.
The alternatives would be wsncpy(); and strcpy_s();.


Both these functions return nothing, but modify the destination buffer.
populating it with the contents from the source.
Copies until the source ends or the destination buffer is almost full, then null terminates
{%endhighlight%}
{%highlight cpp%}
const WCHAR* GetDllName(const UNICODE_STRING* Path) {
    if (!Path || !Path->Buffer || Path->Length == 0) return NULL;
    SIZE_T len = Path->Length / sizeof(WCHAR);
    const WCHAR* start = Path->Buffer;
    const WCHAR* end = start + len;
    for (const WCHAR* p = end - 1; p >= start; --p) {
        if (*p == L'\\' || *p == L'/') return p + 1;
    }
    return start;
}


If you can read, you can guess that it returns the DLL Name from the given path.
However, the path that is supplied to is the UNICODE_STRING path, from the FullDllName.


Takes in the pointer to the structure holding the WHCAR path buffer and its length.
Gets me the file Name.
DLL path C:\Windows\XYZ\PQR\ [Crypt32.dll]<--- this.


It calculates the end of the string buffer using the field length.
Then it scans from the end, looking for the last path separator character.
If found, it returns a pointer to the character immediately after the separator.
If no separator is found, it just assumes the whole string is the filename and
returns the original start pointer.
{%endhighlight%}


<br>
{%highlight cpp%}


typedef struct _Module_Info {
    WCHAR BaseName[MAX_MODULE_NAME_LEN];
    PVOID DllBase;
} MODULE_INFO, * PMODULE_INFO;




int GetLoadedModules(MODULE_INFO* outputArray, int maxEntries) {


    if (!outputArray || maxEntries <= 0) {
        return 0;
    }


    PPEB pPeb = (PPEB)__readgsqword(0x60);


    if (!pPeb || !pPeb->Ldr) {
        return -1;
    }


    PLIST_ENTRY pListHead = &(pPeb->Ldr->InMemoryOrderModuleList);
    if (pListHead->Flink == pListHead) {
        return 0;
    }


    int currentCount = 0;
    PLIST_ENTRY pCurrentEntry = pListHead->Flink;
    while (pCurrentEntry != pListHead) {
        if (currentCount >= maxEntries) {
            break;
        }
        PLDR_DATA_TABLE_ENTRY pModuleEntry = CONTAINING_RECORD(
            pCurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);


        CONST WCHAR* baseNamePtr = NULL;
        size_t baseNameLen = 0;


        if (pModuleEntry->FullDllName.Buffer && pModuleEntry->FullDllName.Length > 0) {
            baseNamePtr = GetDllName(&pModuleEntry->FullDllName);
            if (baseNamePtr) {
                CONST WCHAR* endOfFullName = pModuleEntry->FullDllName.Buffer + (pModuleEntry->FullDllName.Length) / sizeof(WCHAR);
                baseNameLen = endOfFullName - baseNamePtr;
            }
        }


        if (baseNamePtr) {
            copy_str(outputArray[currentCount].BaseName, baseNamePtr, MAX_MODULE_NAME_LEN, baseNameLen);
        }
        else {
            copy_str(outputArray[currentCount].BaseName, L"[NAME N/A]", MAX_MODULE_NAME_LEN, 10);
        }


        outputArray[currentCount].DllBase = pModuleEntry->DllBase;
        currentCount++;


        pCurrentEntry = pCurrentEntry->Flink;
    }


    return currentCount;
}




This function gets a list of all the DLLs that are currently loaded into the program memory.
With Windows, it's guaranteed that kernel32.dll and NTDLL.dll are loaded.


Takes in a pointer to an array of the MODULE_INFO Structs where the results,
which is the DLL Name and In memory Base address are stored.


It fills the output array with information about each loaded DLL, and returns the number of modules found, if none are found, we just return -1.


It finds the Process Environment Block with the compiler intrinsic, __readgsqdword(0x60). Which gets the address of the LDR Data.


It then walks a Double Linked list, InMemoryOrderModuleList, where each node, called the LDR_DATA_TABLE_ENTRY, contains
The information about a loaded DLL.


For each DLL, we get back the base address and the DLL name.
We copy the string and store the file name.
{%endhighlight%}




{%highlight cpp%}
int CompareSubstring(const WCHAR* subStr, size_t subStrLen, const WCHAR* wzStr2) {
    if (!subStr || !wzStr2) {


        if (subStrLen == 0) {
            return (!wzStr2 || wzStr2[0] == L'\0') ? 0 : -1;
        }
        return 1; // Non-equal if other is non-empty
    }
    size_t len2 = get_len(wzStr2);


    if (subStrLen != len2) {
        return 1;
    }
    if (subStrLen == 0) {
        return 0;
    }


 
    for (size_t i = 0; i < subStrLen; ++i) {
        WCHAR c1 = subStr[i];
        WCHAR c2 = wzStr2[i];


        // Convert to lowercase
        if (c1 >= L'A' && c1 <= L'Z') c1 += (L'a' - L'A');
        if (c2 >= L'A' && c2 <= L'Z') c2 += (L'a' - L'A');


        if (c1 != c2) {
            return (int)(c1 - c2);
        }
    }


    return 0;  
}


Compares two WCHAR strings for equality, while being case insensitive.


Compares subStr whose length we already know, subStrLen, against
a standard null terminated string, wzStr2.


Takes in two strings, checks if the known length, subStrLen, matches the calculated length of
the null terminated string, wzStr2.


If the lengths differ, they can't be equal.
If they match, compare character by character.
For each pair of characters, convert them both to lowercase using deltas before comparing them.
If any mismatch, they aren't equal, return non zero value.
Else, return 0.


Effectively replaces the _wcsicmp();


{%endhighlight%}


{%highlight cpp%}
DWORD HasherDjb2(const char* str) {
    DWORD hash = 5381; //  seed value
    int c;


 
    while ((c = (unsigned char)*str++) != 0) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}


Simple scalar hashing routine.
Takes in the narrow string to hash, returns a DWORD, or double word, which is the calculated hash value.
This is a very simple algo, people often use rot13 strings, or xor, or something a tad bit more complex.
It's called dbj2, I actually dont know why, but there is salsa20, and chacha20,
who knows what the crypto people are into.


This function basically creates a unique number from a string,
which we use to ID function names numerically instead of text.




{%endhighlight%}


{%highlight cpp%}
ResolveFuncsByHashInModule(HMODULE hModule, CONST DWORD* pTargetHashes, FARPROC* pResolvedPtrs, int numHashes)


The implementation is above, I'll just run through what it does.


Takes in the Handle to a module, hModule;, which is the address of the dll.
The respective hashes to search for, which we will have precalculated, pTargetHashes;


The result, if we findthe  address of the functions we want, is to be stored in pResolvedPtrs;. This must be null initialized.
The numberofHashes to look for, numHashes;. I've just included this just to reduce runtime, if we have found the hashes,
that is foundCount == numHashes. Stop, instead of running through the whole DLL.


This returns the number of functions that were found and resolved.


We read the Portable Executable/PE headers (everything is a PE file, dlls, exes, sys.),
to find the Export Address Table or EAT.


The EAT lists all the functions that the DLL makes available.
This function iterates through the list of exported names, calculates the hash of each name using the same hashing function that we used to calculate the targets.


Compares these hashes to the target hashes within the pTargetHashes; array.
If a hash matches AND we haven't already found it before,
It looks up the function's actual memory address using the
Ordinals and AdressOfFunctions arrays, and stores it in the
pResolvedPtrs; array.


If something is forwarded into the abyss, lets say to ntdll.dll, we just skip it, as we can re-search the correct target if we need to.


Use hashes, traverse EAT, and find functions.
{%endhighlight%}






{%highlight cpp%}
ZeroMemory(PVOID Destination, SIZE_T Length);


Simple, take the destination, zero it out.
Ideally, I should be using SSE or AVX instructions.
But I was in a considerable amount of pain already.


But, if you are someone who is inclined to do such a thing ,this is how you would do it.


inline void my_set_zero(void* dest, size_t length){


    char* point = (char*) dest;
    size_t i= 0;
    __m128i zero = __mm_setzero_si128();


    size_t byte_chunks = length / 16;
    for(i =0 ; i < byte_chunks; i++){
        __mm_storeu_si128((__m128i *)(point + (i*16)), zero);
    }


    size_t left_overs= byte_chunks * 16;
    for(i=left_overs; i < length ; i++){
        point[i] = 0;
    }
}
Zero out 16 bytes at a time.
Whatever's left, zero that out as well.


Or, resolve RtlZeroMemory, and let Windows handle it for you.




{%endhighlight%}






Putting it all together


{%highlight cpp%}
int start() {
    #define ZeroMemory(Destination, Length) if(pRtlZeroMemory) pRtlZeroMemory((Destination), (Length));
    #define MAX_CMD_PATH 512
    MODULE_INFO Modules[256];
    FARPROC Kernel32Ptrs[10] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL,NULL, NULL, NULL };
    FARPROC NtdllPtrs[1] = { NULL };
    //Get the loaded Modules from the current Process
    int moduleCount = GetLoadedModules(Modules, 256);


    if (moduleCount < 0) { return 1; }


    HMODULE hK32DLL = NULL;
    HMODULE hNtdll = NULL;


    WCHAR  s_kernel_32_dll[] = L"Kernel32.dll";
    WCHAR  s_ntdll_dll[] = L"Ntdll.dll";
    for (int i = 0; i < moduleCount; i++) {
        size_t baseNameLength = get_len(Modules[i].BaseName);


        if (CompareSubstring(Modules[i].BaseName, baseNameLength, s_kernel_32_dll) == 0) {
            //Match -> xyz\pqr\[kernel32.dll] in mem == requried Dll
            hK32DLL = (HMODULE)Modules[i].DllBase;
        }


        if (CompareSubstring(Modules[i].BaseName, baseNameLength, s_ntdll_dll) == 0) {
            hNtdll = (HMODULE)Modules[i].DllBase;
        }
        if (hK32DLL && hNtdll) {
            break;
        }


    }


    //Find Functions within Kernel32,
    //Traverse three arrays,
    // Address of Names, Adress of Ordinals, Adrees of NameOridnals


    CHAR sCreateProcessA[] = "CreateProcessA";
    CHAR sWriteFile[] = "WriteFile";
    CHAR sCreatePipe[] = "CreatePipe";
    CHAR sGetStdHandle[] = "GetStdHandle";
    CHAR sCloseHandle[] = "CloseHandle";
    CHAR sWaitForSingleObject[] = "WaitForSingleObject";
    CHAR sExitProcess[] = "ExitProcess";
    CHAR sSetHandleInformation[] = "SetHandleInformation";
    CHAR sGetEnvironmentVariableA[] = "GetEnvironmentVariableA";
    CHAR sGetLastError[] = "GetLastError";
    CHAR sRtlZeroMemory[] = "RtlZeroMemory";


    FuncCreateProcessA pCreateProcessA = NULL;
    FuncWriteFile pWriteFile = NULL;
    FuncCreatePipe pCreatePipe = NULL;
    FuncGetStdHandle pGetStdHandle = NULL;
    FuncCloseHandle pCloseHandle = NULL;
    FuncWaitForSingleObject pWaitForSingleObject = NULL;
    FuncExitProcess pExitProcess = NULL;
    FuncSetHandleInformation pSetHandleInformation = NULL;
    FuncGetEnvironmentVariableA pGetEnvironmentVariableA = NULL;
    FuncGetLastError pGetLastError = NULL;
    FuncRtlZeroMemory pRtlZeroMemory = NULL;


    CONST DWORD FuncHashesK32[] = {
       HasherDjb2(sCreateProcessA), HasherDjb2(sWriteFile), HasherDjb2(sCreatePipe),
        HasherDjb2(sGetStdHandle), HasherDjb2(sCloseHandle), HasherDjb2(sWaitForSingleObject),
        HasherDjb2(sExitProcess), HasherDjb2(sSetHandleInformation), HasherDjb2(sGetEnvironmentVariableA),
        HasherDjb2(sGetLastError)
    };


    CONST DWORD FuncHashesNTDLL[] = {
        HasherDjb2(sRtlZeroMemory)
    };
   
    int numberOfFuncs_K32 = sizeof(FuncHashesK32) / sizeof(DWORD);


    int NumberFoundK32 = ResolveFuncsByHashInModule(
        // -- # 1 The address of the start of required DLL
        hK32DLL,
        // -- #2 Array of Function Hashes to search for
        FuncHashesK32,
        // -- #3  Where to store, must be a null init array,
        // will store ptrs to the found funcs
        Kernel32Ptrs,
        // -- #4 Number of Funcs to search in DLL, will run this many times.
        numberOfFuncs_K32
        );




    pCreateProcessA = (FuncCreateProcessA)Kernel32Ptrs[0];
    pWriteFile = (FuncWriteFile)Kernel32Ptrs[1];
    pCreatePipe = (FuncCreatePipe)Kernel32Ptrs[2];
    pGetStdHandle = (FuncGetStdHandle)Kernel32Ptrs[3];
    pCloseHandle = (FuncCloseHandle)Kernel32Ptrs[4];
    pWaitForSingleObject = (FuncWaitForSingleObject)Kernel32Ptrs[5];
    pExitProcess = (FuncExitProcess)Kernel32Ptrs[6];
    pSetHandleInformation = (FuncSetHandleInformation)Kernel32Ptrs[7];
    pGetEnvironmentVariableA = (FuncGetEnvironmentVariableA)Kernel32Ptrs[8];
    pGetLastError = (FuncGetLastError)Kernel32Ptrs[9];




    int numberOfFuncs_NTDLL= sizeof(FuncHashesNTDLL) / sizeof(DWORD);


    int foundNtdll = 0;
    if (hNtdll) {
        foundNtdll = ResolveFuncsByHashInModule(hNtdll, FuncHashesNTDLL, NtdllPtrs, numberOfFuncs_NTDLL);
    }


    if (foundNtdll > 0) pRtlZeroMemory = (FuncRtlZeroMemory)NtdllPtrs[0];


 HANDLE hChildStd_IN_Rd = NULL;
    HANDLE hChildStd_IN_Wr = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    SECURITY_ATTRIBUTES sa;
    char cmdPath[MAX_CMD_PATH];
    char cmdLine[MAX_CMD_PATH]; // Buffer for command line


    // Setup security attributes for inheritable pipe handle
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;


   
    if (!pCreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &sa, 0)) {
         pExitProcess(2);
    }


   
    if (!pSetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
         pCloseHandle(hChildStd_IN_Rd);
        pCloseHandle(hChildStd_IN_Wr);
        pExitProcess(3);
    }


   
    CHAR sComSpec[] = "ComSpec";
    if (pGetEnvironmentVariableA(sComSpec, cmdPath, MAX_CMD_PATH) == 0) {
         pCloseHandle(hChildStd_IN_Rd);
        pCloseHandle(hChildStd_IN_Wr);
        pExitProcess(4);
    }
    copy_str_char(cmdLine, cmdPath, MAX_CMD_PATH);


   
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = pGetStdHandle(STD_ERROR_HANDLE);
    si.hStdOutput = pGetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdInput = hChildStd_IN_Rd;
    si.dwFlags |= STARTF_USESTDHANDLES;


    ZeroMemory(&pi, sizeof(pi));


    if (!pCreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
       
        pCloseHandle(hChildStd_IN_Rd);
        pCloseHandle(hChildStd_IN_Wr);
        pExitProcess(5);
    }


   
    pCloseHandle(pi.hThread);
    pCloseHandle(hChildStd_IN_Rd);


   
    CHAR sCommand[] = "echo Hello from CRT-Free Parent!\r\n";
    CHAR sExitCmd[] = "exit\r\n";
    //DWORD bytesWritten;


    /*if (!pWriteFile(hChildStd_IN_Wr, sCommand, (DWORD)get_len_char(sCommand), &bytesWritten, NULL)) {
      // if you care do the cleanup


      //
    }
    if (!pWriteFile(hChildStd_IN_Wr, sExitCmd, (DWORD)get_len_char(sExitCmd), &bytesWritten, NULL)) {
      // if you care do the cleanup,  
    }


    */
    pCloseHandle(hChildStd_IN_Wr);


   
    pWaitForSingleObject(pi.hProcess, INFINITE); // Use INFINITE from WinDef.h


   
    pCloseHandle(pi.hProcess);




   
    pExitProcess(0);
}
{%endhighlight%}






A note, before you compile this, you would need to set a few things in the property sheets for visual studio. I'm almost sure im using the 2022 version of it, whichever came with the FLAREVM.


{%highlight python%}


C++ Language Standard = C++20
Conformance Mode = No -> Backward Compatibility
Control Flow Guard = No
Enable C++ Exceptions = No
Enable Function Level Linking = Yes
Enable Intrinsic Functions = Yes
SDL Checks = No
Security Check = No Gs




Linker Options:
Entry point = to whatever you want to name func, im calling it start
Generate Map File = Yes
This is just so that I can check the length of the opcodes generated
such that I can copy paste them directly into any kind of implant I write.


{%endhighlight%}




Walking through the start.


Find the loaded DLLs to get handles to kernel32.dll and Ntdll.dll.


Resolves the needed Windows API functions by Hash, with the ResovleFuncsHashInModule function using the found handles.


For sanity, checks for ExitProcess, if not found, early exits.


Initializes the STARTUPINFOA, PROCESS_INFORMATION, SECURITY_ATTRIBUTES using the Zeromemory function.


Creates a pipe for IPC, with CreatePipeA.
Configures the pipe handle inheritance with SetHandleInformation.


Finds the path with pGetEnvironmentVariable to cmd.exe.




Write the commands, echo and exit to the child process via the pipe.


Waits until the process finishes with WaitForSingleObject,
cleans up with CloseHandle, and terminates the entire program.




So that was it, a "simple" dynamic function resovler, and a series of calls that writes commands to a cmd.exe child process.  


![DiscountWin](/assets/images/B1/discountwin.png){:.img-medium}




In the next blog post, provided I haven't ascended, I will cover how to do the same thing but with native apis.
Specifically, this one.




{%highlight cpp%}
typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;
typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
#define 	RTL_CONSTANT_STRING(s)   { sizeof(s)-sizeof((s)[0]), sizeof(s), s }


typedef NTSTATUS(NTAPI* FuncRtlCreateProcessParametersEx)(
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath, _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine, _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle, _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo, _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags);
typedef NTSTATUS(NTAPI* FuncRtlDestroyProcessParameters)(_In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

typedef PVOID(NTAPI* FuncRtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
typedef BOOLEAN(NTAPI* FuncRtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
typedef PVOID(NTAPI* FuncRtlProcessHeap)(VOID);
typedef HANDLE(WINAPI* FuncGetProcessHeapHandle)(VOID)

   status = pRtlCreateProcessParametersEx(
        &processParameters,
        &imagePath,  
        NULL, NULL,
        &commandLine,  
        NULL, NULL, NULL, NULL, NULL,
        0x00000001
    );

    if (!NT_SUCCESS(status)) {
        return 6; 
    }

    HANDLE hProcHeap = pGetProcessHeap();
    SIZE_T attributeListSize = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE) + sizeof(PS_ATTRIBUTE); // Size for header + 1 attribute
    attributeList = (PPS_ATTRIBUTE_LIST)pRtlAllocateHeap(
        hProcHeap,       
        handle
        HEAP_ZERO_MEMORY,
        attributeListSize
    );
    if (!attributeList) {
        pRtlDestroyProcessParameters(processParameters); // Clean up params before exiting
        return 7; // Failed to allocate memory for attribute list
    }
    //attributeList->TotalLength = attributeListSize;
    //attributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME; 
    //attributeList->Attributes[0].Size = ntImagePath.Length;           
    //attributeList->Attributes[0].ValuePtr = ntImagePath.Buffer;      

    ACCESS_MASK procAccess = PROCESS_ALL_ACCESS;
    ACCESS_MASK threadAccess = THREAD_ALL_ACCESS;
    status = pNtCreateUserProcess(
        &hProcess,
        &hThread,
        procAccess,
        threadAccess,
        &objAttr,           
        OBJECT_ATTRIBUTES
        &objAttr,          
         OBJECT_ATTRIBUTES
        0,                  // ProcessFlags
        0,                  // ThreadFlags
        processParameters,  
        &createInfo,        
        attributeList       
    );

    finalStatus = status;
{%endhighlight%}


Thank you for reading through.