import crcmod

crc32_func = crcmod.mkCrcFun(0x1EDB88320, initCrc=0xff)
my_imports = ['CreateProcessW','CreateProcessA''CloseHandle','CopyFileA','CreateFileA','CreateFileMappingA','DeleteFileA','FreeLibrary','GetFileAttributesA','GetFileTime','GetProcAddress','GetSystemDirectoryA','GetWindowsDirectoryA','GlobalAlloc','GlobalFree','IsBadCodePtr','LoadLibraryA','MapViewOfFile','SetFileAttributesA','SetFileTime','UnmapViewOfFile','WideCharToMultiByte','WritePrivateProfileStringA','lstrcatA','lstrcpyA','lstrlenA','CloseHandle','CopyFileA','CreateFileA','CreateFileMappingA','DeleteFileA','FreeLibrary','GetFileAttributesA','GetFileTime','GetProcAddress','GetSystemDirectoryA','GetWindowsDirectoryA','GlobalAlloc','GlobalFree','IsBadCodePtr','LoadLibraryA','MapViewOfFile','SetFileAttributesA','SetFileTime','UnmapViewOfFile','WideCharToMultiByte','WritePrivateProfileStringA','lstrcatA','lstrcpyA','lstrlenA','kernel32.dll','user32.dll','malware.bin','malware','sample.bin','sample']
for myimport in my_imports:
    print(hex(crc32_func(myimport.encode('utf-8'))))
