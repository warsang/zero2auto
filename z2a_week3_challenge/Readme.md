## Zero2auto Write-up

So we get the following sample A0AC02A1E6C908B90173E86C3E321F2BAB082ED45236503A21EB7D984DE10611

A quick look in VT shows it being flagged by 53 av's. The FileName is cru_paker.exe

Looking at the sections and their enthropy, we quickly see the sample is packed.

Specifically, the .rsrc section has very high entropy.

The any.run report at https://app.any.run/tasks/c9da38c3-12ba-49f5-8ec9-dafac4764148/ considers the sample clean. We quickly understand by looking at the app.any.run that it crashed and never ran successfully.

Only Kernel32 is imported.

Behavior analysis in VT shows:
- the sample reaching out to pastebin.
- Writing a reg key that seems related to proxy settings ->  HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\SavedLegacySettings 


We continue by throwing the sample in tria.ge.
The output is now available at https://tria.ge/210205-gl47gj2jfx

We notice a pop-up window saying "Uh-oh hacked!"

Cool! Looks like we have enough info to get started with analysis.

Looking at resources with resource hacker we confirm there's one RCData resoure that looks encrypted. I've got a feeling this is going to be RC4...

Detect it easy doesn't have the packer signature.


The process tree suggests injection into svchost (or spawning a new malicious process called svchost.exe). We can confirm that as we see most of the c2 reachouts com from svchost.
Tria.ge shows cruloader as a user-agent. A quick google search shows a few z2a write-ups. I decide not to look at these but if this was a real-life scenario, it's a likely next step I'd take.

The pastebin link: hxxps://pastebin[.]com/raw/mLem9DGk contains a link to hxxps://[i.]ibb[.]co/KsfqHym/PNG-02-Copy.png ; 

The tria.ge analysis also shows reachouts after pastebin to that domain. detonating it in a sandbox shows it's serving what appears to be a broken png.
Opening the png in a hex editor doesn't reveal anything interesting yet.


Tria[.]ge also calls out calls to WriteProcessMemory.
Specifically from a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611.exe to a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611.exe and from 
a0ac02a1e6c908b90173e86c3e321f2bab082ed45236503a21eb7d984de10611.exe to svchost.exe which confirms injection. Another indicator is the EnumeratesProcesses behavior highlighted which suggests calls to ToolHelp32Snapshot to enumerate processes and threads.

File and registry writes indicatw stuff to do with InternetExplorer?

Network reachouts show calls to  224.0.0.252:5355 and 239.255.255.250:1900 ( outside of calls to 53;80 and443)

Speedguide doesn't indicate anything interesting about these ports ( https://www.speedguide.net/port.php?port=5355  https://www.speedguide.net/port.php?port=1900 )

As we think the resource is encrypted, we're going to take a look at cryptofunctions SND Reverser Tool indicates RC4. Sure enough, we browse to that VA and can identify an sbox!
SignSrch doesn't really tell us anything outside of the presence of IsDebuggerPresent


Let's open this guy in IDA!


First SUB looks like anti-vm/sandbox checks
Shortly after at VA: 401fab we have checks for cpuid etc.

In the debugger; we break on LoadResource. We execute untill return; step out and shortly after we see what looks like a decryption function
We browse there in IDA (401300)

This string decryption function is invoked several times with the strings at 414880 and 414970

I tried several approaches to understanding the decrypt function. Quickly looking at it in the debugger, we notice it uses the string abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./= and decrypts a bunch of strings that start at 00414880 ; We select these strings and hit shift+E to export them. I think we're dealing with some substition/rot cypher because of that lookup string. I thought I'd try using Cyberchep or Ciphey to try and decrypt these:

```
➜  z2auto-writeup docker run -it --rm remnux/ciphey -t ".5ea5/QPY4//"
Result 'BYRE' (y/N): N
Result 'ohEAhn* "inn' (y/N): N
🌏  Thinking
```

None of these worked... THat's dissapointing.

We put some breakpoints in the decryption function. There's a few for loops. I just break on the last one. We se the characters of the Cyphertext being decoded one by one. Looking at the lookup table we confirm this is ROT13.

.5ea5/QPY4// -> kernel32.dll

The fact that the rot13 function is followed by GetProcAddress and LoadLibraryA calls followed by call eax/ebx.. confirms dynamic import resolution.

Not having IDA Pro; I decide to use cutter to anotate the rot13 decrypted strings:

I like Ghidra but cutter now includes Ghidra's decompiler, has some pretty neat emulation features and navigating between graph view and disassembly view in Ghidra is a nightmare.

I wanted to try using cutter's powerfull jupyter notebook feature.

It was not straightforward setting it up and I had to follow instructions at https://github.com/rizinorg/cutter-jupyter/issues/11 ;


After a bit of troubleshooting I got my notebook set-up.
It ended up never working so I wenrt back to Ghidra

After writing a small script to decrypt and annotate the rot13 strings, we quickly see 2 decrypted functions:

The first one has calls to:

LoadResource;LockResource;VirutalAlloc etc.

Followed by an RC4 decryption routine; -> Likely there to help decrypt that resource.

Followed by a function:

VirutalAllocEx;WriteProcessA; CreateProcessA with the suspended flag (0x4); ResumeThread etc.
Clear signs of RunPE injection

by breaking on VirtualAlloc and comparing to what we have in ResoureHacker, we quickly see the resource is loaded at offset 1C. Shortly before, we notice an add eax,1c after the call to sizeofresource. 

We see it's decrypted as RC4 with the first 1C bytes as a key. Keeping our breakpoint on VirtualAlloc and keeping it running allows us to dump stage2.

Stage2 at a glance looks very similar but out crypto scanner tools indicate CRC32.
Browsing to the VA indicated by Kanal in IDA, we see:

0EDB88320 ; A quick google search indicates this is a CRC32 crypto constant.

That subroutine is only called once.
At the start of the subroutine, we notice other values like 0C1F3B876; 8197004C; etc.

These hashes are passed to another sub with a call to LoadLibraryA; a sub that looks like CRC32 (because of 0EDB88320 being in it) and then GetProcAddress.
We see the crc32 polynomial used here: https://github.com/guitmz/virii/blob/master/h/heretic.asm in a git referencing virus source code.

After exiting the function. We take a jmp and exit the program. I changed zf again and this time we end up in 401d50 which has more crc32 hashes.
The first call is CreateProcessA.
we see it being called in the next subroutine at 0x401ca0. the push 4 hints to the process suspended flag. This is confirmed though debugging and processhacker.

Once we attach to svchost, we see some calls to decrypt the following:
InternetOpen; ...

Followed by a call to strlen. We follow the string address in the dump and find an encrypted string.
We then hit a small decryption routine and see our string decrypted to https://pastebin[.]com/ ; It shifts left the bytes by 4 (swapping them) and xors the swapped bytes with a key.
0xc5 is the first key.

We xref the string and find some more encrypted strings; We xref them as well. We get the c2 link and find the same decryption function this time using 0xa2 as a key.
C:\Windows\System32\svchost.exe is the 2nd decrypted string.

The following cyberchef reciped performs the decryption:

```
From_Hex('Auto')
Rotate_left(4,false)
XOR({'option':'Hex','string':'A2'},'Standard',false)
```
It pulls an image from pastebin calling it with the userAgent cruloader. Shortly after, it gets a link to an image, downloads it and saves it as XXX.png

Then, it resolves the hashes for GetTempPath. We see the value returned: 0379F904  C.:.\.U.s.e.r.s.\.A.D.M.I.N.I.~.1.\.A.p.p.D.a.t.a.\.L.o.c.a.l.\.  
0379F944  T.e.m.p.\.2.\...................................................  


We then enter a loop that tries to locate the string cruloader in reverse in the png.

A decryption loop is entered which decrypts an MZ block by block. it looks like the block size is 0x40
Looking at the key and chucking it in cyberchef, we quickly realize it's a simple xor operation.
We dump the PE and notice it's a simple MessageBox

https://medium.com/@duzvik/scripting-with-cutter-and-jupyter-notebooks-79d588e5fbb5


https://www.megabeets.net/decrypting-dropshot-with-radare2-and-cutter-part-2/
