# HellsGatePoC


This is an attempt to use the locally loaded ntdll to map syscalls using Hell's Gate (https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf) but without bringing any of my own asm and *hopefully* (maybe) bypassing existing hooks.  

Some thoughts : 
1. If it doesn't find Ntdll where it is supposed to be it just closes, but might be better to continue to iterate through modules to find it.

2. In operational tooling I am reading Ntdll from disk in order to avoid hooks, but I am concerned about the detection of the read of ntdll itself (no reason for a process to do that)

3. Using MapViewofFile might be a better way to go.  BUT if we could have a way to consistently use the locally loaded (and hooked) ntdll, it would be very challenging to detect the syscall mapping.

I don't have a good way to debug this with hooks in place (will be writing my own hooks soon since this is becoming a problem).  Some ideas that I want to try is if we are mapping the hook, can we detect and then just read the bytes+8 and still achieve the same result sans hook?  Or, is reading from the local ntdll just not a viable solution?
