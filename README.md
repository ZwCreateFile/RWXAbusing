# RWXAbusing
PoC

This project abusing which dll's have RWX sections (read, write, execute.) when this dll's are signed(whitelisted by anticheat) its create a major security vulnerability. Since those sections are writable we can simply map
our own DLL into those sections. 
