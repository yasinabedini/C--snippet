.code

iProcessInJob proc
mov r10,rcx
mov rdx,0
mov eax,4fh
syscall
ret
iProcessInJob endp

end