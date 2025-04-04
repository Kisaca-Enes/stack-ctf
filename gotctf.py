import sys

# Komut çıktıları için gerçekçi senaryolar
def execute_command(command):
    global EXPLOIT_CODE, GOT_ADDRS, PLT_ADDRS, ELF_SYM_ADDRS
    output = ""

    # Komutlar ve çıktıları
    if command == "hint":
        output = "İpucu: Format string zafiyetini kullanarak printf GOT adresini system ile değiştir."
    elif command == "gdb ./got_overwrite-32":
        output = "[*] GDB başlatılıyor...\n[*] Güvenlik kontrolü yapılıyor...\n[*] PIE: Kapalı | ASLR: Kapalı | NX: Açık | Stack Canary: Açık"
    elif command == "checksec --fortify-file=got_overwrite-32":
        output = ("[*] Security Check: \n"
                  "    PIE: Disabled\n"
                  "    NX: Enabled\n"
                  "    Canary: Enabled\n"
                  "    Fortify Source: Disabled\n"
                  "    ASLR: Disabled")
    elif command == "exploit":
        global EXPLOIT_CODE
        output = "[*] Exploit yazma alanı açılıyor..."
        print(output)
        print("[*] Exploit kodunu girin. Ctrl+D ile bitirin.")
        
        # Kullanıcıdan exploit kodu almak
        lines = []
        print("Çok satırlı exploit kodunu girin (Ctrl+D ile bitir):")
        
        try:
            while True:
                line = input("> ")
                lines.append(line)
        except EOFError:  # Ctrl+D ile bitirildiğinde EOFError fırlatılır
            exploit_input = "\n".join(lines)

            if not exploit_input.strip():
                output = "[!] Girdi boş."
                print(output)
                return

            EXPLOIT_CODE = exploit_input  # Exploit kodunu kaydet

            # 🔥 Exploit doğrulama (Gerçekçi bir saldırı senaryosu şart!)
            if ("0xf7dc2000" not in EXPLOIT_CODE or "fmtstr_payload(5, {elf.got['printf'] : libc.sym['system']})" not in EXPLOIT_CODE):
                output = "[!] Exploit başarısız! Eksik: Libc adresi veya Format String Attack."
            else:
                output = "[*] Exploit başarıyla kaydedildi!"
            print(output)
            return
    elif command == "cat /root/flag.txt":
        if "0xf7dc2000" not in EXPLOIT_CODE or "fmtstr_payload(5, {elf.got['printf'] : libc.sym['system']})" not in EXPLOIT_CODE:
            output = "root erişim gerekli"
        else:
            output = "flag:welcometorootforhacker"
    elif command == "whoami":
        if "0xf7dc2000" in EXPLOIT_CODE and "fmtstr_payload(5, {elf.got['printf'] : libc.sym['system']})" in EXPLOIT_CODE:
            output = "root"
        else:
            output = "user"
    elif command == "check got":
        # Burada GOT_ADDRS sözlüğüne doğru şekilde erişim sağlanmalı
        GOT_ADDRS = {
            "printf": "0x12345678",
            "read": "0xf7dc2000",
            "puts": "0xabcdef12",
            "exit": "0xf7dc1000",
            "system": "0xf7dc3000"
        }
        # Correct way to format and access the dictionary
        output = f"[*] GOT adresi:\n    printf: {GOT_ADDRS['printf']}\n    system: {GOT_ADDRS['system']}\n    puts: {GOT_ADDRS['puts']}\n    exit: {GOT_ADDRS['exit']}\n    read: {GOT_ADDRS['read']}"
    elif command == "check plt":
        PLT_ADDRS = {"puts@plt": "0x555555555060", "printf@plt": "0x555555555080"}
        output = f"[*] PLT adresi:\n    puts@plt: {PLT_ADDRS['puts@plt']}\n    printf@plt: {PLT_ADDRS['printf@plt']}"
    elif command == "rop gadgets":
        output = "[*] ROP Gadget'lar bulundu: pop rdi; ret | system() | /bin/sh"
    elif command == "rop chain":
        ROP_CHAIN = [
            b'A' * 40,               # Yığın doldurma
            PLT_ADDRS["puts@plt"],    # PLT'ye git (puts@plt adresi)
            ELF_SYM_ADDRS["puts"],    # puts adresini GOT'tan al
            ELF_SYM_ADDRS["main"],    # Ana fonksiyona geri dön
            GOT_ADDRS["puts"],       # puts adresine GOT üzerinden yaz
        ]
        output = f"[*] ROP zinciri oluşturuldu: {ROP_CHAIN}"
    elif command == "exit":
        exit()
    else:
        output = "Bilinmeyen komut."

    print(f"[ {command} Çıktısı ]")
    print(output)

def hacker_terminal():
    global GOT_ADDRS, PLT_ADDRS, ELF_SYM_ADDRS, EXPLOIT_CODE
    GOT_ADDRS = {
        "printf": "0x12345678",
        "system": "0xf7dc2000",
        "puts": "0xabcdef12",
        "exit": "0xf7dc1000",
        "read": "0xf7dc3000"
    }

    PLT_ADDRS = {"puts@plt": "0x555555555060", "printf@plt": "0x555555555080"}  # PLT adresleri
    ELF_SYM_ADDRS = {"puts": "0xabcdef12", "system": "0xf7dc2000", "main": "0x555555555400"}  # ELF sembol adresleri
    EXPLOIT_CODE = ""  # Exploit başlangıçta boş olacak

    print("""
CTF Terminal - GOT Overwrite / PLT Exploit

    __   __  _______  _______  ___   _    _______  _______    _______  _______  _______  _______  ___   _ 
|  | |  ||   _   ||       ||   | | |  |       ||       |  |       ||       ||   _   ||       ||   | | |
|  |_|  ||  |_|  ||       ||   |_| |  |_     _||   _   |  |  _____||_     _||  |_|  ||       ||   |_| |
|       ||       ||       ||      _|    |   |  |  | |  |  | |_____   |   |  |       ||       ||      _|
|       ||       ||      _||     |_     |   |  |  |_|  |  |_____  |  |   |  |       ||      _||     |_ 
|   _   ||   _   ||     |_ |    _  |    |   |  |       |   _____| |  |   |  |   _   ||     |_ |    _  |
|__| |__||__| |__||_______||___| |_|    |___|  |_______|  |_______|  |___|  |__| |__||_______||___| |_|
""")

    while True:
        command = input("┌──(ctf@got_overwrite)-[~]\n└─$ ").strip().lower()
        execute_command(command)

if __name__ == "__main__":
    hacker_terminal()

