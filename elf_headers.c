#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>

void print_hex(const char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", (unsigned char)data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void print_elf_header(Elf64_Ehdr *header) {
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf("%02x ", header->e_ident[i]);
    }
    printf("\n");
    printf("  Class:                             %02x\n", header->e_ident[EI_CLASS]);
    printf("  Data:                              %02x\n", header->e_ident[EI_DATA]);
    printf("  Version:                           %02x\n", header->e_ident[EI_VERSION]);
    printf("  OS/ABI:                            %02x\n", header->e_ident[EI_OSABI]);
    printf("  ABI Version:                       %02x\n", header->e_ident[EI_ABIVERSION]);
    printf("  Type:                              %04x\n", header->e_type);
    printf("  Machine:                           %04x\n", header->e_machine);
    printf("  Version:                           %08x\n", header->e_version);
    printf("  Entry point address:               %016lx\n", (unsigned long)header->e_entry);
    printf("  Start of program headers:         %016lx\n", (unsigned long)header->e_phoff);
    printf("  Start of section headers:         %016lx\n", (unsigned long)header->e_shoff);
    printf("  Flags:                             %08x\n", header->e_flags);
    printf("  Size of this header:               %04x\n", header->e_ehsize);
    printf("  Size of program headers:           %04x\n", header->e_phentsize);
    printf("  Number of program headers:         %04x\n", header->e_phnum);
    printf("  Size of section headers:           %04x\n", header->e_shentsize);
    printf("  Number of section headers:         %04x\n", header->e_shnum);
    printf("  Section header string table index: %04x\n", header->e_shstrndx);
}

void print_program_headers(Elf64_Phdr *phdr, int phnum) {
    printf("Program Headers:\n");
    for (int i = 0; i < phnum; i++) {
        printf("  Header %d:\n", i);
        printf("    Type:   %08x\n", phdr[i].p_type);
        printf("    Flags:  %08x\n", phdr[i].p_flags);
        printf("    Offset: %016lx\n", (unsigned long)phdr[i].p_offset);
        printf("    VAddr:  %016lx\n", (unsigned long)phdr[i].p_vaddr);
        printf("    PAddr:  %016lx\n", (unsigned long)phdr[i].p_paddr);
        printf("    FileSz: %016lx\n", (unsigned long)phdr[i].p_filesz);
        printf("    MemSz:  %016lx\n", (unsigned long)phdr[i].p_memsz);
        printf("    Align:  %016lx\n", (unsigned long)phdr[i].p_align);
    }
}

void print_section_headers(Elf64_Shdr *shdr, int shnum, const char *shstrtab) {
    printf("Section Headers:\n");
    for (int i = 0; i < shnum; i++) {
        printf("  Section %d:\n", i);
        printf("    Name:      %s\n", shstrtab + shdr[i].sh_name);
        printf("    Type:      %08x\n", shdr[i].sh_type);
        printf("    Flags:     %016lx\n", (unsigned long)shdr[i].sh_flags);
        printf("    Addr:      %016lx\n", (unsigned long)shdr[i].sh_addr);
        printf("    Offset:    %016lx\n", (unsigned long)shdr[i].sh_offset);
        printf("    Size:      %016lx\n", (unsigned long)shdr[i].sh_size);
        printf("    Link:      %08x\n", shdr[i].sh_link);
        printf("    Info:      %08x\n", shdr[i].sh_info);
        printf("    AddrAlign: %016lx\n", (unsigned long)shdr[i].sh_addralign);
        printf("    EntSize:   %016lx\n", (unsigned long)shdr[i].sh_entsize);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    Elf64_Ehdr *header = (Elf64_Ehdr *)data;
    if (header->e_ident[EI_MAG0] != ELFMAG0 ||
        header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 ||
        header->e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Not an ELF file\n");
        munmap(data, size);
        close(fd);
        return 1;
    }

    print_elf_header(header);

    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)data + header->e_phoff);
    print_program_headers(phdr, header->e_phnum);

    Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)data + header->e_shoff);
    const char *shstrtab = (const char *)data + shdr[header->e_shstrndx].sh_offset;
    print_section_headers(shdr, header->e_shnum, shstrtab);

    munmap(data, size);
    close(fd);
    return 0;
}
