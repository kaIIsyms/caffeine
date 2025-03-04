//simple coff loader by me, you can read my paper about it on my blog
//higly inspired by https://github.com/trustedsec/COFFLoader
//i suck at c so dont judge the code

//by gbr
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

//#define IMAGE_REL_AMD64_ADDR32   0x0002

typedef struct // https://github.com/RealNeGate/Cuik/blob/7265c1a9b894ba75f053bbcf5d54b0f209592af1/include/tb_coff.h#L99
{
   uint16_t Machine;
   uint16_t NumberOfSections;
   uint32_t TimeDateStamp;
   uint32_t PointerToSymbolTable;
   uint32_t NumberOfSymbols;
   uint16_t SizeOfOptionalHeader;
   uint16_t Characteristics;
} coffee;

typedef struct
{
   uint32_t VirtualAddress;
   uint32_t SymbolTableIndex;
   uint16_t Type;
} realoc;

typedef void (*entry)();

typedef struct
{
   char Name[0x08];
   uint32_t VirtualSize;
   uint32_t VirtualAddress;
   uint32_t SizeOfRawData;
   uint32_t PointerToRawData;
   uint32_t PointerToRelocations;
   uint32_t PointerToLinenumbers;
   uint16_t NumberOfRelocations;
   uint16_t NumberOfLinenumbers;
   uint32_t Characteristics;
} sectionc;

void *alocavirt(size_t tam) {
   void *mem = VirtualAlloc(NULL, tam, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
   return(mem);
}

void parsec(FILE *fpp, void *rd, uint32_t offset, uint32_t tam) {
   fseek(fpp, offset, SEEK_SET);
   fread(rd, tam, 0x01, fpp);
}

void realoc(void* addrb,
                       realoc* vaddr,
                       int cntfor,
                       uint32_t offset) {
   for(int i=0x00; i<cntfor; i++) {
      realoc *reloc = &vaddr[i];
      uint32_t *vddrlc = (uint32_t*)((uint8_t*)addrb + offset +
                                     reloc->VirtualAddress);
      *vddrlc += (uint32_t)(addrb);
   }
}

int main(int argc, char *argv[]) {
   if(argc != 0x02) {
      printf("%s [coff]\x0d\x0a", argv[0x00]);
      return(0x01);
   }

   DWORD memoria;
   void *baddr = alocavirt(0x10000);
   FILE* file = fopen(argv[0x01], "rb");
   coffee header;
   fread(&header, sizeof(coffee), 0x01, file);
   sectionc *ssemllc = malloc(header.NumberOfSections*sizeof(sectionc));
   fread(ssemllc, sizeof(sectionc), header.NumberOfSections, file);

   for(int i=0x00; i<header.NumberOfSections; i++) {
      sectionc *section = &ssemllc[i];
      void *sectionaddr =
        (void*)((uintptr_t)baddr + section->VirtualAddress);
      parsec(file,
                   sectionaddr,
                   section->PointerToRawData,
                   section->SizeOfRawData);

      if(section->NumberOfRelocations>0x00) {
         fseek(file, section->PointerToRelocations, SEEK_SET);
         realoc *iraa =
           malloc(section->NumberOfRelocations*sizeof(realoc));
         fread(iraa,
               sizeof(realoc),
               section->NumberOfRelocations,
               file);
         realoc(baddr,
                           iraa,
                           section->NumberOfRelocations,
                           section->VirtualAddress);
         free(iraa);
      }
   }

   VirtualProtect(baddr, 0x10000, PAGE_EXECUTE_READ, &memoria); //0x40
   entry ent =
     (entry)(baddr+ssemllc[0x00].VirtualAddress);
   ent();

   free(ssemllc);
   fclose(file);
   VirtualFree(baddr, 0x00, MEM_RELEASE);

   return(0x00);
}
