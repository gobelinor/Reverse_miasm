from pdb import pm
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
from miasm.os_dep.win_api_x86_32 import *

# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")

options = parser.parse_args()

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Win_x86_32(loc_db, options.filename, options, globals())

# Ajout la page pour le shellcode
addr_shellcode = 0x500000
sb.jitter.vm.add_memory_page(addr_shellcode, PAGE_READ | PAGE_WRITE | PAGE_EXEC, b"\x00" * 0x1000, "shellcode")


shellcode = open('./dump1.bin', 'rb').read()
sb.jitter.vm.set_mem(addr_shellcode, shellcode)


addr_dllname = 0x30000
sb.jitter.vm.add_memory_page(addr_dllname, PAGE_READ, b"\x00" * 0x1000, "dll name")

def getHash(jitter):
    print("Hash: %x" % jitter.cpu.EDI)
    return False
sb.jitter.vm.add_memory_page(0x7ffdf002, PAGE_READ | PAGE_WRITE, b"\x00"*4)
sb.jitter.vm.add_memory_page(0x7ffdf064, PAGE_READ | PAGE_WRITE, b"\x02"*4)
# ajouter un breakpoint a la fin du hash
sb.jitter.add_breakpoint(addr_shellcode + 0x12b, getHash)

fd_dll = open('dll.list')
for line in fd_dll:
    line = line.strip()

    print(repr(line))

    sb.jitter.cpu.ESI = addr_dllname
    dllname = line + "\x00"
    sb.jitter.vm.set_mem(addr_dllname, dllname.encode("utf-16le"))


    # Run a partir du début de hash
    sb.jitter.run(addr_shellcode + 0x10e)

