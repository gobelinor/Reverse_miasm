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
# Charger le shellcode en mémoire

def dump(jitter):
    data = jitter.vm.get_mem(addr_shellcode, len(shellcode))
    open('dump1.bin', 'wb').write(data)
    return True

#sb.jitter.add_breakpoint(0x500171, dump)

shellcode = open('./dump1.bin', 'rb').read()
sb.jitter.vm.set_mem(addr_shellcode, shellcode)

#sb.jitter.remove_breakpoints_by_address(sb.libs.cname2addr['ntdll_swprintf'])

# Run
sb.run(addr_shellcode + 0x95)

assert(sb.jitter.running is False)
