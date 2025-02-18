### python3 -i dumpshellcode.py ../samples/box_upx.exe -s -y -z -b -l
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
import sys

machine = Machine("x86_32")
loc_db = LocationDB()
jitter = machine.jitter(loc_db)

addr_shellcode = 0x10000
jitter.vm.add_memory_page(addr_shellcode, PAGE_READ | PAGE_WRITE | PAGE_EXEC, b"\x00" * 0x1000, "shellcode")

shellcode = open('../files/output_022.bin', 'rb').read()
jitter.vm.set_mem(addr_shellcode, shellcode)

addr_stack = 0x20000
jitter.vm.add_memory_page(addr_stack, PAGE_READ | PAGE_WRITE, b"\x00" * 0x1000, "stack")
jitter.vm.set_mem(addr_stack + 0x1000 - 4, b"\xef\xbe\x37\x13")
jitter.cpu.ESP = addr_stack + 0x1000 - 4
jitter.cpu.EAX = addr_shellcode

jitter.set_trace_log(trace_instr=True, trace_regs=True, trace_new_blocks=True)

def dump(jitter):
    data = jitter.vm.get_mem(addr_shellcode, len(shellcode))
    print('brui')
    open('dump.bin', 'wb').write(data)
    return False

#jitter.add_breakpoint(addr_shellcode + 0x61, dump)


jitter.run(addr_shellcode)

# print(jitter.cpu.EAX)
