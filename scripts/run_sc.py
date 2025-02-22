from miasm.core.locationdb import LocationDB
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC

### Create environnement with PE context for the shellcode to run 

# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")

# Get the shellcode from the second argument
parser.add_argument("shellcode", help="shellcode file")

options = parser.parse_args()
# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Win_x86_32(loc_db, options.filename, options, globals())

# Load the shellcode
data = open(options.shellcode, 'rb').read()
run_addr = 0x40000000
sb.jitter.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE | PAGE_EXEC, data, "shellcode")
sb.jitter.cpu.EAX = run_addr

# Avoid crash 
sb.jitter.vm.add_memory_page(0x7ffdf002, PAGE_READ | PAGE_WRITE, b"\x00"*4)
sb.jitter.vm.add_memory_page(0x7ffdf064, PAGE_READ | PAGE_WRITE, b"\x02"*4)

# Run at 
sb.run(run_addr)


## python3 -i run_sc.py -b -s -l -y ../samples/box_upx.exe ../files/output_022.bin
