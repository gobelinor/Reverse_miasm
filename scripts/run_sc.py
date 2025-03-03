from miasm.core.locationdb import LocationDB
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC


def user32_MessageBoxA(jitter):
    # MessageBoxA
    # MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
    # hWnd: 0
    # lpText: "Hello, World!"
    # lpCaption: "Hello"
    # uType: 0
    # Return: int
    ret_ad, args = sb.jitter.func_args_stdcall(["hWnd", "lpText", "lpCaption", "uType"])
    hWnd, text_ad, caption_ad, uType = args
    text = sb.jitter.get_c_str(text_ad)
    caption = sb.jitter.get_c_str(caption_ad)
    print(f"MessageBoxA(hWnd={hWnd}, lpText={text}, lpCaption={caption}, uType={uType})")
    jitter.func_ret_stdcall(ret_ad, 1) # 1 == OK


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

# 0x7ffdf000 PEB FS:[0x30] 
# 0x7ffdf002 BYTE BeingDebugged
# 0x7ffdf064 DWORD NumberOfProcessors
# Avoid crash and continue execution 
sb.jitter.vm.add_memory_page(0x7ffdf002, PAGE_READ | PAGE_WRITE, b"\x00")
sb.jitter.vm.add_memory_page(0x7ffdf064, PAGE_READ | PAGE_WRITE, b"\x00\x00\x00\x02")

# Run at 
sb.run(run_addr)

## python3 -i run_sc.py -b -s -l -y ../samples/box_upx.exe ../files/output_022.bin
## python3 -i run_sc.py -l -y ../samples/box_upx.exe ../files/output_022.bin
