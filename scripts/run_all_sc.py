from miasm.core.locationdb import LocationDB
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
import os

def write_to_output_file(string):
    with open("SOLUTIONS_SC.txt", "a") as f:
        f.write(string + "\n")

def user32_MessageBoxA(jitter):
    # MessageBoxA
    # MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
    # hWnd: 0
    # lpText: "Hello, World!"
    # lpCaption: "Hello"
    # uType: 0
    # Return: int
    ret_ad, args = jitter.func_args_stdcall(["hWnd", "lpText", "lpCaption", "uType"])
    hWnd, text_ad, caption_ad, uType = args
    text = jitter.get_c_str(text_ad)
    caption = jitter.get_c_str(caption_ad)
    print(f"[SOLUTION] MessageBoxA(hWnd={hWnd}, lpText={text}, lpCaption={caption}, uType={uType})")
    write_to_output_file(f"[SOLUTION] MessageBoxA(hWnd={hWnd}, lpText={text}, lpCaption={caption}, uType={uType})")
    write_to_output_file(f"[SOLUTION] The code is {text}")
    jitter.func_ret_stdcall(ret_ad, 1) # 1 == OK

def emulate(data):
    # Parse arguments
    parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
    parser.add_argument("filename", help="PE Filename")
    options = parser.parse_args()
    # Create sandbox
    loc_db = LocationDB()
    sb = Sandbox_Win_x86_32(loc_db, options.filename, options, globals())
    # Avoid crash and continue execution
    sb.jitter.vm.add_memory_page(0x7ffdf002, PAGE_READ | PAGE_WRITE, b"\x00"*4)
    sb.jitter.vm.add_memory_page(0x7ffdf064, PAGE_READ | PAGE_WRITE, b"\x02"*4) # mucho processors
    # Load the shellcode
    run_addr = 0x40000000 
    sb.jitter.vm.remove_memory_page(run_addr)
    sb.jitter.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE | PAGE_EXEC, data, "shellcode")
    sb.jitter.cpu.EAX = run_addr
    # Run at 
    sb.run(run_addr)

# get all files from out_sc directory
files = os.listdir("../out_sc")
for file in files:
    data = open("../out_sc/"+file, 'rb').read()
    print(f"[SOLUTION] For file {file}")
    write_to_output_file(f"\n[SOLUTION] For file {file}")
    emulate(data)

## python3 -i run_all_sc.py -b -s -l -y ../samples/box_upx.exe 
## python3 -i run_all_sc.py -l -y ../samples/box_upx.exe 
