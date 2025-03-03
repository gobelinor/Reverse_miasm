from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
from miasm.jitter.loader.pe import vm2pe
from miasm.os_dep.common import get_win_str_a
import os

# py -i run_all_nsm.py ../output_022.exe -z -o -i -b -s -l -y

# Permet de "reconstruire" l'Import Table, mais fonctionne moyennement bien 
# def kernel32_GetProcAddress(jitter):
#     ret_ad, args = jitter.func_args_stdcall(["libbase", "fname"])
#     # When the function is called, EBX is a pointer to the destination buffer
#     print('Call to kernel32_GetProcAddress reached')
#     dst_ad = jitter.cpu.EBX
#     logging.error('EBX ' + hex(dst_ad))
#     # Handle ordinal imports
#     fname = (args.fname if args.fname < 0x10000
#              else get_win_str_a(jitter, args.fname))
#     logging.error(fname)
#     # Get the generated address of the library, and store it in memory to
#     # dst_ad
#     ad = sb.libs.lib_get_add_func(args.libbase, fname, dst_ad)
#     # Add a breakpoint in case of a call on the resolved function
#     # NOTE: never happens in UPX, just for skeleton
#     jitter.handle_function(ad)
#     jitter.func_ret_stdcall(ret_ad, ad)
#

# Si on veut que le binaire s'execute en entier 
def kernel32_Beep(jitter):
    print('Call to kernel32_Beep reached')
    ret_ad, args = jitter.func_args_stdcall(["dwFreq", "dwDuration"])
    jitter.func_ret_stdcall(ret_ad, 1)

# Malheureusement ça marche pas la pirouette ci dessous car la fonction est définie dans le binaire
# def my_lstrcmp(jitter):
#     ezoufyzouefyzeoufyzeoufyzeoufyu
#     print('Call to my_lstrcmp reached')
#     ret_ad, args = jitter.func_args_stdcall(["ptr_str1", "ptr_str2"])
#     args.str2 = get_win_str_a(jitter, args.str2)
#     jitter.func_ret_stdcall(ret_ad, 0)




### ce code declenche une protection qui fait JUMP dans le merde au bout de 3 instructions
# # Ensure there is one and only one leave (for OEP discovering)
# mdis = sb.machine.dis_engine(sb.jitter.bs, loc_db=loc_db)
# mdis.dont_dis_nulstart_bloc = True
# asmcfg = mdis.dis_multiblock(sb.entry_point)
#
# leaves = list(asmcfg.get_bad_blocks())
# assert(len(leaves) == 1)
# l = leaves.pop()
# logging.info(l)
# end_offset = mdis.loc_db.get_location_offset(l.loc_key)
#
# logging.info('final offset')
# logging.info(hex(end_offset))

def stop(jitter):
    # print('section .text reached')
    # print('Call to kernel32_GetTickCount reached')
    # print('POPAD reached')
    print('section .text reached 1001')
    # Stop execution
    jitter.running = False
    return False

# Set breakpoints

# sb.jitter.add_breakpoint(0x00A91000, stop) # dont work to make Bravo appear in strings
# sb.jitter.add_breakpoint(0x00A9102C, stop) # work to make Bravo appear in strings # BEEP
# sb.jitter.add_breakpoint(0xa91025, stop) # work to make Bravo appear in strings # GetTickCount
# sb.jitter.add_breakpoint(0xa943AF, stop) # work to make Bravo appear in strings # POPAD
# sb.jitter.add_breakpoint(0xa91001, stop) # debut section .text
# 00A943AF POPAD

# print("EntryPoint:", hex(sb.entry_point))

# Tentative de bypass les protections initiales finalement inutile
# print(hex(sb.entry_point+int(0x0d)))
# sb.run(sb.entry_point+int(0x0d))

def emulate(exe, file):
    parser = Sandbox_Win_x86_32.parser()
    options = parser.parse_args()
    loc_db = LocationDB()
    sb = Sandbox_Win_x86_32(
    loc_db, exe, options, globals(),
    )
    breakpointt = sb.entry_point - 0x3000 # debut section .text
    sb.jitter.add_breakpoint(breakpointt, stop)     
    print("EntryPoint:", hex(sb.entry_point))
    print("Breakpoint:", hex(breakpointt))
    
    # Tentative de pirouette qui ne marche pas    
    # addr = sb.loc_db.get_name_location('my_lstrcmp')
    # print(addr)
    # sb.jitter.add_breakpoint(addr, my_lstrcmp)

    sb.run()
    vm2pe(sb.jitter, "../out_bin-mdo-RE2600/"+file+"unpacked.exe", libs=sb.libs, e_orig=sb.pe)
    # print("LE CODE:", sb.jitter.get_c_str(breakpointt+0x81)) fonctionne uniquement pour notre binaire malheureusement 

# TOUS LES BINAIRES DE L'ARCHIVE !!!
files = os.listdir("../out_bin-mdo-RE2600")
for file in files:
    path = "../out_bin-mdo-RE2600/"+file+"/archives/"+file+"/"+file+".exe"
    if ".sh" in file:
        continue
    emulate(path, file)

# py -i run_all_exe.py ../output_022.exe -z -o -i -b -s -l -y
# py -i run_all_exe.py
