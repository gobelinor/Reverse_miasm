from __future__ import print_function
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
from miasm.jitter.loader.pe import vm2pe
from miasm.os_dep.common import get_win_str_a
import os
import logging

# py -i run_exe_nsm.py ../output_022.exe -z -o -i -b -s -l -y

# Permet de "reconstruire" l'Import Table, mais fonctionne moyennement bien 
def kernel32_GetProcAddress(jitter):
    ret_ad, args = jitter.func_args_stdcall(["libbase", "fname"])
    # When the function is called, EBX is a pointer to the destination buffer
    print('Call to kernel32_GetProcAddress reached')
    dst_ad = jitter.cpu.EBX
    logging.error('EBX ' + hex(dst_ad))
    # Handle ordinal imports
    fname = (args.fname if args.fname < 0x10000
             else get_win_str_a(jitter, args.fname))
    logging.error(fname)
    # Get the generated address of the library, and store it in memory to
    # dst_ad
    ad = sb.libs.lib_get_add_func(args.libbase, fname, dst_ad)
    print(sb.libs)
    # Add a breakpoint in case of a call on the resolved function
    # NOTE: never happens in UPX, just for skeleton
    jitter.handle_function(ad)
    jitter.func_ret_stdcall(ret_ad, ad)

# Si on veut que le binaire s'execute en entier 
# def kernel32_Beep(jitter):
#     print('Call to kernel32_Beep reached')
#     ret_ad, args = jitter.func_args_stdcall(["dwFreq", "dwDuration"])
#     # ptr1 = jitter.get_arg_n_cdecl(1)
#     # ptr2 = jitter.get_arg_n_cdecl(2)
#     # print(ptr1)
#     # print(ptr2)
#     jitter.func_ret_stdcall(ret_ad, 1)
#     # return 0

parser = Sandbox_Win_x86_32.parser()
parser.add_argument('filename', help='The filename of the executable to run')
options = parser.parse_args()

loc_db = LocationDB()
sb = Sandbox_Win_x86_32(
    loc_db, options.filename, options, globals(),
)

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
    logging.info('section .text reached')
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
sb.jitter.add_breakpoint(0xa91001, stop) # debut section .text
# 00A943AF POPAD

print("EntryPoint:", hex(sb.entry_point))
# print(hex(sb.entry_point+int(0x0d)))
# sb.run(sb.entry_point+int(0x0d))
sb.run()

# Construct the output filename
bname, fname = os.path.split(options.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
out_fname = fname + '_unupx_clean.exe'

print("Saving to %s" % out_fname)

# Rebuild the PE thanks to `vm2pe`
#
# vm2pe will:
# - set the new entry point to the current address (ie, the OEP)
# - dump each section from the virtual memory into the new PE
# - use `sb.libs` to generate a new import directory, and use it in the new PE
# - save the resulting PE in `out_fname`

vm2pe(sb.jitter, out_fname, libs=sb.libs, e_orig=sb.pe)


# py -i run_exe_nsm.py ../output_022.exe -z -o -i -b -s -l -y
# py -i run_all_exe.py ../output_022.exe
