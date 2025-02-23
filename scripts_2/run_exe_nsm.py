from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
from miasm.jitter.loader.pe import vm2pe
import os
import logging

parser = Sandbox_Win_x86_32.parser()
parser.add_argument('filename', help='The filename of the executable to run')
options = parser.parse_args()

loc_db = LocationDB()
sb = Sandbox_Win_x86_32(
    loc_db, options.filename, options, globals(),
)

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
    print('POPAD reached')
    # Stop execution
    jitter.running = False
    return False

# Set breakpoints
# sb.jitter.add_breakpoint(0x00A91000, stop) # dont work to make Bravo appear in strings
# sb.jitter.add_breakpoint(0x00A9102C, stop) # work to make Bravo appear in strings # BEEP
# sb.jitter.add_breakpoint(0xa91025, stop) # work to make Bravo appear in strings # GetTickCount
sb.jitter.add_breakpoint(0xa943AF, stop) # work to make Bravo appear in strings # POPAD

# 00A943AF POPAD

print(sb.entry_point)
# print(hex(sb.entry_point+int(0x0d)))
# sb.run(sb.entry_point+int(0x0d))
sb.run()

# Construct the output filename
bname, fname = os.path.split(options.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
out_fname = fname + '_unupx.exe'

print("Saving to %s" % out_fname)
vm2pe(sb.jitter, out_fname, libs=sb.libs, e_orig=sb.pe)
