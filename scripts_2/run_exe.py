from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
import os
import logging


parser = Sandbox_Win_x86_32.parser()
parser.add_argument('filename', help='The filename of the executable to run')
options = parser.parse_args()
options.load_hdr = True

loc_db = LocationDB()
sb = Sandbox_Win_x86_32(
    loc_db, options.filename, options, globals(),
)

# Ensure there is one and only one leave (for OEP discovering)
mdis = sb.machine.dis_engine(sb.jitter.bs, loc_db=loc_db)
mdis.dont_dis_nulstart_bloc = True
asmcfg = mdis.dis_multiblock(sb.entry_point)

leaves = list(asmcfg.get_bad_blocks())
assert(len(leaves) == 1)
l = leaves.pop()
logging.info(l)
end_offset = mdis.loc_db.get_location_offset(l.loc_key)


def stop(jitter):
    logging.info('OEP reached')

    # Stop execution
    jitter.running = False
    return False

sb.jitter.add_breakpoint(end_offset, stop)

# avoid crash
# sb.jitter.vm.add_memory_page(

# Run
sb.run(run_addr)

# Construct the output filename
bname, fname = os.path.split(options.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
out_fname = fname + '_unupx.bin'

# Rebuild the PE thanks to `vm2pe`
#
# vm2pe will:
# - set the new entry point to the current address (ie, the OEP)
# - dump each section from the virtual memory into the new PE
# - use `sb.libs` to generate a new import directory, and use it in the new PE
# - save the resulting PE in `out_fname`

vm2pe(sb.jitter, out_fname, libs=sb.libs, e_orig=sb.pe)
