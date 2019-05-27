#include "CapstoneHandle.h"

using namespace capstone;

capstone::Handle_::Handle_(cs_arch arch, cs_mode mode) noexcept
{
	error = cs_open(arch, mode, &handle);
	if (error == CS_ERR_OK)
		Option(CS_OPT_DETAIL, CS_OPT_ON);
}

capstone::Handle_::~Handle_() noexcept
{
	if (handle != 0)
		cs_close(&handle);
}

void capstone::Handle_::Option(cs_opt_type type, size_t value) noexcept
{
	error = cs_option(handle, type, value);
}

buffer<cs_insn> capstone::Handle_::Disassemble(const buffer<uint8_t, false>& data, uint64_t zeroAddress, size_t count) const noexcept 
{
	cs_insn* instructions;
	auto icount = cs_disasm(handle, data.data(), data.size(), zeroAddress, count, &instructions);
	return buffer<cs_insn>(instructions, icount, [](cs_insn* mem, size_t size) { cs_free(mem, size); });
}
