#include "bqm/capstone/Handle.h"

using namespace capstone;

template<>
cs_insn* CapstoneAllocator<cs_insn>::allocate(size_t n) const noexcept
{
	return nullptr; // should be unreachable
}
template<>
void CapstoneAllocator<cs_insn>::deallocate(cs_insn* p, size_t n) const noexcept
{
	cs_free(p, n);
}

capstone::RuntimeHandle::RuntimeHandle(cs_arch arch, cs_mode mode) noexcept
{
	error = cs_open(arch, mode, &handle);
	if (error == CS_ERR_OK)
		Option(CS_OPT_DETAIL, CS_OPT_ON);
}

capstone::RuntimeHandle::~RuntimeHandle() noexcept
{
	if (handle != 0)
		cs_close(&handle);
}

void capstone::RuntimeHandle::Option(cs_opt_type type, size_t value) noexcept
{
	error = cs_option(handle, type, value);
}

buffer<cs_insn, CapstoneAllocator> capstone::RuntimeHandle::Disassemble(const const_buffer<uint8_t>& data, uint64_t zeroAddress, size_t count) const noexcept
{
	cs_insn* instructions;
	auto icount = cs_disasm(handle, data.data(), data.size(), zeroAddress, count, &instructions);
	return buffer<cs_insn, CapstoneAllocator>(instructions, icount, true);
}
