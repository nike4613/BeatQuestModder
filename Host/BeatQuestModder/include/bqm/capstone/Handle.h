#ifndef CAPSTONE_HANDLE_H
#define CAPSTONE_HANDLE_H

#include <iterator>
#include <capstone/capstone.h>
#include "buffer.h"

namespace capstone {
	class RuntimeHandle
	{
		csh handle = 0;
		cs_err error;
	public:
		RuntimeHandle(cs_arch arch, cs_mode mode) noexcept;
		~RuntimeHandle() noexcept;
		[[nodiscard]] constexpr auto Handle() const noexcept { return handle; }
		[[nodiscard]] constexpr auto Error() const noexcept { return error; }

		void Option(cs_opt_type type, size_t value) noexcept;

		[[nodiscard]] buffer<cs_insn> Disassemble(const buffer<uint8_t, false>& data, uint64_t zeroAddress, size_t count = 0) const noexcept;
	};

	template<cs_arch ARCH, cs_mode MODE>
	class Handle : public RuntimeHandle
	{
	public:
		Handle() noexcept : RuntimeHandle(ARCH, MODE) {}
	};

	using ARMHandle = Handle<CS_ARCH_ARM, CS_MODE_ARM>;
}

#endif