#ifndef CAPSTONE_HANDLE_H
#define CAPSTONE_HANDLE_H

#include <iterator>
#include <capstone/capstone.h>
#include "buffer.h"

namespace capstone {
	template<typename T>
	struct CapstoneAllocator  {
		using value_type = T;
		constexpr CapstoneAllocator() noexcept = default;
		constexpr CapstoneAllocator(const CapstoneAllocator<T>&) noexcept = default;
		constexpr CapstoneAllocator(CapstoneAllocator<T>&&) noexcept = default;
		CapstoneAllocator<T>& operator=(const CapstoneAllocator<T>&) noexcept = default;
		[[nodiscard]] T* allocate(size_t n) const noexcept;
		void deallocate(T* ptr, size_t n) const noexcept;
		[[nodiscard]] constexpr bool operator==(const CapstoneAllocator<T>&) const noexcept { return true; }
		[[nodiscard]] constexpr bool operator!=(const CapstoneAllocator<T>& o) const noexcept { return !(*this==o); }
	};
	template struct CapstoneAllocator<cs_insn>;

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

		[[nodiscard]] buffer<cs_insn, CapstoneAllocator> Disassemble(const const_buffer<uint8_t>& data, uint64_t zeroAddress, size_t count = 0) const noexcept;
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