#ifndef BUFFER_H
#define BUFFER_H

#include <cstddef>
#include <memory>
#include <cstdlib>
#include <stdexcept>
#include <functional>
#include <type_traits>
#include <utility>
#include <cstring>

template<typename T>
// read-only buffer
class const_buffer
{
	const T* memptr;
	size_t size_;
public:
	// no need to copy
	constexpr const_buffer(const const_buffer<T>& other) noexcept : memptr(other.data()), size_(other.size()) {}
	// no need to transfer ownership
	constexpr const_buffer(const const_buffer<T>&& other) noexcept : const_buffer(other.data(), other.size()) {}

	constexpr const_buffer() noexcept : memptr(nullptr), size_(0) {}
	constexpr const_buffer(const T* ptr, size_t count) noexcept : memptr(ptr), size_(count) {}
	~const_buffer() noexcept = default;

	constexpr const_buffer<T>& operator=(const const_buffer<T>& other) {
		std::swap(memptr, other.memptr); std::swap(size_, other.size_);
		return *this;
	}
	constexpr const_buffer<T>& operator=(const const_buffer<T>&& other) {
		memptr = other.memptr; size_ = other.size_;
		return *this;
	}

	[[nodiscard]] constexpr auto is_writable() const noexcept { return false; }

	[[nodiscard]] constexpr auto data() const noexcept { return memptr; }
	[[nodiscard]] constexpr auto size() const noexcept { return size_; }
	[[nodiscard]] constexpr auto empty() const noexcept { return size() == 0; }

	// does not do bounds checking
	[[nodiscard]] constexpr auto slice(size_t start, size_t len) const noexcept { return const_buffer<T>(data() + start, len); }
	[[nodiscard]] constexpr auto slice(size_t len) const noexcept { return slice(0, len); }
	[[nodiscard]] constexpr auto strip(size_t dist) const noexcept { return slice(size() - dist); }

	template<typename U>
	[[nodiscard]] auto reinterpret_as() const noexcept { return const_buffer<U>(reinterpret_cast<const U*>(data()), size()); }

	[[nodiscard]] constexpr const T& operator[](size_t index) const noexcept { return memptr[index]; }

	[[nodiscard]] constexpr const T& at(size_t index) const {
		if (index < size()) return (*this)[index];
		else throw std::out_of_range("index out of range of buffer");
	}

	using iterator = T const*;

	[[nodiscard]] constexpr const iterator begin() const noexcept { return data(); }
	[[nodiscard]] constexpr const iterator end() const noexcept { return data() + size(); }
};

template<typename T, template<typename> class Alloc = std::allocator>
// readwrite buffer
class buffer
{
	T* memptr;
	size_t size_;
	bool ownAlloc = false;

	using trait = std::allocator_traits<Alloc<T>>;
	typename trait::allocator_type allocator{};

	// allocate ourselves
	buffer(size_t count, std::nullptr_t) noexcept : size_(count), ownAlloc(true), allocator({}) {
		memptr = trait::allocate(allocator, count);
	}
	constexpr void adjust(size_t ptr_off, size_t size) noexcept { memptr += ptr_off; size_ = size; }
public:
	// require a readonly to copy
	constexpr buffer(const const_buffer<T>& other) noexcept : buffer(other.size(), nullptr)
		{ memcpy(memptr, other.data(), size_); }
	// properly transfer ownership
	constexpr buffer(const buffer<T, Alloc>&& other) noexcept : buffer(other.memptr, other.size_, std::move(other.allocator))
		{ ownAlloc = other.ownAlloc; other.ownAlloc = false; }

	buffer() noexcept : buffer(static_cast<size_t>(0)) {}
	buffer(size_t count) noexcept : buffer(count, nullptr) {}
	constexpr buffer(T* ptr, size_t count, bool dealloc = false) noexcept : memptr(ptr), size_(count), ownAlloc(dealloc), allocator({}) {}
	~buffer() noexcept {
		if (ownAlloc) {
			trait::deallocate(allocator, memptr, size());
		}
	}

	constexpr buffer<T, Alloc>& operator=(const buffer<T, Alloc>& other) {
		std::swap(memptr, other.memptr); std::swap(size_, other.size_); std::swap(ownAlloc, other.ownAlloc);
		std::swap(allocator, other.allocator);
		return *this;
	}

	constexpr buffer<T, Alloc>& operator=(buffer<T, Alloc>&& other) {
		this->~buffer(); // explicitly call destructor to make sure that the old form is cleaned properly
		memptr = other.memptr; size_ = other.size_; ownAlloc = other.ownAlloc; other.ownAlloc = false;
		allocator = std::move(other.allocator);
		return *this;
	}

	[[nodiscard]] constexpr auto is_writable() const noexcept { return true; }

	[[nodiscard]] constexpr auto data() const noexcept { return memptr; }
	[[nodiscard]] constexpr auto size() const noexcept { return size_; }
	[[nodiscard]] constexpr auto empty() const noexcept { return size() == 0; }

	// does not do bounds checking; gives a readonly view into this buffer
	[[nodiscard]] constexpr auto slice(size_t start, size_t len) const noexcept { return const_buffer<T>(data() + start, len); }
	[[nodiscard]] constexpr auto slice(size_t len) const noexcept { return slice(0, len); }
	[[nodiscard]] constexpr auto strip(size_t dist) const noexcept { return slice(size() - dist); }

	[[nodiscard]] constexpr auto as_const() const noexcept { return slice(size()); }

	// implicit conversion avoids copying data
	constexpr operator const_buffer<T>() const noexcept { return as_const(); }

	[[nodiscard]] constexpr const T& operator[](size_t index) const noexcept { return memptr[index]; }
	[[nodiscard]] constexpr T& operator[](size_t index) noexcept { return memptr[index]; }

	[[nodiscard]] constexpr const T& at(size_t index) const {
		if (index < size()) return (*this)[index];
		else throw std::out_of_range("index out of range of buffer");
	}
	[[nodiscard]] constexpr T& at(size_t index) {
		if (index < size()) return (*this)[index];
		else throw std::out_of_range("index out of range of buffer");
	}

	using iterator = T *;

	[[nodiscard]] constexpr iterator begin() noexcept { return data(); }
	[[nodiscard]] constexpr const iterator begin() const noexcept { return data(); }
	[[nodiscard]] constexpr iterator end() noexcept { return data() + size(); }
	[[nodiscard]] constexpr const iterator end() const noexcept { return data() + size(); }
};

template<typename T>
constexpr auto make_buffer(T* data, size_t size) noexcept { return buffer<T>(data, size); }
template<typename T>
constexpr auto make_buffer(const T* data, size_t size) noexcept { return const_buffer<T>(data, size); }
template<typename T, size_t Count>
constexpr auto make_buffer(T(&data)[Count]) noexcept { return make_buffer(data, Count); }
template<typename T, size_t Count>
constexpr auto make_buffer(const T(&data)[Count]) noexcept { return make_buffer(data, Count); }

constexpr auto operator""_buffer(const char* chars, size_t len) noexcept { return make_buffer(chars, len); }
constexpr auto operator""_buffer(const wchar_t* chars, size_t len) noexcept { return make_buffer(chars, len); }
//constexpr auto operator""_buffer(const char8_t* chars, size_t len) noexcept { return make_buffer(chars, len); } // C++ 20
constexpr auto operator""_buffer(const char16_t* chars, size_t len) noexcept { return make_buffer(chars, len); }
constexpr auto operator""_buffer(const char32_t* chars, size_t len) noexcept { return make_buffer(chars, len); }

#endif