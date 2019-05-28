#ifndef BUFFER_H
#define BUFFER_H

#include <cstddef>
#include <memory>
#include <cstdlib>
#include <stdexcept>
#include <functional>
#include <type_traits>
#include <utility>

template<typename T, bool readwrite = true> class buffer;

template<typename T>
// readwrite buffer
class buffer<T, true>
{
	T* memptr;
	size_t size_;
	bool ownAlloc;

	using dealloc_t = std::function<void(T*, size_t)>;
	dealloc_t deallocator;

	friend class buffer<T, false>;
	friend class buffer<T, true>;

	constexpr buffer(std::nullptr_t) noexcept : memptr(nullptr), size_(0), ownAlloc(false), deallocator({}) {}
	constexpr void adjust(size_t ptr_off, size_t size) noexcept { memptr += ptr_off; size_ = size; }
public:
	// require a readonly to copy
	constexpr buffer(const buffer<T, false>& other) noexcept : buffer(other.size()) { memcpy(memptr, other.data(), size_); }
	// properly transfer ownership
	constexpr buffer(const buffer<T, true>&& other) noexcept : buffer(other.memptr, other.size_, std::move(other.deallocator)) {
		ownAlloc = other.ownAlloc; other.ownAlloc = false;
	}

	buffer() noexcept : buffer(static_cast<size_t>(0)) {}
	buffer(size_t count) noexcept : size_(count), ownAlloc(true) {
		memptr = new T[size_];
	}
	constexpr buffer(T* ptr, size_t count, std::function<void(T*)> dealloc) noexcept : buffer(ptr, count, [dealloc](T* m, size_t s) { dealloc(m); }) {}
	constexpr buffer(T* ptr, size_t count, dealloc_t dealloc) noexcept : buffer(ptr, count) { deallocator = dealloc; }
	constexpr buffer(T* ptr, size_t count) noexcept : memptr(ptr), size_(count), ownAlloc(false) {}
	~buffer() noexcept {
		if (ownAlloc) delete memptr;
		else if (deallocator) deallocator(memptr, size());
	}

	constexpr buffer<T, true>& operator=(const buffer<T, true>& other) {
		std::swap(memptr, other.memptr); std::swap(size_, other.size_); std::swap(ownAlloc, other.ownAlloc);
		std::swap(deallocator, other.deallocator);
		return *this;
	}

	constexpr buffer<T, true>& operator=(buffer<T, true>&& other) {
		memptr = other.memptr; size_ = other.size_; ownAlloc = other.ownAlloc; other.ownAlloc = false;
		deallocator = std::move(other.deallocator);
		return *this;
	}

	[[nodiscard]] constexpr auto is_writable() const noexcept { return true; }

	[[nodiscard]] constexpr auto data() const noexcept { return memptr; }
	[[nodiscard]] constexpr auto size() const noexcept { return size_; }
	[[nodiscard]] constexpr auto empty() const noexcept { return size() == 0; }

	// does not do bounds checking; gives a readonly view into this buffer
	[[nodiscard]] constexpr auto slice(size_t start, size_t len) const noexcept { return buffer<T, false>(data() + start, len); }
	[[nodiscard]] constexpr auto slice(size_t len) const noexcept { return slice(0, len); }

	[[nodiscard]] constexpr auto as_readonly() const noexcept { return slice(size()); }

	// implicit conversion avoids copying data
	constexpr operator buffer<T, false>() const noexcept { return as_readonly(); }

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
// read-only buffer
class buffer<T, false>
{
	const T* memptr;
	size_t size_;

	buffer<T, true> rwBuffer;
public:
	// keep a hold of the other buffer
	explicit constexpr buffer(const buffer<T, true>& other) noexcept : rwBuffer(other.as_readonly()) 
		{ memptr = rwBuffer.data(); size_ = rwBuffer.size(); }
	// no need to copy
	constexpr buffer(const buffer<T, false>& other) noexcept : memptr(other.data()), size_(other.size()), rwBuffer(nullptr) {}
	// no need to transfer ownership
	constexpr buffer(const buffer<T, false>&& other) noexcept : buffer(other.data(), other.size()) {}

	constexpr buffer() noexcept : memptr(nullptr), size_(0), rwBuffer(nullptr) {}
	constexpr buffer(const T* ptr, size_t count) noexcept : memptr(ptr), size_(count), rwBuffer(nullptr) {}
	~buffer() noexcept {}

	constexpr buffer<T, false>& operator=(const buffer<T, false>& other) {
		std::swap(memptr, other.memptr); std::swap(size_, other.size_);
		std::swap(rwBuffer, other.rwBuffer);
		return *this;
	}
	constexpr buffer<T, false>& operator=(const buffer<T, false>&& other) {
		memptr = other.memptr; size_ = other.size_;
		rwBuffer = std::move(other.rwBuffer);
		return *this;
	}

	[[nodiscard]] constexpr auto is_writable() const noexcept { return false; }
	template<typename U>
	[[nodiscard]] constexpr auto reinterpret_as() const noexcept { 
		static_assert(sizeof(T) == sizeof(U));
		return buffer<U, false>(reinterpret_cast<const U*>(memptr), size_); 
	}

	[[nodiscard]] constexpr auto data() const noexcept { return memptr; }
	[[nodiscard]] constexpr auto size() const noexcept { return size_; }
	[[nodiscard]] constexpr auto empty() const noexcept { return size() == 0; }

	// does not do bounds checking
	[[nodiscard]] constexpr auto slice(size_t start, size_t len) const noexcept { return buffer<T, false>(data() + start, len); }
	[[nodiscard]] constexpr auto slice(size_t len) const noexcept { return slice(0, len); }

	[[nodiscard]] constexpr const T& operator[](size_t index) const noexcept { return memptr[index]; }

	[[nodiscard]] constexpr const T& at(size_t index) const {
		if (index < size()) return (*this)[index];
		else throw std::out_of_range("index out of range of buffer");
	}

	using iterator = T const*;

	[[nodiscard]] constexpr const iterator begin() const noexcept { return data(); }
	[[nodiscard]] constexpr const iterator end() const noexcept { return data() + size(); }
};

template<typename T>
using const_buffer = buffer<T, false>;

template<typename T>
constexpr auto make_buffer(T* data, size_t size) { return buffer<T>(data, size); }
template<typename T>
constexpr auto make_buffer(const T* data, size_t size) { return const_buffer<T>(data, size); }
template<typename T, size_t Count>
constexpr auto make_buffer(T(&data)[Count]) { return make_buffer(data, Count); }
template<typename T, size_t Count>
constexpr auto make_buffer(const T(&data)[Count]) { return make_buffer(data, Count); }

#endif