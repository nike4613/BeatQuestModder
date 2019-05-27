#ifndef BUFFER_H
#define BUFFER_H

#include <cstddef>
#include <memory>
#include <cstdlib>
#include <stdexcept>
#include <functional>
#include <type_traits>


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
public:
	template<bool readwrite>
	// copy actual buffer data
	constexpr buffer(const buffer<T, readwrite>& other) noexcept : buffer(other.size()) { memcpy(memptr, other.data(), size_); }
	// properly transfer ownership
	constexpr buffer(const buffer<T, true>&& other) noexcept : buffer(other.memptr, other.size_, std::move(other.deallocator)) {
		ownAlloc = other.ownAlloc; other.ownAlloc = false;
	}

	buffer() noexcept : buffer(static_cast<size_t>(0)) {}
	buffer(size_t count) noexcept : size_(count), ownAlloc(true) {
		memptr = reinterpret_cast<T*>(malloc(size_ * sizeof(T)));
	}
	constexpr buffer(T* ptr, size_t count, std::function<void(T*)> dealloc) noexcept : buffer(ptr, count, [dealloc](T* m, size_t s) { dealloc(m); }) {}
	constexpr buffer(T* ptr, size_t count, dealloc_t dealloc) noexcept : buffer(ptr, count) { deallocator = dealloc; }
	constexpr buffer(T* ptr, size_t count) noexcept : memptr(ptr), size_(count), ownAlloc(false) {}
	~buffer() noexcept {
		if (ownAlloc) free(memptr);
		else if (deallocator) deallocator(memptr, size());
	}

	[[nodiscard]] constexpr auto is_writable() const noexcept { return true; }

	[[nodiscard]] constexpr auto data() const noexcept { return memptr; }
	[[nodiscard]] constexpr auto size() const noexcept { return size_; }
	[[nodiscard]] constexpr auto empty() const noexcept { return size() == 0; }

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
	constexpr buffer(const buffer<T, true>& other) noexcept : memptr(other.data()), size_(other.size()), rwBuffer(other) {}
	// no need to copy
	constexpr buffer(const buffer<T, false>& other) noexcept : memptr(other.data()), size_(other.size()), rwBuffer(nullptr) {}
	// no need to transfer ownership
	constexpr buffer(const buffer<T, false>&& other) noexcept : buffer(other.data(), other.size()) {}

	constexpr buffer() noexcept : memptr(nullptr), size_(0), rwBuffer(nullptr) {}
	constexpr buffer(const T* ptr, size_t count) noexcept : memptr(ptr), size_(count), rwBuffer(nullptr) {}
	~buffer() noexcept {}

	[[nodiscard]] constexpr auto is_writable() const noexcept { return false; }
	template<typename U>
	[[nodiscard]] constexpr auto reinterpret_as() const noexcept { return buffer<U, false>(reinterpret_cast<const U*>(memptr), size_); }

	[[nodiscard]] constexpr auto data() const noexcept { return memptr; }
	[[nodiscard]] constexpr auto size() const noexcept { return size_; }
	[[nodiscard]] constexpr auto empty() const noexcept { return size() == 0; }

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