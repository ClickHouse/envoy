#pragma once

#include "envoy/network/filter.h"
#include <cstdint>
#include <memory>
#include <mutex>

namespace Envoy {

namespace Buffer {

class Iterator : public std::iterator<std::random_access_iterator_tag, Instance>
{
public:
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    using pointer = char*;
    using reference = char&;
    using iterator_category = std::random_access_iterator_tag;
    
    Iterator() = default;
    Iterator(Instance & data)
        : len(data.length()), slices(data.getRawSlices()), current(slices.begin())
    {}
    Iterator(Instance & data, size_t len_)
        : len(len_), slices(data.getRawSlices()), current(slices.begin())
    {
        if (len > data.length())
            throw std::out_of_range(fmt::format("Buffer::Iterator::ctor with length {} from Buffer::Instance with length", len, data.length()));
    }
    Iterator(const Iterator &rhs) { *this = rhs; }
    Iterator(const Iterator &rhs, size_t len_)
    {
        if (rhs.pos + len_ > rhs.len)
            throw std::out_of_range("Buffer::Iterator::ctor from Iterator extends length beyond range");
        *this = rhs;
        len = pos + len_;
    }
    Iterator & operator=(const Iterator &rhs)
    {
        len = rhs.len;
        pos = rhs.pos;
        slices = rhs.slices;
        current = slices.begin() + (rhs.current - rhs.slices.begin());
        idx = rhs.idx;
        return *this;
    }

    inline Iterator& operator+=(difference_type rhs)
    {
        if (rhs < 0)
            return operator-=(-rhs);

        while (pos < len)
        {
            if (idx + rhs < current->len_)
            {
                if (len - pos < static_cast<size_t>(rhs))
                    throw std::out_of_range("Buffer::Iterator increment beyond range");
                pos += rhs;
                idx += rhs;
                return *this;
            }
            rhs -= (current->len_ - idx);
            pos += (current->len_ - idx);
            idx = 0;
            ++current;
        }

        return *this;
    }

    inline Iterator& operator-=(difference_type rhs)
    {
        if (rhs < 0)
            return operator+=(-rhs);

        for (;;)
        {
            if (idx >= static_cast<size_t>(rhs))
            {
                idx -= rhs;
                pos -= rhs;
                return *this;
            }

            if (current == slices.begin())
                throw std::out_of_range("Buffer::Iterator decrement beyond range");

            rhs -= (idx + 1);
            pos -= (idx + 1);
            --current;
            idx = current->len_ - 1;
        }
    }

    inline reference operator*() const { return reinterpret_cast<pointer>(current->mem_)[idx]; }
    inline pointer operator->() const { return reinterpret_cast<pointer>(current->mem_) + idx; }
    
    inline Iterator& operator++()
    {
        if (!(*this))
            throw std::out_of_range("Buffer::Iterator increment beyond range");

        if (++idx == current->len_)
        {
            idx = 0;
            ++current;
        }
        ++pos;

        return *this; 
    }
    inline Iterator& operator--()
    {
        if (pos == 0)
            throw std::out_of_range("Buffer::Iterator decrement beyond range");
        
        if (idx == 0)
            idx = ++current->len_ - 1;
        --pos;

        return *this;
    }
    inline Iterator operator++(int) const { Iterator tmp(*this); return ++tmp; }
    inline Iterator operator--(int) const { Iterator tmp(*this); return --tmp; }

    inline difference_type operator-(const Iterator& rhs) const { return static_cast<difference_type>(pos) - rhs.pos; }
    inline Iterator operator+(difference_type rhs) const { return Iterator(*this).operator+=(rhs); }
    inline Iterator operator-(difference_type rhs) const { return Iterator(*this).operator-=(rhs); }
    
    inline bool operator==(const Iterator& rhs) const { return pos == rhs.pos; }
    inline bool operator!=(const Iterator& rhs) const { return !operator==(rhs); }
    inline bool operator>(const Iterator& rhs) const { return *this - rhs > 0; }
    inline bool operator<(const Iterator& rhs) const { return !(operator>(rhs) || operator==(rhs)); }
    inline bool operator>=(const Iterator& rhs) const { return operator==(rhs) || operator>(rhs); }
    inline bool operator<=(const Iterator& rhs) const { return operator==(rhs) || operator<(rhs); }

    inline operator bool() const { return pos < len; }

    inline difference_type position() const { return pos; }
    inline difference_type available() const { return len - pos; }
    inline difference_type length() const { return len; }

    inline Iterator begin() const
    {
        Iterator tmp(*this);
        tmp.idx = 0;
        tmp.pos = 0;
        tmp.current = tmp.slices.begin();
        return tmp;
    }

    inline Iterator end() const
    {
        Iterator tmp(*this);
        tmp += (len - pos);
        return tmp;
    }
private:
    size_t len = 0;
    size_t pos = 0;
    RawSliceVector slices;
    RawSliceVector::iterator current;
    size_t idx = 0;
};

} // namespace Buffer

namespace Extensions {
namespace NetworkFilters {
namespace ClickHouse {

/// Simple synchronized object, can be constructed with either internal or external mutex.
template <typename T>
struct Synchronized
{
    T value {};
    std::unique_ptr<std::mutex> int_mutex;
    std::mutex & mutex;

    T get() const
    {
        std::lock_guard lock(mutex);
        return value;
    }
    void set(const T & v)
    {
        std::lock_guard lock(mutex);
        value = v;
    }

    Synchronized() : int_mutex(std::make_unique<std::mutex>()), mutex(*int_mutex) {}
    explicit Synchronized(const T & v) : value(v), int_mutex(std::make_unique<std::mutex>()), mutex(*int_mutex) {}
    Synchronized(const T & v, std::mutex & mutex) : value(v), mutex(mutex) {}
    explicit Synchronized(std::mutex & mutex) : mutex(mutex) {}
};


} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
