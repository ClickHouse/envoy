#pragma once

#include "envoy/network/filter.h"
#include <cstdint>
#include <memory>

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
        : len_(data.length()), slices_(data.getRawSlices()), current_(slices_.begin())
    {}
    Iterator(const Iterator &rhs) { *this = rhs; }
    Iterator & operator=(const Iterator &rhs)
    {
        len_ = rhs.len_;
        pos_ = rhs.pos_;
        slices_ = rhs.slices_;
        current_ = slices_.begin() + (rhs.current_ - rhs.slices_.begin());
        idx_ = rhs.idx_;
        return *this;
    }
    /* inline Iterator& operator=(Type* rhs) {_ptr = rhs; return *this;} */
    /* inline Iterator& operator=(const Iterator &rhs) {_ptr = rhs._ptr; return *this;} */

    inline Iterator& operator+=(difference_type rhs)
    {
        if (rhs < 0)
            return operator-=(-rhs);

        while (pos_ < len_)
        {
            if (idx_ + rhs < current_->len_)
            {
                if (len_ - pos_ < static_cast<size_t>(rhs))
                {
                    pos_ = len_;
                    idx_ += len_ - pos_;
                }
                else
                {
                    pos_ += rhs;
                    idx_ += rhs;
                }
                return *this;
            }
            rhs -= (current_->len_ - idx_);
            pos_ += (current_->len_ - idx_);
            idx_ = 0;
            ++current_;
        }

        return *this;
    }

    inline Iterator& operator-=(difference_type rhs)
    {
        if (rhs < 0)
            return operator+=(-rhs);

        for (;;)
        {
            if (idx_ >= static_cast<size_t>(rhs))
            {
                idx_ -= rhs;
                pos_ -= rhs;
                return *this;
            }

            if (current_ == slices_.begin())
                throw std::out_of_range("");

            rhs -= (idx_ + 1);
            pos_ -= (idx_ + 1);
            --current_;
            idx_ = current_->len_ - 1;
        }
    }

    inline reference operator*() const { return reinterpret_cast<pointer>(current_->mem_)[idx_]; }
    inline pointer operator->() const { return reinterpret_cast<pointer>(current_->mem_) + idx_; }
//    inline reference operator[](difference_type rhs) const {return _ptr[rhs];}
    
    inline Iterator& operator++()
    {
        if (!(*this))
            throw std::out_of_range("");

        if (++idx_ == current_->len_)
        {
            idx_ = 0;
            ++current_;
        }
        ++pos_;

        return *this; 
    }
    inline Iterator& operator--()
    {
        if (pos_ == 0)
            throw std::out_of_range("");
        
        if (idx_ == 0)
            idx_ = ++current_->len_ - 1;
        --pos_;

        return *this;
    }
    inline Iterator operator++(int) const { Iterator tmp(*this); return ++tmp; }
    inline Iterator operator--(int) const { Iterator tmp(*this); return --tmp; }
    /* inline Iterator operator+(const Iterator& rhs) {return Iterator(_ptr+rhs.ptr);} */
    inline difference_type operator-(const Iterator& rhs) const { return static_cast<difference_type>(pos_) - rhs.pos_; }
    inline Iterator operator+(difference_type rhs) const { return Iterator(*this).operator+=(rhs); }
    inline Iterator operator-(difference_type rhs) const { return Iterator(*this).operator-=(rhs); }
//    friend inline Iterator operator+(difference_type lhs, const Iterator& rhs) {return Iterator(lhs+rhs._ptr);}
//    friend inline Iterator operator-(difference_type lhs, const Iterator& rhs) {return Iterator(lhs-rhs._ptr);}
    
    inline bool operator==(const Iterator& rhs) const { return pos_ == rhs.pos_; }
    inline bool operator!=(const Iterator& rhs) const { return !operator==(rhs); }
    inline bool operator>(const Iterator& rhs) const { return *this - rhs > 0; }
    inline bool operator<(const Iterator& rhs) const { return !(operator>(rhs) || operator==(rhs)); }
    inline bool operator>=(const Iterator& rhs) const { return operator==(rhs) || operator>(rhs); }
    inline bool operator<=(const Iterator& rhs) const { return operator==(rhs) || operator<(rhs); }

    inline operator bool() const { return pos_ < len_; }

    inline Iterator begin() const
    {
        Iterator tmp(*this);
        tmp.idx_ = 0;
        tmp.pos_ = 0;
        tmp.current_ = tmp.slices_.begin();
        return tmp;
    }

    inline Iterator end() const
    {
        Iterator tmp(*this);
        tmp += (len_ - pos_);
        return tmp;
    }
private:
    size_t len_ = 0;
    size_t pos_ = 0;
    RawSliceVector slices_;
    RawSliceVector::iterator current_;
    size_t idx_ = 0;
};

} // namespace Buffer

namespace Extensions {
namespace NetworkFilters {
namespace ClickHouse {

// Read the variable length integer from the buffer into the value.
// Offset will be modified after reading.
// ClickHouse version LEB128 encoding.
bool readVarUInt(Buffer::Instance& data, uint64_t& offset, uint64_t& value);

void readStringBinary(Buffer::Instance& data, uint64_t& offset, std::string& s);

} // namespace ClickHouse
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
