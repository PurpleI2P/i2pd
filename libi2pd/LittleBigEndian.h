// LittleBigEndian.h fixed for 64-bits added union
//

#ifndef LITTLEBIGENDIAN_H
#define LITTLEBIGENDIAN_H

// Determine Little-Endian or Big-Endian

#define CURRENT_BYTE_ORDER       (*(int *)"\x01\x02\x03\x04")
#define LITTLE_ENDIAN_BYTE_ORDER 0x04030201
#define BIG_ENDIAN_BYTE_ORDER    0x01020304
#define PDP_ENDIAN_BYTE_ORDER    0x02010403

#define IS_LITTLE_ENDIAN (CURRENT_BYTE_ORDER == LITTLE_ENDIAN_BYTE_ORDER)
#define IS_BIG_ENDIAN    (CURRENT_BYTE_ORDER == BIG_ENDIAN_BYTE_ORDER)
#define IS_PDP_ENDIAN    (CURRENT_BYTE_ORDER == PDP_ENDIAN_BYTE_ORDER)

// Forward declaration

template<typename T>
struct LittleEndian;

template<typename T>
struct BigEndian;

// Little-Endian template

#pragma pack(push,1)
template<typename T>
struct LittleEndian
{
    union
    {
        unsigned char bytes[sizeof(T)];
        T raw_value;
    };

    LittleEndian(T t = T())
    {
        operator =(t);
    }

    LittleEndian(const LittleEndian<T> & t)
    {
        raw_value = t.raw_value;
    }

    LittleEndian(const BigEndian<T> & t)
    {
        for (unsigned i = 0; i < sizeof(T); i++)
            bytes[i] = t.bytes[sizeof(T)-1-i];
    }

    operator const T() const
    {
        T t = T();
        for (unsigned i = 0; i < sizeof(T); i++)
            t |= T(bytes[i]) << (i << 3);
        return t;
    }

	const T operator = (const T t)
	{
		for (unsigned i = 0; i < sizeof(T); i++)
			bytes[sizeof(T)-1 - i] = static_cast<unsigned char>(t >> (i << 3));
		return t;
	}

    // operators

    const T operator += (const T t)
    {
        return (*this = *this + t);
    }

    const T operator -= (const T t)
    {
        return (*this = *this - t);
    }

    const T operator *= (const T t)
    {
        return (*this = *this * t);
    }

    const T operator /= (const T t)
    {
        return (*this = *this / t);
    }

    const T operator %= (const T t)
    {
        return (*this = *this % t);
    }

    LittleEndian<T> operator ++ (int)
    {
        LittleEndian<T> tmp(*this);
        operator ++ ();
        return tmp;
    }

    LittleEndian<T> & operator ++ ()
    {
        for (unsigned i = 0; i < sizeof(T); i++)
        {
            ++bytes[i];
            if (bytes[i] != 0)
                break;
        }
        return (*this);
    }

    LittleEndian<T> operator -- (int)
    {
        LittleEndian<T> tmp(*this);
        operator -- ();
        return tmp;
    }

    LittleEndian<T> & operator -- ()
    {
        for (unsigned i = 0; i < sizeof(T); i++)
        {
            --bytes[i];
            if (bytes[i] != (T)(-1))
                break;
        }
        return (*this);
    }
};
#pragma pack(pop)

// Big-Endian template

#pragma pack(push,1)
template<typename T>
struct BigEndian
{
    union
    {
        unsigned char bytes[sizeof(T)];
        T raw_value;
    };

    BigEndian(T t = T())
    {
        operator =(t);
    }

    BigEndian(const BigEndian<T> & t)
    {
        raw_value = t.raw_value;
    }

    BigEndian(const LittleEndian<T> & t)
    {
        for (unsigned i = 0; i < sizeof(T); i++)
            bytes[i] = t.bytes[sizeof(T)-1-i];
    }

    operator const T() const
    {
        T t = T();
        for (unsigned i = 0; i < sizeof(T); i++)
            t |= T(bytes[sizeof(T) - 1 - i]) << (i << 3);
        return t;
    }

    const T operator = (const T t)
    {
        for (unsigned i = 0; i < sizeof(T); i++)
            bytes[sizeof(T) - 1 - i] = t >> (i << 3);
        return t;
    }

    // operators

    const T operator += (const T t)
    {
        return (*this = *this + t);
    }

    const T operator -= (const T t)
    {
        return (*this = *this - t);
    }

    const T operator *= (const T t)
    {
        return (*this = *this * t);
    }

    const T operator /= (const T t)
    {
        return (*this = *this / t);
    }

    const T operator %= (const T t)
    {
        return (*this = *this % t);
    }

    BigEndian<T> operator ++ (int)
    {
        BigEndian<T> tmp(*this);
        operator ++ ();
        return tmp;
    }

    BigEndian<T> & operator ++ ()
    {
        for (unsigned i = 0; i < sizeof(T); i++)
        {
            ++bytes[sizeof(T) - 1 - i];
            if (bytes[sizeof(T) - 1 - i] != 0)
                break;
        }
        return (*this);
    }

    BigEndian<T> operator -- (int)
    {
        BigEndian<T> tmp(*this);
        operator -- ();
        return tmp;
    }

    BigEndian<T> & operator -- ()
    {
        for (unsigned i = 0; i < sizeof(T); i++)
        {
            --bytes[sizeof(T) - 1 - i];
            if (bytes[sizeof(T) - 1 - i] != (T)(-1))
                break;
        }
        return (*this);
    }
};
#pragma pack(pop)

#endif // LITTLEBIGENDIAN_H