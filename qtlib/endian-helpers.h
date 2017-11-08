#ifndef __ENDIAN_H__
#define __ENDIAN_H__

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be16_to_cpup(A)	__builtin_bswap16(*(uint16_t *)(A))
#define be32_to_cpup(A)	__builtin_bswap32(*(uint32_t *)(A))
#define be64_to_cpup(A)	__builtin_bswap64(*(uint64_t *)(A))
#define cpu_to_be16(A) __builtin_bswap16(A)
#define cpu_to_be32(A) __builtin_bswap32(A)
#define cpu_to_be64(A) __builtin_bswap64(A)
#else
#define be16_to_cpup(A)	(*(uint16_t *)A)
#define be32_to_cpup(A)	(*(uint32_t *)A)
#define be64_to_cpup(A)	(*(uint64_t *)A)
#define cpu_to_be16(A) (A)
#define cpu_to_be32(A) (A)
#define cpu_to_be64(A) (A)
#endif

#endif
