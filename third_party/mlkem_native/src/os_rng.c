// SSB PATCH 2: hardened randombytes().
// Upstream ignored the return value of read(), so a short read or a failed
// read left key material partly unfilled. So Smart Beneficiary always
// supplies its own coins from the OS CSPRNG via the *_derand entry points,
// but this fallback must still be correct.
#if (defined(__linux__) || defined(__ANDROID__)) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <stddef.h>

int randombytes(uint8_t *out, size_t outlen);

#if defined(__APPLE__)
#include <Security/SecRandom.h>
int randombytes(uint8_t *out, size_t outlen) {
    return SecRandomCopyBytes(kSecRandomDefault, outlen, out) == errSecSuccess ? 0 : -1;
}

#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
int randombytes(uint8_t *out, size_t outlen) {
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL, out, (ULONG)outlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ? 0 : -1;
}

#elif defined(__linux__) || defined(__ANDROID__)
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
int randombytes(uint8_t *out, size_t outlen) {
    int fd;
    do {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return -1;
    while (outlen > 0) {
        ssize_t n = read(fd, out, outlen);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        out += (size_t)n;
        outlen -= (size_t)n;
    }
    close(fd);
    return 0;
}

#else
#error "Unsupported platform: you must implement randombytes()"
#endif
