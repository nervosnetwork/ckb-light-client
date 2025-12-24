/* Android stubs for missing libc functions */
/* These functions are not available in Android's Bionic libc */
/* UPnP functionality will be disabled on Android */

#include <sys/types.h>
#include <ifaddrs.h>
#include <errno.h>

/* Stub implementation of getifaddrs for Android */
/* Returns ENOSYS (function not implemented) */
int getifaddrs(struct ifaddrs **ifap) {
    (void)ifap;
    errno = ENOSYS;
    return -1;
}

/* Stub implementation of freeifaddrs for Android */
void freeifaddrs(struct ifaddrs *ifa) {
    (void)ifa;
    /* No-op since getifaddrs always fails */
}
