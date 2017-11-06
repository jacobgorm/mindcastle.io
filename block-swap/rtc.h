#ifndef __RTC_H__
#define __RTC_H__

#ifdef _WIN32
inline double rtc() {
    LARGE_INTEGER time;
    LARGE_INTEGER freq;
    uint64_t t, f;
    QueryPerformanceCounter(&time);
    QueryPerformanceFrequency(&freq);
    t = ((uint64_t)time.HighPart << 32UL) | time.LowPart;
    f = ((uint64_t)freq.HighPart << 32UL) | freq.LowPart;
    return ((double)t) / ((double)f);
}

#else

#include <sys/time.h>
static inline double rtc(void)
{
    struct timeval time;
    gettimeofday(&time,0);
    return ( (double)(time.tv_sec)+(double)(time.tv_usec)/1e6f );
}

#endif
#endif /* __RTC_H__ */
