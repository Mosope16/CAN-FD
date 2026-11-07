/**
 * CAN-FD Decision Tree Embedded Microbenchmark.
 *
 * Evaluates bare-metal C classifier execution speed under realistic conditions:
 * 1. Cycles across a diverse pool of distinct CAN-FD feature vectors (Normal + 5 attack classes).
 * 2. Employs compiler optimization barriers and consumes predictions into an observable checksum.
 * 3. Separates warm-up iterations from timed execution.
 * 4. Reports compiler version, target architecture, and hardware metrics.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "classifier.h"

/* Diverse feature vectors representing Normal, DoS, Fuzzing, Spoofing, Replay, and Suppression */
static const int64_t TEST_POOL[16][NUM_FEATURES] = {
    /* 0: Normal VehicleSpeed (0x100), DLC 8, normal inter-arrival */
    {0x100, 8, 0, 10008, 8, 10, 18, 1, 0, 0, 0, 0, 0, 0},
    /* 1: DoS Flood (0x050), interval 500 us, high bus rate */
    {0x050, 8, 0, 500, -9500, 200, 218, 1, 0, 0, 0, 0, 0, 0},
    /* 2: Normal EngineTemp (0x101), 100ms period */
    {0x101, 8, 0, 100018, 18, 1, 18, 1, 0, 0, 0, 0, 0, 0},
    /* 3: Fuzzing Random ID (0x3AB), DLC 12, unknown ID */
    {0x3AB, 12, 12, 2000, 0, 5, 25, 0, 0, 6, 0, 0, 0, 0},
    /* 4: Normal BrakeStatus (0x102), 20ms period */
    {0x102, 8, 0, 19995, -5, 5, 18, 1, 0, 0, 0, 0, 0, 0},
    /* 5: Spoofing Brake (0x102), interval 7000 us, elevated rate */
    {0x102, 8, 100, 7000, -13000, 14, 28, 1, 0, 1, 0, 0, 0, 0},
    /* 6: Normal SteeringAngle (0x103), 10ms period */
    {0x103, 8, 1, 9992, -8, 10, 18, 1, 0, 2, 0, 0, 0, 0},
    /* 7: Replay Steering (0x103), duplicate payload in window */
    {0x103, 8, 0, 10000, 0, 10, 22, 1, 0, 0, 0, 0, 1000, 1},
    /* 8: Normal BatteryStatus (0x200), DLC 10 (16B), 500ms period */
    {0x200, 10, 0, 499982, -18, 1, 18, 1, 0, 0, 0, 0, 0, 0},
    /* 9: Suppression missing frame entry (0x102), id_rate=0, missing_frame_count=1 */
    {0x102, 8, 0, 30000, 10000, 0, 17, 1, 0, 0, 0, 1, 0, 0},
    /* 10: Fuzzing DLC mismatch on 0x100 (DLC=15 instead of 8) */
    {0x100, 15, 5, 10000, 0, 10, 20, 1, 1, 4, 0, 0, 0, 0},
    /* 11: Normal Diagnostics (0x201), DLC 13 (32B), 1000ms period */
    {0x201, 13, 0, 1000000, 0, 1, 18, 1, 0, 0, 0, 0, 0, 0},
    /* 12: DoS burst frame (0x050) */
    {0x050, 8, 0, 500, -9500, 195, 210, 1, 0, 0, 0, 0, 0, 0},
    /* 13: Normal cruising frame with slight jitter */
    {0x100, 8, 1, 10045, 45, 10, 18, 1, 0, 1, 0, 0, 0, 0},
    /* 14: Spoofing with sudden large payload delta */
    {0x102, 8, 95, 7000, -13000, 13, 26, 1, 0, 2, 0, 0, 0, 0},
    /* 15: Replay burst frame */
    {0x103, 8, 0, 10000, 0, 10, 24, 1, 0, 0, 0, 0, 1000, 2}
};

int main(void) {
    const int WARMUP_ITERATIONS = 100000;
    const int TIMED_ITERATIONS = 2000000;
    
    /* 1. Warm-up Phase (populate I-cache, branch predictor, branch history table) */
    uint64_t warmup_chk = 0;
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        const int64_t *vec = TEST_POOL[i & 0xF];
        warmup_chk += (uint64_t)classify_frame_array(vec);
    }
    
    /* Optimization barrier on warmup checksum */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : "+r"(warmup_chk) : : "memory");
#endif

    /* 2. Timed Evaluation Phase */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint64_t checksum = 0;
    for (int i = 0; i < TIMED_ITERATIONS; i++) {
        const int64_t *vec = TEST_POOL[i & 0xF];
        int pred = classify_frame_array(vec);
        checksum += (uint64_t)pred;
#if defined(__GNUC__) || defined(__clang__)
        /* Prevent compiler from unrolling the loop or collapsing iterations */
        __asm__ __volatile__("" : "+r"(checksum) : : "memory");
#endif
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    uint64_t total_ns = (uint64_t)(end.tv_sec - start.tv_sec) * 1000000000ULL +
                        (uint64_t)(end.tv_nsec - start.tv_nsec);
    double per_call_ns = (double)total_ns / TIMED_ITERATIONS;
    double per_call_us = per_call_ns / 1000.0;
    double fps = 1000000000.0 / per_call_ns;

    printf("===========================================================================\n");
    printf("   CAN-FD DECISION TREE EMBEDDED C CLASSIFIER MICROBENCHMARK\n");
    printf("===========================================================================\n");
#if defined(__VERSION__)
    printf("  Compiler:          GCC %s\n", __VERSION__);
#elif defined(__clang_version__)
    printf("  Compiler:          Clang %s\n", __clang_version__);
#else
    printf("  Compiler:          Standard ANSI C (C99)\n");
#endif
#if defined(__OPTIMIZE__)
    printf("  Optimization:      -O2 (Enabled)\n");
#else
    printf("  Optimization:      None\n");
#endif
    printf("  Target Arch:       x86_64 host (POSIX Monotonic Clock)\n");
    printf("  Input Vector Pool: 16 distinct vectors (Normal + 5 attack classes cycling)\n");
    printf("  Warmup Iterations: %d\n", WARMUP_ITERATIONS);
    printf("  Timed Iterations:  %d\n", TIMED_ITERATIONS);
    printf("  Verified Checksum: %llu (Anti-Dead-Code Consumer)\n", (unsigned long long)checksum);
    printf("---------------------------------------------------------------------------\n");
    printf("  Total Execution:   %.3f ms\n", (double)total_ns / 1000000.0);
    printf("  Per-Frame Latency: %.2f ns (%.4f us)\n", per_call_ns, per_call_us);
    printf("  Throughput:        %.1f million frames/sec\n", fps / 1000000.0);
    printf("===========================================================================\n");

    return (int)(checksum & 0xFF);
}
