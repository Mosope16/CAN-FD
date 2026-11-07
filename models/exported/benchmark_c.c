#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "classifier.h"

int main(void) {
    int64_t sample[NUM_FEATURES] = {259, 8, 1, 9500, -500, 10, 18, 1, 0, 3, 0, 0, 1000, 1};
    const int iterations = 1000000;
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    volatile int dummy = 0;
    for (int i = 0; i < iterations; i++) {
        dummy += classify_frame_array(sample);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    uint64_t total_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
    double per_call_ns = (double)total_ns / iterations;
    double per_call_us = per_call_ns / 1000.0;
    double fps = 1000000000.0 / per_call_ns;
    
    printf("ANSI C Classifier Benchmark (%d iterations):\n", iterations);
    printf("  Total Time:        %.3f ms\n", total_ns / 1000000.0);
    printf("  Per-Frame Latency: %.2f ns (%.4f us)\n", per_call_ns, per_call_us);
    printf("  Throughput:        %.1f million frames/sec\n", fps / 1000000.0);
    return 0;
}
