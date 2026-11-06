#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "classifier.h"

int main(void) {
    int64_t f[NUM_FEATURES];
    while (1) {
        int read_count = 0;
        for (int i = 0; i < NUM_FEATURES; i++) {
            long long val;
            if (scanf("%lld", &val) == 1) {
                f[i] = (int64_t)val;
                read_count++;
            } else {
                break;
            }
        }
        if (read_count == NUM_FEATURES) {
            int pred = classify_frame_array(f);
            printf("%d\n", pred);
        } else {
            break;
        }
    }
    return 0;
}
