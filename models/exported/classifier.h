#ifndef CANFD_CLASSIFIER_H
#define CANFD_CLASSIFIER_H

#include <stdint.h>

#define NUM_FEATURES 14

int classify_frame_array(const int64_t *features);
int classify_frame(int64_t frame_id, int64_t frame_dlc, int64_t payload_delta, int64_t inter_arrival, int64_t period_deviation, int64_t id_rate, int64_t total_bus_rate, int64_t id_seen_before, int64_t dlc_mismatch, int64_t payload_change_count, int64_t protocol_error_count, int64_t missing_frame_count, int64_t replay_similarity, int64_t duplicate_count);

#endif /* CANFD_CLASSIFIER_H */
