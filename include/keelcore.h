#ifndef KEELCORE_H
#define KEELCORE_H

#include <stdint.h>

// Define the KeelSnapshot structure
typedef struct {
    uint32_t id;
    char name[256];
    float value;
    // Add other fields as necessary
} KeelSnapshot;

// Function declarations
void createKeelSnapshot(KeelSnapshot* snapshot);
void deleteKeelSnapshot(uint32_t id);
void updateKeelSnapshot(KeelSnapshot* snapshot);
KeelSnapshot getKeelSnapshot(uint32_t id);

#endif // KEELCORE_H