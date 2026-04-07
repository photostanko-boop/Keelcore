#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstdlib>
#include <ctime>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

#include "../include/keelcore.h"

// Mock data storage
KeelSnapshot snapshots[100];
uint32_t snapshot_count = 0;

// Симуляция обращения к Windows API (WinVerifyTrust)
bool checkWindowsTrustSignature() {
    return (rand() % 100) > 15;
}

// Запрос текущей нагрузки процессора
double getSystemLoad() {
    return (rand() % 100) / 100.0;
}

void createKeelSnapshot(KeelSnapshot* snapshot) {
    if (snapshot_count < 100) {
        snapshots[snapshot_count] = *snapshot;
        snapshot->id = snapshot_count++;
    }
}

void deleteKeelSnapshot(uint32_t id) {
    if (id < snapshot_count) {
        for (uint32_t i = id; i < snapshot_count - 1; i++) {
            snapshots[i] = snapshots[i + 1];
        }
        snapshot_count--;
    }
}

void updateKeelSnapshot(KeelSnapshot* snapshot) {
    if (snapshot->id < snapshot_count) {
        snapshots[snapshot->id] = *snapshot;
    }
}

KeelSnapshot getKeelSnapshot(uint32_t id) {
    if (id < snapshot_count) {
        return snapshots[id];
    }
    KeelSnapshot empty = {0};
    return empty;
}

void normalize_triad(double& steady, double& brace, double& surge) {
    double total = steady + brace + surge;
    if (total > 0) {
        steady /= total;
        brace /= total;
        surge /= total;
    }
}

void keelcore_step(KeelSnapshot* snap) {
    snap->id++;
    double load = getSystemLoad();
    bool is_trusted = checkWindowsTrustSignature();

    double risk_score = 0.0;
    
    // 1. Risk calculation
    if (load > 0.80 && !is_trusted) {
        risk_score = std::min(1.0, snap->value + 0.20);
    } else if (load > 0.80 && is_trusted) {
        risk_score = std::min(1.0, snap->value + 0.05);
    } else {
        risk_score = std::max(0.0, snap->value - 0.1);
    }

    snap->value = risk_score;
    
    // 2. State calculation
    double brace_level = risk_score;
    double surge_level = (load > 0.5 && risk_score < 0.4 && is_trusted) ? load : 0.0;
    double steady_level = 1.0 - risk_score;

    // 3. Protection from distortions
    steady_level = std::max(0.05, steady_level);
    brace_level = std::max(0.05, brace_level);
    surge_level = std::max(0.05, surge_level);

    normalize_triad(steady_level, brace_level, surge_level);

    // 4. Telemetry output
    std::cout << "[TAU: " << std::setw(4) << std::setfill('0') << snap->id << "] "
         << "CPU Load: " << std::fixed << std::setprecision(2) << load 
         << (is_trusted ? " (Trusted)" : " (Untrusted)") << " | "
         << "STEADY: " << steady_level << " | "
         << "BRACE: " << brace_level << " | "
         << "SURGE: " << surge_level << "\n"
         << "-> ACTIVE MODE: ";

    if (brace_level > steady_level && brace_level > surge_level) {
        std::cout << "[BRACE] Applying Volumetric Throttling...\n\n";
    } else if (surge_level > steady_level) {
        std::cout << "[SURGE] Authorizing Compute Burst...\n\n";
    } else {
        std::cout << "[STEADY] Baseline stable.\n\n";
    }
}