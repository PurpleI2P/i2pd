/**
 * Sybil Attack Detector for i2pd
 * Prevents mass botnet router attacks (Kimwolf-style)
 * 
 * Date: Feb 13, 2026
 * Context: Kimwolf botnet (700K+ routers) overwhelmed I2P network
 * Author: Lance James / Unit221B
 */

#ifndef SYBIL_DETECTOR_H__
#define SYBIL_DETECTOR_H__

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <string>
#include "RouterInfo.h"
#include "Identity.h"

namespace i2p {
namespace data {

struct SybilDetectorConfig {
    // Rate limits
    uint32_t max_new_routers_per_hour = 1000;
    uint32_t max_new_routers_per_day = 10000;
    uint32_t max_routers_per_asn = 500;
    
    // Clustering thresholds
    float version_cluster_threshold = 0.60f;  // >60% same version = suspicious
    float bandwidth_cluster_threshold = 0.70f;  // >70% same bandwidth class
    uint32_t min_router_age_minutes = 60;  // New routers <1hr = suspicious
    
    // Trust scoring
    float min_trust_score = 0.3f;  // Reject routers below this
    uint32_t min_uptime_for_trust_hours = 24;
    
    // Detection flags
    bool flood_protection_enabled = true;
    bool reputation_system_enabled = true;
    bool enabled = true;
};

class SybilDetector {
public:
    enum class Verdict {
        ACCEPT,
        REJECT,
        PROBATION  // Accept but monitor closely
    };
    
    SybilDetector(const SybilDetectorConfig& cfg = SybilDetectorConfig());
    ~SybilDetector() = default;
    
    Verdict EvaluateRouter(std::shared_ptr<const RouterInfo> ri);
    
    // Statistics
    uint32_t GetNewRoutersLastHour() const;
    uint32_t GetRejectedRoutersCount() const { return m_RejectedCount; }

private:
    SybilDetectorConfig m_Config;
    
    // Network statistics tracking
    struct NetworkStats {
        std::vector<std::pair<IdentHash, std::chrono::system_clock::time_point>> new_routers;
        std::unordered_map<std::string, uint32_t> asn_counts;
        std::unordered_map<std::string, uint32_t> version_counts;
        std::unordered_map<std::string, uint32_t> bandwidth_counts;
        uint32_t total_routers = 0;
        
        void RecordNewRouter(const IdentHash& hash, const std::string& version, 
                           const std::string& asn, const std::string& bw_class);
        uint32_t GetNewRoutersLastHour() const;
        uint32_t GetASNCount(const std::string& asn) const;
        float GetVersionRatio(const std::string& version) const;
        float GetBandwidthClassRatio(const std::string& bw_class) const;
    };
    
    // Router reputation tracking
    struct ReputationScore {
        float trust_score = 0.5f;
        std::chrono::system_clock::time_point first_seen;
        std::chrono::system_clock::time_point last_seen;
        uint32_t successful_tunnels = 0;
        uint64_t transit_bytes = 0;
        bool is_floodfill = false;
        std::unordered_set<IdentHash> unique_destinations;
    };
    
    NetworkStats m_Stats;
    std::unordered_map<IdentHash, ReputationScore> m_Reputation;
    uint32_t m_RejectedCount = 0;
    
    // Detection methods
    bool IsFloodAttack(std::shared_ptr<const RouterInfo> ri, 
                      const std::string& asn, const std::string& version,
                      const std::string& bw_class);
    bool IsKnownBotnet(std::shared_ptr<const RouterInfo> ri,
                      const std::string& asn, const std::string& version,
                      const std::string& bw_class);
    float CalculateTrust(std::shared_ptr<const RouterInfo> ri, const IdentHash& hash);
    
    // Helper methods
    std::string GetASN(std::shared_ptr<const RouterInfo> ri) const;
    std::string GetBandwidthClass(std::shared_ptr<const RouterInfo> ri) const;
};

} // namespace data
} // namespace i2p

#endif // SYBIL_DETECTOR_H__
