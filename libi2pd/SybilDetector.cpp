/**
 * Sybil Attack Detector for i2pd
 * Implementation
 * 
 * Date: Feb 13, 2026
 * Author: Lance James / Unit221B
 */

#include "SybilDetector.h"
#include "Log.h"
#include "RouterContext.h"
#include <algorithm>

namespace i2p {
namespace data {

//
// NetworkStats implementation
//

void SybilDetector::NetworkStats::RecordNewRouter(const IdentHash& hash, 
                                                  const std::string& version,
                                                  const std::string& asn,
                                                  const std::string& bw_class) {
    auto now = std::chrono::system_clock::now();
    auto hour_ago = now - std::chrono::hours(1);
    
    // Remove old entries (older than 1 hour)
    new_routers.erase(
        std::remove_if(new_routers.begin(), new_routers.end(),
            [hour_ago](const auto& entry) { return entry.second < hour_ago; }),
        new_routers.end());
    
    // Add new entry
    new_routers.push_back({hash, now});
    
    // Update counts
    asn_counts[asn]++;
    version_counts[version]++;
    bandwidth_counts[bw_class]++;
    total_routers++;
}

uint32_t SybilDetector::NetworkStats::GetNewRoutersLastHour() const {
    auto now = std::chrono::system_clock::now();
    auto hour_ago = now - std::chrono::hours(1);
    return std::count_if(new_routers.begin(), new_routers.end(),
        [hour_ago](const auto& entry) { return entry.second >= hour_ago; });
}

uint32_t SybilDetector::NetworkStats::GetASNCount(const std::string& asn) const {
    auto it = asn_counts.find(asn);
    return it != asn_counts.end() ? it->second : 0;
}

float SybilDetector::NetworkStats::GetVersionRatio(const std::string& version) const {
    auto it = version_counts.find(version);
    if (it == version_counts.end() || total_routers == 0) return 0.0f;
    return static_cast<float>(it->second) / total_routers;
}

float SybilDetector::NetworkStats::GetBandwidthClassRatio(const std::string& bw_class) const {
    auto it = bandwidth_counts.find(bw_class);
    if (it == bandwidth_counts.end() || total_routers == 0) return 0.0f;
    return static_cast<float>(it->second) / total_routers;
}

//
// SybilDetector implementation
//

SybilDetector::SybilDetector(const SybilDetectorConfig& cfg) : m_Config(cfg) {
    if (m_Config.enabled) {
        LogPrint(eLogInfo, "SybilDetector: Enabled (flood=", m_Config.flood_protection_enabled,
                 ", reputation=", m_Config.reputation_system_enabled,
                 ", rate_limit=", m_Config.max_new_routers_per_hour, "/hour)");
    }
}

std::string SybilDetector::GetASN(std::shared_ptr<const RouterInfo> ri) const {
    // Simplified ASN extraction - in production, use MaxMind GeoIP2
    // For now, just return a placeholder based on IP range
    auto addrs = ri->GetAddresses();
    if (!addrs || addrs->empty()) return "AS0";
    
    // Example: Check for known Kimwolf ASNs (CHINANET)
    // In production, implement proper GeoIP lookup
    // For now, simplified detection
    
    return "AS0";  // Placeholder
}

std::string SybilDetector::GetBandwidthClass(std::shared_ptr<const RouterInfo> ri) const {
    uint8_t caps = ri->GetCaps();
    if (caps == 0) return "Unknown";
    
    // Bandwidth class is encoded in caps byte
    // Extract first char: K,L,M,N,O,P,X
    char bw = (caps >> 4) & 0x0F; // upper nibble
    if (bw >= 1 && bw <= 7) {
        // K=1, L=2, M=3, N=4, O=5, P=6, X=7
        const char* bw_chars = " KLMNOPX";
        return std::string(1, bw_chars[bw]);
    }
    
    return "Unknown";
}

SybilDetector::Verdict SybilDetector::EvaluateRouter(std::shared_ptr<const RouterInfo> ri) {
    if (!m_Config.enabled) {
        return Verdict::ACCEPT;
    }
    
    const auto& hash = ri->GetIdentHash();
    // Get version as string for logging (format: "0.9.67")
    int ver = ri->GetVersion();
    char version_buf[16];
    snprintf(version_buf, sizeof(version_buf), "%d.%d.%d",
             (ver >> 16) & 0xFF, (ver >> 8) & 0xFF, ver & 0xFF);
    std::string version(version_buf);
    std::string asn = GetASN(ri);
    std::string bw_class = GetBandwidthClass(ri);
    
    // Check 1: Flood detection
    if (m_Config.flood_protection_enabled) {
        if (IsFloodAttack(ri, asn, version, bw_class)) {
            LogPrint(eLogWarning, "SybilDetector: Flood attack detected, rejecting router");
            m_RejectedCount++;
            return Verdict::REJECT;
        }
    }
    
    // Check 2: Reputation scoring
    if (m_Config.reputation_system_enabled) {
        float trust = CalculateTrust(ri, hash);
        
        if (trust < m_Config.min_trust_score) {
            LogPrint(eLogWarning, "SybilDetector: Low trust router (trust=", trust, ")");
            m_RejectedCount++;
            return Verdict::REJECT;
        }
        
        if (trust < 0.5f) {
            LogPrint(eLogInfo, "SybilDetector: Router on probation (trust=", trust, ")");
            return Verdict::PROBATION;
        }
    }
    
    // Check 3: Known botnet fingerprints
    if (IsKnownBotnet(ri, asn, version, bw_class)) {
        LogPrint(eLogWarning, "SybilDetector: Known botnet fingerprint detected");
        m_RejectedCount++;
        return Verdict::REJECT;
    }
    
    // Record this router for statistics
    m_Stats.RecordNewRouter(hash, version, asn, bw_class);
    
    return Verdict::ACCEPT;
}

bool SybilDetector::IsFloodAttack(std::shared_ptr<const RouterInfo> ri,
                                  const std::string& asn,
                                  const std::string& version,
                                  const std::string& bw_class) {
    // Mass registration detection
    uint32_t new_routers_count = m_Stats.GetNewRoutersLastHour();
    if (new_routers_count > m_Config.max_new_routers_per_hour) {
        LogPrint(eLogWarning, "SybilDetector: Mass registration detected (", 
                 new_routers_count, " routers in last hour)");
        return true;
    }
    
    // ASN clustering detection
    uint32_t asn_count = m_Stats.GetASNCount(asn);
    if (asn_count > m_Config.max_routers_per_asn) {
        LogPrint(eLogWarning, "SybilDetector: ASN flood from ", asn,
                 " (", asn_count, " routers)");
        return true;
    }
    
    // Version clustering detection
    float version_ratio = m_Stats.GetVersionRatio(version);
    if (version_ratio > m_Config.version_cluster_threshold) {
        LogPrint(eLogWarning, "SybilDetector: Version clustering detected (",
                 version, " = ", version_ratio * 100, "%)");
        return true;
    }
    
    // Bandwidth class clustering
    float bw_ratio = m_Stats.GetBandwidthClassRatio(bw_class);
    if (bw_ratio > m_Config.bandwidth_cluster_threshold) {
        LogPrint(eLogWarning, "SybilDetector: Bandwidth clustering detected (",
                 bw_class, " = ", bw_ratio * 100, "%)");
        return true;
    }
    
    return false;
}

bool SybilDetector::IsKnownBotnet(std::shared_ptr<const RouterInfo> ri,
                                  const std::string& asn,
                                  const std::string& version,
                                  const std::string& bw_class) {
    // Kimwolf/HydeMoon fingerprint:
    // - Version: 0.9.57 or 0.9.67
    // - Bandwidth: L (low)
    // - ASN: CHINANET (AS4134, AS4837) - simplified for now
    
    int ver = ri->GetVersion();
    // MAKE_VERSION_NUMBER(0,9,57) = (0*100+9)*100+57 = 957
    // MAKE_VERSION_NUMBER(0,9,67) = (0*100+9)*100+67 = 967
    bool is_kimwolf_version = (ver == 957 || ver == 967);
    bool is_low_bandwidth = (bw_class == "L");
    
    // If both match, likely Kimwolf bot
    // In production, add ASN check when GeoIP is integrated
    if (is_kimwolf_version && is_low_bandwidth) {
        LogPrint(eLogWarning, "SybilDetector: Kimwolf fingerprint match (version=",
                 version, ", bandwidth=", bw_class, ")");
        return true;
    }
    
    // Add more fingerprints here as new botnets are discovered
    
    return false;
}

float SybilDetector::CalculateTrust(std::shared_ptr<const RouterInfo> ri, const IdentHash& hash) {
    // Get or create reputation score
    auto it = m_Reputation.find(hash);
    ReputationScore score;
    
    if (it != m_Reputation.end()) {
        score = it->second;
        score.last_seen = std::chrono::system_clock::now();
    } else {
        score.first_seen = std::chrono::system_clock::now();
        score.last_seen = score.first_seen;
        score.is_floodfill = ri->IsFloodfill();
        m_Reputation[hash] = score;
    }
    
    float trust = 0.5f;  // Neutral starting point
    auto now = std::chrono::system_clock::now();
    
    // Age factor - new routers are less trusted
    auto age_minutes = std::chrono::duration_cast<std::chrono::minutes>(
        now - score.first_seen).count();
    
    if (age_minutes > 43200) trust += 0.3f;  // >30 days
    else if (age_minutes > 10080) trust += 0.2f;  // >7 days
    else if (age_minutes > 1440) trust += 0.1f;  // >1 day
    else if (age_minutes < 60) trust -= 0.3f;  // <1 hour = very suspicious
    
    // Floodfill routers are more trusted
    if (score.is_floodfill) trust += 0.3f;
    
    // Participation factor
    if (score.transit_bytes > 1e9) trust += 0.2f;  // >1GB transit
    if (score.successful_tunnels > 100) trust += 0.1f;
    
    // Tunnel diversity check (CRITICAL for botnet detection)
    // Kimwolf bots only connect to their C2 .b32.i2p addresses
    // Legitimate routers participate in many tunnels
    if (score.unique_destinations.size() < 2 && age_minutes > 60) {
        trust -= 0.4f;  // Only 1 destination after 1hr = likely bot
    }
    
    // Bandwidth class penalty for new low-bandwidth routers
    std::string bw_class = GetBandwidthClass(ri);
    if (bw_class == "L" && age_minutes < 1440) {
        trust -= 0.1f;  // New low-bandwidth router = slightly suspicious
    }
    
    // Clamp to [0.0, 1.0]
    trust = std::max(0.0f, std::min(1.0f, trust));
    
    // Update reputation
    m_Reputation[hash].trust_score = trust;
    
    return trust;
}

uint32_t SybilDetector::GetNewRoutersLastHour() const {
    return m_Stats.GetNewRoutersLastHour();
}

} // namespace data
} // namespace i2p
