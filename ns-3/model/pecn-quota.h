#ifndef RUBATO_PECN_QUOTA_H
#define RUBATO_PECN_QUOTA_H

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace ns3
{

// Software reference of a control-plane lease plus a bounded data-plane action.
// No queue contents, per-flow exact rate, playback buffer or future chunk input.
class PecnQuota
{
  public:
    struct Config
    {
        int64_t epochNs{500000000};
        int64_t targetNs{1000000};
        int64_t freshNs{2000000};
        int64_t cooldownNs{10000000000LL};
        uint32_t maxPackets{16};
        uint32_t activeMinBytes{32768};
        double minBudgetSeconds{0.05};
        double packetProbability{1.0};
        bool randomOrder{false};
        uint64_t seed{3};
    };
    struct Lease
    {
        uint64_t epoch{0};
        uint32_t rank{0}, allocated{0}, remaining{0}, estimateBytes{0};
        double budgetSeconds{0};
        int64_t expiresNs{0};
    };
    struct GrantEvent
    {
        int64_t timeNs;
        uint32_t flow;
        Lease lease;
    };
    struct CloseEvent
    {
        int64_t timeNs;
        uint32_t flow;
        uint64_t epoch;
        uint32_t allocated, used;
        int64_t cooldownUntilNs;
    };
    struct WindowEvent
    {
        int64_t startNs, endNs;
        uint64_t epoch, totalBytes, videoBytes;
        uint32_t eligible, selected;
        bool cmsValid;
        uint64_t q0Samples, q0HighSamples;
        int64_t q0MaxDelayNs;
    };
    struct MarkEvent
    {
        int64_t timeNs;
        uint32_t flow;
        uint64_t epoch;
        uint32_t rank, before, after;
        int64_t expiresNs, q0DelayNs, q0AgeNs;
        double budgetSeconds;
        double packetProbability, sample;
    };

    static int64_t NanosecondsFromMilliseconds(double milliseconds)
    {
        if (!std::isfinite(milliseconds) || milliseconds < 0 ||
            milliseconds >= static_cast<double>(std::numeric_limits<int64_t>::max()) / 1e6)
            throw std::invalid_argument("Invalid PECN time parameter");
        return std::llround(milliseconds * 1e6);
    }

    PecnQuota(uint32_t flows, Config config)
        : m_config(config), m_keys(flows), m_known(flows, false), m_leases(flows),
          m_cooldownUntil(flows, 0)
    {
        if (!flows || config.epochNs <= 0 || config.targetNs < 0 || config.freshNs <= 0 ||
            config.cooldownNs < 0 || !config.maxPackets || config.maxPackets > 65535 ||
            !config.activeMinBytes || !std::isfinite(config.minBudgetSeconds) ||
            config.minBudgetSeconds < 0 || !std::isfinite(config.packetProbability) ||
            config.packetProbability < 0 || config.packetProbability > 1)
            throw std::invalid_argument("Invalid PECN quota configuration");
    }

    void ObservePort(uint32_t bytes) { m_totalBytes += bytes; }
    void ObserveVideo(uint32_t flow, uint64_t key, uint32_t bytes)
    {
        m_keys.at(flow) = key;
        m_known.at(flow) = true;
        m_videoBytes += bytes;
        for (uint32_t row = 0; row < 2; row++)
        {
            auto &counter = m_cms[m_bank][row][Hash(key, row)];
            if (bytes > std::numeric_limits<uint32_t>::max() - counter)
            {
                counter = std::numeric_limits<uint32_t>::max();
                m_valid[m_bank] = false;
            }
            else
                counter += bytes;
        }
    }
    void ObserveQ0(int64_t nowNs, int64_t delayNs)
    {
        m_q0Time = nowNs;
        m_q0Delay = std::max<int64_t>(0, delayNs);
        ++m_q0Samples;
        m_q0HighSamples += m_q0Delay > m_config.targetNs;
        m_q0MaxDelay = std::max(m_q0MaxDelay, m_q0Delay);
    }

    void Query(int64_t nowNs, const std::vector<double> &budgets)
    {
        if (budgets.size() != m_keys.size() || nowNs <= m_lastQuery)
            throw std::invalid_argument("Invalid quota query time or budget roster");
        const uint32_t old = m_bank;
        m_bank = 1 - m_bank;
        ++m_epoch;
        // Confirmation is at lease end. This conservatively provides >=10s
        // from the last CE, without assuming synchronized per-packet RPCs.
        for (uint32_t flow = 0; flow < m_leases.size(); flow++)
        {
            auto &lease = m_leases[flow];
            if (lease.allocated)
            {
                const uint32_t used = lease.allocated - lease.remaining;
                if (used)
                    m_cooldownUntil[flow] = nowNs + m_config.cooldownNs;
                closes.push_back(
                    {nowNs, flow, lease.epoch, lease.allocated, used, m_cooldownUntil[flow]});
            }
            lease = {};
        }
        std::vector<uint32_t> eligible;
        if (m_valid[old])
            for (uint32_t flow = 0; flow < m_keys.size(); flow++)
            {
                if (m_known[flow] && nowNs >= m_cooldownUntil[flow] &&
                    std::isfinite(budgets[flow]) && budgets[flow] >= m_config.minBudgetSeconds &&
                    Estimate(old, m_keys[flow]) >= m_config.activeMinBytes)
                    eligible.push_back(flow);
            }
        std::sort(eligible.begin(), eligible.end(),
                  [&](uint32_t a, uint32_t b)
                  {
                      if (m_config.randomOrder)
                      {
                          auto ka = Mix(m_keys[a] ^ Mix(m_epoch) ^ m_config.seed);
                          auto kb = Mix(m_keys[b] ^ Mix(m_epoch) ^ m_config.seed);
                          if (ka != kb)
                              return ka < kb;
                      }
                      else if (budgets[a] != budgets[b])
                          return budgets[a] > budgets[b];
                      return a < b;
                  });
        const uint32_t selected = (eligible.size() + 3) / 4;
        for (uint32_t i = 0; i < selected; i++)
        {
            const uint32_t flow = eligible[i];
            const uint32_t amount =
                (uint64_t(m_config.maxPackets) * (selected - i) + selected - 1) / selected;
            m_leases[flow] = {m_epoch,
                              i + 1,
                              amount,
                              amount,
                              Estimate(old, m_keys[flow]),
                              budgets[flow],
                              nowNs + m_config.epochNs};
            grants.push_back({nowNs, flow, m_leases[flow]});
        }
        windows.push_back({m_lastQuery, nowNs, m_epoch, m_totalBytes, m_videoBytes,
                           static_cast<uint32_t>(eligible.size()), selected, m_valid[old],
                           m_q0Samples, m_q0HighSamples, m_q0MaxDelay});
        m_cms[old] = {};
        m_valid[old] = true;
        m_totalBytes = m_videoBytes = 0;
        m_q0Samples = m_q0HighSamples = 0;
        m_q0MaxDelay = 0;
        m_lastQuery = nowNs;
    }

    bool CanMark(uint32_t flow, int64_t nowNs, double sample = 0) const
    {
        const auto &lease = m_leases.at(flow);
        return std::isfinite(sample) && sample >= 0 && sample < m_config.packetProbability &&
               lease.remaining > 0 && nowNs < lease.expiresNs && m_q0Time >= 0 &&
               nowNs >= m_q0Time && nowNs - m_q0Time <= m_config.freshNs &&
               m_q0Delay > m_config.targetNs;
    }
    // Call only after the caller has successfully changed ECT to CE.
    void CommitMark(uint32_t flow, int64_t nowNs, double sample = 0)
    {
        if (!CanMark(flow, nowNs, sample))
            throw std::logic_error("Unauthorized quota CE");
        auto &lease = m_leases.at(flow);
        const uint32_t before = lease.remaining--;
        marks.push_back({nowNs, flow, lease.epoch, lease.rank, before, lease.remaining,
                         lease.expiresNs, m_q0Delay, nowNs - m_q0Time, lease.budgetSeconds,
                         m_config.packetProbability, sample});
    }
    const Lease &GetLease(uint32_t flow) const { return m_leases.at(flow); }
    int64_t CooldownUntil(uint32_t flow) const { return m_cooldownUntil.at(flow); }
    uint32_t EstimateCurrent(uint64_t key) const { return Estimate(m_bank, key); }
    const Config &GetConfig() const { return m_config; }

    std::vector<GrantEvent> grants;
    std::vector<CloseEvent> closes;
    std::vector<WindowEvent> windows;
    std::vector<MarkEvent> marks;

  private:
    static uint64_t Mix(uint64_t x)
    {
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        return x ^ (x >> 31);
    }
    static uint32_t Hash(uint64_t key, uint32_t row)
    {
        return Mix(key ^ (0x9e3779b97f4a7c15ULL * (row + 1))) & 1023;
    }
    uint32_t Estimate(uint32_t bank, uint64_t key) const
    {
        return std::min(m_cms[bank][0][Hash(key, 0)], m_cms[bank][1][Hash(key, 1)]);
    }

    Config m_config;
    std::array<std::array<std::array<uint32_t, 1024>, 2>, 2> m_cms{};
    std::array<bool, 2> m_valid{{true, true}};
    uint32_t m_bank{0};
    uint64_t m_epoch{0}, m_totalBytes{0}, m_videoBytes{0};
    int64_t m_lastQuery{0}, m_q0Time{-1}, m_q0Delay{0};
    uint64_t m_q0Samples{0}, m_q0HighSamples{0};
    int64_t m_q0MaxDelay{0};
    std::vector<uint64_t> m_keys;
    std::vector<bool> m_known;
    std::vector<Lease> m_leases;
    std::vector<int64_t> m_cooldownUntil;
};
} // namespace ns3
#endif
