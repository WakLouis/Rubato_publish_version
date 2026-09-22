#ifndef RUBATO_DQA_ALLOCATION_H
#define RUBATO_DQA_ALLOCATION_H

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace ns3
{
// Divide a fixed per-round video-byte budget by demand. The largest-remainder
// method preserves the total with less than one byte of quantization error.
// Never inflate q0 or the total round budget; reject demands too small to
// receive a positive integer-byte allocation.
inline std::vector<uint32_t> AllocateDqaQuanta(const std::vector<double> &demands,
                                               uint32_t totalBytes)
{
    long double sum = 0;
    for (double demand : demands)
    {
        if (!std::isfinite(demand) || demand <= 0)
        {
            throw std::invalid_argument("DQA weights require positive finite queue demands");
        }
        sum += demand;
    }
    if (demands.empty() || totalBytes < demands.size())
    {
        throw std::invalid_argument("DQA quantum budget is too small");
    }
    std::vector<uint32_t> quanta(demands.size());
    std::vector<std::pair<long double, uint32_t>> remainder;
    uint32_t used = 0;
    for (uint32_t q = 0; q < demands.size(); ++q)
    {
        const long double ideal = totalBytes * static_cast<long double>(demands[q]) / sum;
        quanta[q] = static_cast<uint32_t>(ideal);
        used += quanta[q];
        remainder.emplace_back(ideal - quanta[q], q);
    }
    std::sort(remainder.begin(), remainder.end(), [](const auto &a, const auto &b)
              { return a.first != b.first ? a.first > b.first : a.second < b.second; });
    for (uint32_t i = 0; i < totalBytes - used; ++i)
    {
        ++quanta[remainder.at(i).second];
    }
    for (auto quantum : quanta)
    {
        if (quantum == 0)
        {
            throw std::invalid_argument(
                "DQA demand weight rounds to zero; increase precision explicitly");
        }
    }
    return quanta;
}

struct DqaFlow
{
    uint32_t id;
    std::string platform;
    double demandBps;
};

struct DqaBudgetFlow
{
    uint32_t id;
    int64_t remainingBudgetNs;
};

// Rotate all local video flows in descending mean-demand order, without using
// platform identity or remaining delay budget.
inline std::map<uint32_t, uint32_t> AllocateDqaRateQueues(std::vector<DqaFlow> flows,
                                                          uint32_t queues)
{
    if (flows.empty() || queues == 0)
    {
        throw std::invalid_argument("Rate DQA requires flows and queues");
    }
    std::map<uint32_t, uint32_t> result;
    for (const auto &flow : flows)
    {
        if (!std::isfinite(flow.demandBps) || flow.demandBps <= 0 ||
            !result.emplace(flow.id, 0).second)
        {
            throw std::invalid_argument(
                "Rate DQA requires unique flows and positive finite demands");
        }
    }
    queues = std::min(queues, static_cast<uint32_t>(flows.size()));
    std::sort(flows.begin(), flows.end(), [](const auto &a, const auto &b)
              { return a.demandBps != b.demandBps ? a.demandBps > b.demandBps : a.id < b.id; });
    for (uint32_t rank = 0; rank < flows.size(); ++rank)
    {
        result.at(flows[rank].id) = rank % queues;
    }
    return result;
}

// Ignore platform identity: sort by remaining budget after local DBSP and form
// contiguous, equally sized groups. Nanosecond precision matches simulation
// time and prevents floating-point tails from deciding near-zero budgets;
// break equal-budget ties by flow ID.
inline std::map<uint32_t, uint32_t> AllocateDqaBudgetQueues(std::vector<DqaBudgetFlow> flows,
                                                            uint32_t queues)
{
    if (flows.empty() || queues == 0)
    {
        throw std::invalid_argument("Budget DQA requires flows and video queues");
    }
    std::map<uint32_t, uint32_t> result;
    for (const auto &flow : flows)
    {
        if (flow.remainingBudgetNs < 0 || !result.emplace(flow.id, 0).second)
        {
            throw std::invalid_argument("Budget DQA requires unique flows and nonnegative budgets");
        }
    }
    queues = std::min(queues, static_cast<uint32_t>(flows.size()));
    std::sort(flows.begin(), flows.end(),
              [](const auto &a, const auto &b)
              {
                  return a.remainingBudgetNs != b.remainingBudgetNs
                             ? a.remainingBudgetNs < b.remainingBudgetNs
                             : a.id < b.id;
              });
    for (uint32_t rank = 0; rank < flows.size(); ++rank)
    {
        result.at(flows[rank].id) = uint64_t(rank) * queues / flows.size();
    }
    return result;
}

// Deterministic demand balancing: process flows in descending mean-demand
// order and place each flow in the queue with the smallest accumulated demand.
// Platform fields are retained only for offline statistics. Stable ties use
// queue ID and flow ID. Inputs contain only flows traversing this egress; the
// result is a zero-based video queue and the physical qid adds one.
inline std::map<uint32_t, uint32_t> AllocateDqaQueues(const std::vector<DqaFlow> &flows,
                                                      uint32_t queues)
{
    if (flows.empty() || queues == 0)
    {
        throw std::invalid_argument("DQA requires flows and video queues");
    }
    std::map<uint32_t, uint32_t> result;
    for (const auto &flow : flows)
    {
        if (!std::isfinite(flow.demandBps) || flow.demandBps <= 0 ||
            !result.emplace(flow.id, 0).second)
        {
            throw std::invalid_argument("DQA requires unique flows and positive finite demand");
        }
    }
    queues = std::min(queues, static_cast<uint32_t>(flows.size()));
    std::vector<DqaFlow> ordered = flows;
    std::sort(ordered.begin(), ordered.end(), [](const auto &a, const auto &b)
              { return a.demandBps != b.demandBps ? a.demandBps > b.demandBps : a.id < b.id; });
    std::vector<long double> load(queues, 0.0L);
    for (const auto &flow : ordered)
    {
        const uint32_t queue =
            static_cast<uint32_t>(std::min_element(load.begin(), load.end()) - load.begin());
        result.at(flow.id) = queue;
        load[queue] += flow.demandBps;
    }
    return result;
}
} // namespace ns3
#endif
