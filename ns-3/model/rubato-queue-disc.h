#ifndef RUBATO_QUEUE_DISC_H
#define RUBATO_QUEUE_DISC_H

#include "ns3/event-id.h"
#include "ns3/data-rate.h"
#include "ns3/queue-disc.h"
#include "ns3/random-variable-stream.h"
#include "pecn-quota.h"

#include <cstdint>
#include <deque>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ns3
{

/** Single-FIFO iRED classic-loss model. */
class IredQueueDisc : public QueueDisc
{
  public:
    static TypeId GetTypeId();
    IredQueueDisc();

  private:
    bool DoEnqueue(Ptr<QueueDiscItem> item) override;
    Ptr<QueueDiscItem> DoDequeue() override;
    Ptr<const QueueDiscItem> DoPeek() override;
    bool CheckConfig() override;
    void InitializeParams() override;
    void ArmDrop();
    void UpdateAverageDelay();

    double m_weight{0.5};
    Time m_minDelay{MilliSeconds(20)};
    Time m_maxDelay{MilliSeconds(40)};
    Time m_feedbackDelay{NanoSeconds(750)};
    DataRate m_linkRate{"100Mbps"};
    double m_averageDelay{0.0};
    // Number of pending drops. A Boolean implementation collapses repeated
    // arming events into one drop and systematically understates loss rate.
    uint32_t m_dropCredits{0};
    Ptr<UniformRandomVariable> m_random;
};

/**
 * Shared hard buffer with per-flow queues and a byte-based DWRR scheduler.
 * q0 carries non-video
 * traffic; q1..qN carry identified video flows.
 */
class RubatoQueueDisc : public QueueDisc
{
    friend struct VideoRedTest;

  public:
    struct PecnMarkEvent
    {
        double timeSeconds;
        uint32_t flow;
        uint32_t queue;
        uint32_t queueBytes;
        uint32_t activeFlows;
        uint32_t activeVideoFlows;
        double dbspRemainingBudgetSeconds;
        double pecnObservedBudgetSeconds;
        uint64_t historicalPeakBytes;
        uint64_t thresholdBytes;
        double queueLevelPercent;
        uint32_t intensityLevel;
        double markProbability;
        uint32_t clusterId;
        double clusterPeakTimeSeconds;
        double clusterPeakAgeSeconds;
        uint32_t clusterSize;
        uint32_t eligibleClusterFlows;
        uint32_t selectedRank;
        std::string clusterMembers;
        uint64_t recentPayloadBytes{0};
    };

    struct PecnDecisionEvent
    {
        double timeSeconds;
        uint64_t epoch;
        bool triggered;
        uint32_t clusterId;
        double clusterPeakTimeSeconds;
        uint32_t clusterSize;
        uint32_t eligibleClusterFlows;
        uint32_t selectedFlows;
        uint64_t historicalPeakBytes;
        uint64_t thresholdBytes;
        double queueLevelPercent;
        uint32_t intensityLevel;
        double markProbability;
        double clusterPeakAgeSeconds;
        std::string clusterMembers;
        std::string reason;
    };

    struct PecnBudgetState
    {
        double initialSeconds;
        double usedSeconds;
        uint32_t level;
    };

    static TypeId GetTypeId();
    RubatoQueueDisc();

    void SetFlowPolicy(uint32_t flow, DataRate rate, Time phase, Time period, bool gated,
                       bool relativePhase = false, uint32_t burstBytes = 0);
    uint32_t GetQueueBytes(uint32_t queue) const;

    /// Explicit flow-to-queue map. An empty map falls back to
    /// flow % VideoQueueCount(). Queue assignment remains externally
    /// configurable so alternative dynamic allocation policies can be tested.
    void SetFlowQueueMap(std::vector<uint32_t> map);
    // Configure per-round video byte budgets directly so integer weight
    // scaling does not also change q0's scheduling granularity.
    void SetVideoQuanta(std::vector<uint32_t> quanta);
    void SetClassQuanta(uint32_t sensitiveQuantum, std::vector<uint32_t> videoQuanta);
    void UpdateQueueRate(uint32_t queue, DataRate rate, uint32_t burstBytes);
    struct SafetyReleaseEvent
    {
        double timeSeconds;
        bool active;
        uint32_t queueBytes;
    };
    const std::vector<SafetyReleaseEvent> &GetSafetyReleaseEvents() const;
    struct ClassWeightSample
    {
        double time;
        uint64_t sensitiveBytes;
        uint64_t videoBytes;
        uint32_t sensitiveQuantum;
        uint32_t videoQuantum;
    };
    const std::vector<ClassWeightSample> &GetClassWeightSamples() const;
    /** Post-local-DBSP safe-delay balance for every video flow at this node. */
    void SetPecnFlowBudgets(std::vector<double> remainingBudgetSeconds);
    void ConfigureVideoRed(uint32_t minBytes, double maxProbability, DataRate linkRate);
    void ConfigureQuotaPecn(PecnQuota::Config config);
    const PecnQuota *GetQuotaPecn() const { return m_quotaPecn.get(); }
    /** Configure the offline historical peak used by formal PECN runs. */
    void SetPecnHistoricalPeakBytes(uint64_t historicalPeakBytes);
    void SetPecnThresholdRatio(double ratio);
    const std::vector<PecnMarkEvent> &GetPecnMarkEvents() const;
    void ConfigureMarkGate(bool enabled, Time start)
    {
        m_markGateEnabled = enabled;
        m_markGateStart = start;
    }
    struct OnInterval
    {
        uint32_t flow;
        double start;
        double last;
        uint64_t bytes;
    };
    void EnableOnTrace() { m_recordOn = true; }
    std::vector<OnInterval> GetOnIntervals() const;
    const std::vector<PecnDecisionEvent> &GetPecnDecisionEvents() const;
    std::vector<PecnBudgetState> GetPecnBudgetStates() const;

  private:
    struct FlowPolicy
    {
        DataRate rate{"0bps"};
        Time phase{Seconds(0)};
        Time period{Seconds(2)};
        Time nextEligible{Seconds(0)};
        // Apply relative phase at most once per refill period; TCP packet gaps
        // are not new media chunks.
        Time nextPhaseArm{Seconds(0)};
        bool gated{false};
        bool relativePhase{false};
        // The Tofino TM shaper is a token bucket. The control plane uses
        // bfrt.tf1.tm.queue.sched_shaping.mod(max_rate=..., max_burst_size=...)
        // to set both rate and bucket depth. The bucket admits a bounded burst
        // before rate limiting starts. Modeling a zero-depth, pure-rate spacer
        // would be stricter than hardware and overstate the QoE cost.
        uint32_t burstBytes{0};
        // Available tokens in bytes, capped by burstBytes.
        double tokenBytes{0.0};
        Time lastRefill{Seconds(0)};
    };

    bool DoEnqueue(Ptr<QueueDiscItem> item) override;
    Ptr<QueueDiscItem> DoDequeue() override;
    Ptr<const QueueDiscItem> DoPeek() override;
    bool CheckConfig() override;
    void InitializeParams() override;
    uint32_t Classify(const Ptr<QueueDiscItem> &item) const;
    bool GetVideoFlow(const Ptr<QueueDiscItem> &item, uint32_t &flow) const;
    bool VideoRedDrop(Ptr<QueueDiscItem> item, uint32_t queue);
    bool m_videoRedEnabled{false};
    uint32_t m_redMinBytes{0};
    double m_redMaxProbability{0.0};
    double m_redAverageBytes{0.0};
    double m_redPacketTime{0.0};
    int64_t m_redCount{-1};
    Time m_redIdleSince{Seconds(0)};
    Ptr<UniformRandomVariable> m_redRandom;
    bool GetTcpPayloadBytes(const Ptr<QueueDiscItem> &item, uint32_t &bytes) const;
    bool GetTcpFlowKey(const Ptr<QueueDiscItem> &item, uint64_t &key) const;
    void MaybeMarkPecn(Ptr<QueueDiscItem> item, uint32_t queue);
    void RefreshPecnState(Time now);
    void QueryQuotaPecn();
    void ObserveQuotaDeparture(Ptr<QueueDiscItem> item, uint32_t queue);
    std::unique_ptr<PecnQuota> m_quotaPecn;
    EventId m_quotaQueryEvent;
    double PecnActionCharge(double probability) const;
    uint64_t RecentVideoBytes(uint32_t flow, Time now);
    uint32_t VideoQueueCount() const;
    bool Eligible(uint32_t queue, Time now, Time &wake) const;
    void ScheduleWake(Time when);
    void UpdateClassWeights();
    void UpdateSafetyRelease();
    void DoDispose() override;

    uint32_t m_videoPortBase{5000};
    uint32_t m_videoFlows{8};
    // Number of TM queues used by video traffic. Tofino applies DWRR weights
    // to TM queues, not individual flows, and each port has a hard queue limit
    // (32 on Tofino 1). Therefore a "sensitive:video = 6:1" ratio depends on
    // how many queues video uses:
    //   - one queue per flow (= m_videoFlows): sensitive share = 6/(6 + N);
    //   - one queue for the whole class (= 1): sensitive share = 6/7.
    // The former enables per-queue shaping; the latter only class shaping.
    // Zero preserves m_videoFlows, i.e., one queue per flow.
    uint32_t m_videoQueues{0};
    // Explicit flow-to-queue map; empty means modulo mapping. See SetFlowQueueMap.
    std::vector<uint32_t> m_flowQueue;
    // Strict priority: serve q0 whenever it is non-empty; video queues use only
    // residual capacity. This lower-bound reference minimizes sensitive-flow
    // delay at the cost of possible video starvation. Tofino TM applies DWRR
    // only among queues in the same priority tier.
    bool m_strictPriority{false};
    uint32_t m_baseQuantum{1500};
    uint32_t m_sensitiveWeight{6};
    uint32_t m_videoWeight{1};
    std::vector<uint32_t> m_videoQuanta;
    uint32_t m_cursor{0};
    std::vector<int64_t> m_deficit;
    std::vector<FlowPolicy> m_policies;
    EventId m_wakeEvent;
    // Local arrival bytes from the previous complete window. Never use future
    // traffic, backlog, or dequeue throughput.
    Time m_dynamicClassEpoch{Seconds(0)};
    EventId m_classWeightEvent;
    uint64_t m_sensitiveArrivalBytes{0};
    uint64_t m_videoArrivalBytes{0};
    uint32_t m_dynamicSensitiveQuantum{0};
    std::vector<ClassWeightSample> m_classWeightSamples;
    bool m_safetyReleaseEnabled{false};
    double m_safetyHighWatermark{0.8};
    double m_safetyLowWatermark{0.6};
    bool m_safetyReleaseActive{false};
    std::vector<SafetyReleaseEvent> m_safetyReleaseEvents;

    bool m_pecnEnabled{false};
    bool m_markGateEnabled{true};
    Time m_markGateStart{Seconds(0)};
    bool m_recordOn{false};
    std::vector<OnInterval> m_onIntervals;
    uint32_t m_pecnQueueThresholdBytes{1048576};
    uint64_t m_pecnHistoricalPeakBytes{0};
    bool m_pecnHistoricalPeakConfigured{false};
    double m_pecnThresholdRatio{0.70};
    uint32_t m_pecnMinActiveFlows{8};
    uint32_t m_pecnMinVideoFlows{4};
    uint32_t m_pecnSelectionModulo{4};
    bool m_pecnContributionOrder{false};
    uint32_t m_pecnMaxSelectedFlows{0};
    double m_pecnMarkProbability{0.015625};
    double m_pecnMaxMarkProbability{0.125};
    double m_pecnMinBudgetSeconds{0.25};
    double m_pecnBudgetStepSeconds{0.05};
    Time m_pecnActiveWindow{MilliSeconds(20)};
    Time m_pecnEpoch{MilliSeconds(100)};
    Time m_pecnFeedbackWait{Seconds(0)};
    Time m_pecnNextAction{Seconds(0)};
    Ptr<UniformRandomVariable> m_pecnRandom;
    uint64_t m_pecnEpochIndex{std::numeric_limits<uint64_t>::max()};
    uint32_t m_pecnActiveFlows{0};
    uint32_t m_pecnActiveVideoFlows{0};
    std::unordered_map<uint64_t, Time> m_lastFlowArrival;
    std::vector<Time> m_lastVideoArrival;
    struct RecentPayload
    {
        std::deque<std::pair<Time, uint32_t>> packets;
        uint64_t bytes{0};
    };
    std::vector<RecentPayload> m_recentPayload;
    struct VideoEpisode
    {
        Time start{Seconds(-1)};
        Time last{Seconds(-1)};
        uint64_t bytes{0};
    };
    std::vector<VideoEpisode> m_videoEpisodes;
    std::vector<std::vector<VideoEpisode>> m_videoEpisodeHistory;
    std::vector<double> m_pecnInitialBudgetSeconds;
    std::vector<double> m_pecnUsedBudgetSeconds;
    std::vector<double> m_pecnFlowProbability;
    std::vector<uint32_t> m_pecnFlowLevel;
    std::vector<bool> m_pecnSelected;
    std::vector<uint32_t> m_pecnSelectedRank;
    uint32_t m_pecnClusterId{0};
    double m_pecnClusterPeakTimeSeconds{0.0};
    double m_pecnClusterPeakAgeSeconds{0.0};
    uint32_t m_pecnClusterSize{0};
    uint32_t m_pecnEligibleClusterFlows{0};
    uint64_t m_pecnHistoricalPeakBytesForTrace{0};
    uint64_t m_pecnThresholdBytesForTrace{0};
    double m_pecnQueueLevelPercent{0.0};
    uint32_t m_pecnIntensityLevel{0};
    double m_pecnMarkProbabilityForTrace{0.0};
    std::string m_pecnClusterMembers;
    std::vector<PecnMarkEvent> m_pecnMarkEvents;
    std::vector<PecnDecisionEvent> m_pecnDecisionEvents;
};

} // namespace ns3

#endif
