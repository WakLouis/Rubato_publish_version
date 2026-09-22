#include "rubato-queue-disc.h"

#include "ns3/boolean.h"
#include "ns3/data-rate.h"
#include "ns3/double.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/enum.h"
#include "ns3/ipv4-queue-disc-item.h"
#include "ns3/log.h"
#include "ns3/pointer.h"
#include "ns3/simulator.h"
#include "ns3/tcp-header.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <sstream>

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(IredQueueDisc);
NS_OBJECT_ENSURE_REGISTERED(RubatoQueueDisc);

namespace
{
constexpr const char *HARD_LIMIT_DROP = "Shared hard buffer limit";
constexpr const char *IRED_DROP = "iRED ingress drop";
constexpr const char *PECN_MARK = "PECN selective CE";
} // namespace

TypeId IredQueueDisc::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::IredQueueDisc")
            .SetParent<QueueDisc>()
            .SetGroupName("TrafficControl")
            .AddConstructor<IredQueueDisc>()
            .AddAttribute("MaxSize", "Shared hard queue limit.", QueueSizeValue(QueueSize("256KB")),
                          MakeQueueSizeAccessor(&QueueDisc::SetMaxSize, &QueueDisc::GetMaxSize),
                          MakeQueueSizeChecker())
            .AddAttribute("Weight", "EWMA weight.", DoubleValue(0.5),
                          MakeDoubleAccessor(&IredQueueDisc::m_weight),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("MinDelay", "Minimum queue-delay threshold.", TimeValue(MilliSeconds(20)),
                          MakeTimeAccessor(&IredQueueDisc::m_minDelay), MakeTimeChecker())
            .AddAttribute("MaxDelay", "Maximum queue-delay threshold.", TimeValue(MilliSeconds(40)),
                          MakeTimeAccessor(&IredQueueDisc::m_maxDelay), MakeTimeChecker())
            .AddAttribute("FeedbackDelay", "Egress decision to ingress action delay.",
                          TimeValue(NanoSeconds(750)),
                          MakeTimeAccessor(&IredQueueDisc::m_feedbackDelay), MakeTimeChecker())
            .AddAttribute("LinkRate", "Rate used to convert bytes to queue delay.",
                          DataRateValue(DataRate("100Mbps")),
                          MakeDataRateAccessor(&IredQueueDisc::m_linkRate), MakeDataRateChecker());
    return tid;
}

IredQueueDisc::IredQueueDisc()
    : QueueDisc(QueueDiscSizePolicy::SINGLE_INTERNAL_QUEUE),
      m_random(CreateObject<UniformRandomVariable>())
{
}

bool IredQueueDisc::DoEnqueue(Ptr<QueueDiscItem> item)
{
    if (GetCurrentSize() + item > GetMaxSize())
    {
        DropBeforeEnqueue(item, HARD_LIMIT_DROP);
        return false;
    }
    // Update average delay on enqueue as well. If updates occur only on
    // dequeue, an empty queue has no event to decay the average; a past
    // congestion episode can then cause an unrelated future packet to drop.
    UpdateAverageDelay();
    if (m_dropCredits > 0)
    {
        --m_dropCredits;
        DropBeforeEnqueue(item, IRED_DROP);
        return false;
    }
    return GetInternalQueue(0)->Enqueue(item);
}

void IredQueueDisc::UpdateAverageDelay()
{
    const double instantaneous =
        static_cast<double>(GetCurrentSize().GetValue()) * 8.0 / m_linkRate.GetBitRate();
    m_averageDelay = m_weight * instantaneous + (1.0 - m_weight) * m_averageDelay;
}

Ptr<QueueDiscItem> IredQueueDisc::DoDequeue()
{
    Ptr<QueueDiscItem> item = GetInternalQueue(0)->Dequeue();
    UpdateAverageDelay();

    double probability = 0.0;
    const double minDelay = m_minDelay.GetSeconds();
    const double maxDelay = m_maxDelay.GetSeconds();
    if (m_averageDelay >= maxDelay)
    {
        probability = 1.0;
    }
    else if (m_averageDelay > minDelay)
    {
        probability = (m_averageDelay - minDelay) / (maxDelay - minDelay);
    }
    if (probability > 0.0 && m_random->GetValue() < probability)
    {
        Simulator::Schedule(m_feedbackDelay, &IredQueueDisc::ArmDrop, this);
    }
    return item;
}

Ptr<const QueueDiscItem> IredQueueDisc::DoPeek() { return GetInternalQueue(0)->Peek(); }

bool IredQueueDisc::CheckConfig()
{
    if (GetNInternalQueues() == 0)
    {
        AddInternalQueue(CreateObjectWithAttributes<DropTailQueue<QueueDiscItem>>(
            "MaxSize", QueueSizeValue(GetMaxSize())));
    }
    return GetNInternalQueues() == 1 && m_maxDelay > m_minDelay;
}

void IredQueueDisc::InitializeParams()
{
    m_averageDelay = 0.0;
    m_dropCredits = 0;
}

void IredQueueDisc::ArmDrop() { ++m_dropCredits; }

TypeId RubatoQueueDisc::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::RubatoQueueDisc")
            .SetParent<QueueDisc>()
            .SetGroupName("TrafficControl")
            .AddConstructor<RubatoQueueDisc>()
            .AddAttribute("MaxSize", "Shared hard buffer across all internal queues.",
                          QueueSizeValue(QueueSize("256KB")),
                          MakeQueueSizeAccessor(&QueueDisc::SetMaxSize, &QueueDisc::GetMaxSize),
                          MakeQueueSizeChecker())
            .AddAttribute("VideoPortBase", "First TCP destination port assigned to video.",
                          UintegerValue(5000),
                          MakeUintegerAccessor(&RubatoQueueDisc::m_videoPortBase),
                          MakeUintegerChecker<uint32_t>(1, 65535))
            .AddAttribute("VideoFlows", "Number of video flows mapped into video queues.",
                          UintegerValue(8), MakeUintegerAccessor(&RubatoQueueDisc::m_videoFlows),
                          // Tofino 1 exposes 32 queues per port and Tofino 2
                          // exposes 128. The higher limit supports scaling
                          // studies; hardware configurations should use 32 or 128.
                          MakeUintegerChecker<uint32_t>(1, 4096))
            .AddAttribute("BaseQuantum", "DWRR base quantum in bytes.", UintegerValue(1500),
                          MakeUintegerAccessor(&RubatoQueueDisc::m_baseQuantum),
                          MakeUintegerChecker<uint32_t>(64))
            .AddAttribute("SensitiveWeight", "DWRR weight of the non-video queue.",
                          UintegerValue(6),
                          MakeUintegerAccessor(&RubatoQueueDisc::m_sensitiveWeight),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute("VideoWeight", "DWRR weight of each video queue.", UintegerValue(1),
                          MakeUintegerAccessor(&RubatoQueueDisc::m_videoWeight),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute("DynamicClassEpoch", "Local arrival-byte class weighting; zero disables.",
                          TimeValue(Seconds(0)),
                          MakeTimeAccessor(&RubatoQueueDisc::m_dynamicClassEpoch),
                          MakeTimeChecker(Seconds(0)))
            .AddAttribute("StrictPriority", "Serve the sensitive queue before any video queue.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&RubatoQueueDisc::m_strictPriority),
                          MakeBooleanChecker())
            .AddAttribute(
                "SafetyReleaseEnabled",
                "Bypass video shapers above the shared-buffer high watermark.", BooleanValue(false),
                MakeBooleanAccessor(&RubatoQueueDisc::m_safetyReleaseEnabled), MakeBooleanChecker())
            .AddAttribute("SafetyHighWatermark", "Shared-buffer fraction that releases shaping.",
                          DoubleValue(0.8),
                          MakeDoubleAccessor(&RubatoQueueDisc::m_safetyHighWatermark),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("SafetyLowWatermark", "Shared-buffer fraction that restores shaping.",
                          DoubleValue(0.6),
                          MakeDoubleAccessor(&RubatoQueueDisc::m_safetyLowWatermark),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("VideoQueues",
                          "Number of TM queues video shares; 0 means one queue per flow.",
                          UintegerValue(0), MakeUintegerAccessor(&RubatoQueueDisc::m_videoQueues),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("PecnEnabled", "Enable phase-aware selective ECN marking.",
                          BooleanValue(false), MakeBooleanAccessor(&RubatoQueueDisc::m_pecnEnabled),
                          MakeBooleanChecker())
            .AddAttribute("PecnContributionOrder",
                          "After safe-budget admission, rank by recent payload bytes.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&RubatoQueueDisc::m_pecnContributionOrder),
                          MakeBooleanChecker())
            .AddAttribute("PecnQueueThresholdBytes", "Queue pressure required by PECN.",
                          UintegerValue(1048576),
                          MakeUintegerAccessor(&RubatoQueueDisc::m_pecnQueueThresholdBytes),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute(
                "PecnThresholdRatio", "Fraction of the offline historical peak that triggers PECN.",
                DoubleValue(0.70), MakeDoubleAccessor(&RubatoQueueDisc::m_pecnThresholdRatio),
                MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("PecnMinActiveFlows", "Recently active flows across q0--q7 required.",
                          UintegerValue(8),
                          MakeUintegerAccessor(&RubatoQueueDisc::m_pecnMinActiveFlows),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute("PecnMinVideoFlows", "Recently active video flows required.",
                          UintegerValue(4),
                          MakeUintegerAccessor(&RubatoQueueDisc::m_pecnMinVideoFlows),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute("PecnSelectionModulo", "Rotating fraction denominator.", UintegerValue(4),
                          MakeUintegerAccessor(&RubatoQueueDisc::m_pecnSelectionModulo),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute(
                "PecnMaxSelectedFlows",
                "Hard cap on selected PECN flows per epoch; zero leaves the fraction uncapped.",
                UintegerValue(0), MakeUintegerAccessor(&RubatoQueueDisc::m_pecnMaxSelectedFlows),
                MakeUintegerChecker<uint32_t>())
            .AddAttribute("PecnMarkProbability", "CE probability within selected subset.",
                          DoubleValue(1.0 / 64.0),
                          MakeDoubleAccessor(&RubatoQueueDisc::m_pecnMarkProbability),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("PecnMaxMarkProbability", "Largest DCTCP byte-marking staircase level.",
                          DoubleValue(1.0 / 8.0),
                          MakeDoubleAccessor(&RubatoQueueDisc::m_pecnMaxMarkProbability),
                          MakeDoubleChecker<double>(0.0, 1.0))
            .AddAttribute("PecnMinBudget", "Minimum DBSP balance required for a PECN action.",
                          DoubleValue(0.25),
                          MakeDoubleAccessor(&RubatoQueueDisc::m_pecnMinBudgetSeconds),
                          MakeDoubleChecker<double>(0.0))
            .AddAttribute(
                "PecnBudgetStep", "Observation-ledger amount at the first staircase level.",
                DoubleValue(0.05), MakeDoubleAccessor(&RubatoQueueDisc::m_pecnBudgetStepSeconds),
                MakeDoubleChecker<double>(0.0))
            .AddAttribute("PecnActiveWindow", "Window used to detect overlapping ON flows.",
                          TimeValue(MilliSeconds(20)),
                          MakeTimeAccessor(&RubatoQueueDisc::m_pecnActiveWindow), MakeTimeChecker())
            .AddAttribute("PecnEpoch", "Measurement, sorting, and DCTCP action epoch.",
                          TimeValue(MilliSeconds(100)),
                          MakeTimeAccessor(&RubatoQueueDisc::m_pecnEpoch), MakeTimeChecker())
            .AddAttribute("PecnFeedbackWait",
                          "Minimum time from first actual CE to the next action; zero disables.",
                          TimeValue(Seconds(0)),
                          MakeTimeAccessor(&RubatoQueueDisc::m_pecnFeedbackWait),
                          MakeTimeChecker());
    return tid;
}

RubatoQueueDisc::RubatoQueueDisc()
    : QueueDisc(QueueDiscSizePolicy::MULTIPLE_QUEUES),
      m_pecnRandom(CreateObject<UniformRandomVariable>())
{
}

uint32_t RubatoQueueDisc::VideoQueueCount() const
{
    // Zero keeps one queue per flow. Otherwise fold video flows into the
    // finite queue set using flow % VideoQueues.
    // Explicit queue resources may exceed the number of flows; retain empty queues.
    return m_videoQueues == 0 ? m_videoFlows : m_videoQueues;
}

void RubatoQueueDisc::SetFlowPolicy(uint32_t flow, DataRate rate, Time phase, Time period,
                                    bool gated, bool relativePhase, uint32_t burstBytes)
{
    const uint32_t queues = VideoQueueCount();
    NS_ABORT_MSG_IF(flow >= queues, "Video queue index out of range");
    if (m_policies.size() != queues)
    {
        m_policies.resize(queues);
    }
    auto &policy = m_policies[flow];
    policy.rate = rate;
    policy.phase = phase;
    policy.period = period;
    policy.nextEligible = phase;
    policy.nextPhaseArm = Seconds(0);
    policy.relativePhase = relativePhase;
    policy.burstBytes = burstBytes;
    // Start with a full token bucket, matching a newly installed shaper before
    // the queue has accumulated backlog.
    policy.tokenBytes = static_cast<double>(burstBytes);
    policy.lastRefill = Simulator::Now();
    policy.gated = gated;
}

void RubatoQueueDisc::UpdateQueueRate(uint32_t queue, DataRate rate, uint32_t burstBytes)
{
    NS_ABORT_MSG_IF(queue >= m_policies.size() || rate.GetBitRate() == 0,
                    "Invalid DBSP runtime queue-rate update");
    auto &policy = m_policies[queue];
    const Time now = Simulator::Now();
    const double elapsed = std::max(0.0, (now - policy.lastRefill).GetSeconds());
    policy.tokenBytes = std::min<double>(
        policy.burstBytes, policy.tokenBytes + elapsed * policy.rate.GetBitRate() / 8.0);
    policy.rate = rate;
    policy.burstBytes = burstBytes;
    policy.tokenBytes = std::min<double>(policy.tokenBytes, burstBytes);
    policy.lastRefill = now;
    policy.nextEligible =
        policy.tokenBytes < 0.0 ? now + Seconds(-policy.tokenBytes * 8.0 / rate.GetBitRate()) : now;
    if (!GetInternalQueue(queue + 1)->IsEmpty())
    {
        ScheduleWake(policy.nextEligible);
    }
}

uint32_t RubatoQueueDisc::GetQueueBytes(uint32_t queue) const
{
    return queue < GetNInternalQueues() ? GetInternalQueue(queue)->GetNBytes() : 0;
}

uint32_t RubatoQueueDisc::Classify(const Ptr<QueueDiscItem> &item) const
{
    Ptr<Ipv4QueueDiscItem> ipv4 = DynamicCast<Ipv4QueueDiscItem>(item);
    if (!ipv4 || ipv4->GetHeader().GetProtocol() != 6)
    {
        return 0;
    }
    TcpHeader tcp;
    if (ipv4->GetPacket()->PeekHeader(tcp) == 0)
    {
        return 0;
    }
    const uint32_t port = tcp.GetDestinationPort();
    if (port >= m_videoPortBase && port < m_videoPortBase + m_videoFlows)
    {
        // Tofino DWRR and shaping operate on TM queues with a hard queue-count
        // limit. Excess flows must share queues; FIFO sharing leaves only a
        // group rate, not independently controllable per-flow rates.
        const uint32_t flow = port - m_videoPortBase;
        if (!m_flowQueue.empty())
        {
            NS_ABORT_MSG_IF(flow >= m_flowQueue.size() || m_flowQueue[flow] >= VideoQueueCount(),
                            "Packet has no valid local video queue assignment");
            return 1 + m_flowQueue[flow];
        }
        return 1 + flow % VideoQueueCount();
    }
    return 0;
}

void RubatoQueueDisc::SetFlowQueueMap(std::vector<uint32_t> map) { m_flowQueue = std::move(map); }

void RubatoQueueDisc::SetPecnFlowBudgets(std::vector<double> remainingBudgetSeconds)
{
    NS_ABORT_MSG_IF(remainingBudgetSeconds.size() != m_videoFlows,
                    "PECN budget vector must contain one entry per video flow");
    NS_ABORT_MSG_IF(std::any_of(remainingBudgetSeconds.begin(), remainingBudgetSeconds.end(),
                                [](double value) { return !std::isfinite(value) || value < 0.0; }),
                    "PECN budgets must be finite and non-negative");
    m_pecnInitialBudgetSeconds = std::move(remainingBudgetSeconds);
    // DBSP may refresh its balance every control epoch.  Keep the PECN amount
    // as an observation ledger across those refreshes; it is intentionally not
    // subtracted from the DBSP balance used for candidate admission.
    if (m_pecnUsedBudgetSeconds.size() != m_videoFlows)
    {
        m_pecnUsedBudgetSeconds.assign(m_videoFlows, 0.0);
    }
}

void RubatoQueueDisc::SetPecnHistoricalPeakBytes(uint64_t historicalPeakBytes)
{
    m_pecnHistoricalPeakBytes = historicalPeakBytes;
    m_pecnHistoricalPeakConfigured = true;
}

void RubatoQueueDisc::SetPecnThresholdRatio(double ratio)
{
    NS_ABORT_MSG_IF(!std::isfinite(ratio) || ratio <= 0.0 || ratio > 1.0,
                    "PECN historical threshold ratio must be in (0, 1]");
    m_pecnThresholdRatio = ratio;
}

const std::vector<RubatoQueueDisc::PecnMarkEvent> &RubatoQueueDisc::GetPecnMarkEvents() const
{
    return m_pecnMarkEvents;
}

const std::vector<RubatoQueueDisc::PecnDecisionEvent> &
RubatoQueueDisc::GetPecnDecisionEvents() const
{
    return m_pecnDecisionEvents;
}

std::vector<RubatoQueueDisc::PecnBudgetState> RubatoQueueDisc::GetPecnBudgetStates() const
{
    std::vector<PecnBudgetState> states;
    states.reserve(m_pecnInitialBudgetSeconds.size());
    for (uint32_t flow = 0; flow < m_pecnInitialBudgetSeconds.size(); ++flow)
    {
        states.push_back({m_pecnInitialBudgetSeconds[flow], m_pecnUsedBudgetSeconds[flow],
                          m_pecnFlowLevel[flow]});
    }
    return states;
}

bool RubatoQueueDisc::GetVideoFlow(const Ptr<QueueDiscItem> &item, uint32_t &flow) const
{
    Ptr<Ipv4QueueDiscItem> ipv4 = DynamicCast<Ipv4QueueDiscItem>(item);
    if (!ipv4 || ipv4->GetHeader().GetProtocol() != 6)
    {
        return false;
    }
    TcpHeader tcp;
    if (ipv4->GetPacket()->PeekHeader(tcp) == 0)
    {
        return false;
    }
    const uint32_t port = tcp.GetDestinationPort();
    if (port < m_videoPortBase || port >= m_videoPortBase + m_videoFlows)
    {
        return false;
    }
    flow = port - m_videoPortBase;
    return true;
}

bool RubatoQueueDisc::GetTcpPayloadBytes(const Ptr<QueueDiscItem> &item, uint32_t &bytes) const
{
    Ptr<Ipv4QueueDiscItem> ipv4 = DynamicCast<Ipv4QueueDiscItem>(item);
    if (!ipv4 || ipv4->GetHeader().GetProtocol() != 6)
    {
        return false;
    }
    TcpHeader tcp;
    const Ptr<const Packet> packet = ipv4->GetPacket();
    if (!packet || packet->PeekHeader(tcp) == 0)
    {
        return false;
    }
    const uint32_t tcpHeaderBytes = static_cast<uint32_t>(tcp.GetLength()) * 4;
    if (packet->GetSize() <= tcpHeaderBytes)
    {
        return false;
    }
    bytes = packet->GetSize() - tcpHeaderBytes;
    return bytes > 0;
}

bool RubatoQueueDisc::GetTcpFlowKey(const Ptr<QueueDiscItem> &item, uint64_t &key) const
{
    Ptr<Ipv4QueueDiscItem> ipv4 = DynamicCast<Ipv4QueueDiscItem>(item);
    if (!ipv4 || ipv4->GetHeader().GetProtocol() != 6)
    {
        return false;
    }
    TcpHeader tcp;
    if (ipv4->GetPacket()->PeekHeader(tcp) == 0)
    {
        return false;
    }
    // FNV-1a over the forward-path IPv4/TCP 4-tuple.  The controlled queue discs
    // only see the forward direction, so one key represents one q0--q7 flow.
    uint64_t hash = 1469598103934665603ULL;
    const uint64_t fields[] = {ipv4->GetHeader().GetSource().Get(),
                               ipv4->GetHeader().GetDestination().Get(), tcp.GetSourcePort(),
                               tcp.GetDestinationPort()};
    for (uint64_t field : fields)
    {
        hash ^= field;
        hash *= 1099511628211ULL;
    }
    key = hash;
    return true;
}

double RubatoQueueDisc::PecnActionCharge(double probability) const
{
    return m_pecnBudgetStepSeconds * probability / std::max(m_pecnMarkProbability, 1e-12);
}

std::vector<RubatoQueueDisc::OnInterval> RubatoQueueDisc::GetOnIntervals() const
{
    auto intervals = m_onIntervals;
    if (m_recordOn)
    {
        for (uint32_t flow = 0; flow < m_videoEpisodes.size(); ++flow)
        {
            const auto &episode = m_videoEpisodes[flow];
            if (episode.last >= Seconds(0))
            {
                intervals.push_back(
                    {flow, episode.start.GetSeconds(), episode.last.GetSeconds(), episode.bytes});
            }
        }
    }
    return intervals;
}

uint64_t RubatoQueueDisc::RecentVideoBytes(uint32_t flow, Time now)
{
    auto &recent = m_recentPayload[flow];
    while (!recent.packets.empty() && recent.packets.front().first < now - m_pecnActiveWindow)
    {
        recent.bytes -= recent.packets.front().second;
        recent.packets.pop_front();
    }
    return recent.bytes;
}

void RubatoQueueDisc::RefreshPecnState(Time now)
{
    const uint64_t epoch =
        static_cast<uint64_t>(now.GetNanoSeconds() / m_pecnEpoch.GetNanoSeconds());
    if (epoch == m_pecnEpochIndex)
    {
        return;
    }
    m_pecnEpochIndex = epoch;
    std::fill(m_pecnSelected.begin(), m_pecnSelected.end(), false);
    std::fill(m_pecnFlowProbability.begin(), m_pecnFlowProbability.end(), 0.0);
    std::fill(m_pecnFlowLevel.begin(), m_pecnFlowLevel.end(), 0);
    std::fill(m_pecnSelectedRank.begin(), m_pecnSelectedRank.end(), 0);
    m_pecnClusterId = 0;
    m_pecnClusterPeakTimeSeconds = 0.0;
    m_pecnClusterPeakAgeSeconds = 0.0;
    m_pecnClusterSize = 0;
    m_pecnEligibleClusterFlows = 0;
    m_pecnClusterMembers.clear();

    const uint64_t historicalPeakBytes =
        m_pecnHistoricalPeakConfigured ? m_pecnHistoricalPeakBytes : 0;
    const uint64_t thresholdBytes =
        m_pecnHistoricalPeakConfigured && historicalPeakBytes > 0
            ? static_cast<uint64_t>(std::ceil(historicalPeakBytes * m_pecnThresholdRatio))
            : m_pecnQueueThresholdBytes;
    m_pecnHistoricalPeakBytesForTrace = historicalPeakBytes;
    m_pecnThresholdBytesForTrace = thresholdBytes;

    auto recordDecision = [&](bool triggered, const std::string &reason)
    {
        m_pecnDecisionEvents.push_back(
            {now.GetSeconds(), epoch, triggered, m_pecnClusterId, m_pecnClusterPeakTimeSeconds,
             m_pecnClusterSize, m_pecnEligibleClusterFlows,
             static_cast<uint32_t>(std::count(m_pecnSelected.begin(), m_pecnSelected.end(), true)),
             m_pecnHistoricalPeakBytesForTrace, m_pecnThresholdBytesForTrace,
             m_pecnQueueLevelPercent, m_pecnIntensityLevel, m_pecnMarkProbabilityForTrace,
             m_pecnClusterPeakAgeSeconds, m_pecnClusterMembers, reason});
    };

    m_pecnActiveFlows = 0;
    for (auto it = m_lastFlowArrival.begin(); it != m_lastFlowArrival.end();)
    {
        if (now - it->second <= m_pecnActiveWindow)
        {
            ++m_pecnActiveFlows;
            ++it;
        }
        else
        {
            it = m_lastFlowArrival.erase(it);
        }
    }
    m_pecnActiveVideoFlows = 0;
    for (const Time &last : m_lastVideoArrival)
    {
        m_pecnActiveVideoFlows += last >= Seconds(0) && now - last <= m_pecnActiveWindow;
    }

    uint64_t videoBytes = 0;
    for (uint32_t queue = 1; queue < GetNInternalQueues(); ++queue)
    {
        videoBytes += GetInternalQueue(queue)->GetNBytes();
    }
    const uint64_t queueBytes = GetCurrentSize().GetValue();
    if (m_pecnHistoricalPeakConfigured && historicalPeakBytes == 0)
    {
        recordDecision(false, "historical_peak_unavailable");
        return;
    }
    // A legacy fixed threshold is the trigger (70%), not a measured peak
    // (100%). Treating it as Qhist made the first admitted action saturate.
    // Keep absent historical measurements explicit in the trace.
    m_pecnQueueLevelPercent =
        historicalPeakBytes > 0
            ? 100.0 * static_cast<double>(queueBytes) / static_cast<double>(historicalPeakBytes)
            : 70.0 * static_cast<double>(queueBytes) /
                  static_cast<double>(std::max<uint64_t>(thresholdBytes, 1));
    const double levelAboveThreshold = std::max(0.0, m_pecnQueueLevelPercent - 70.0);
    m_pecnIntensityLevel = static_cast<uint32_t>(std::floor(levelAboveThreshold + 1e-12));
    const double deltaProbability = (m_pecnMaxMarkProbability - m_pecnMarkProbability) / 30.0;
    m_pecnMarkProbabilityForTrace = std::min(
        m_pecnMaxMarkProbability, m_pecnMarkProbability + m_pecnIntensityLevel * deltaProbability);
    const bool triggered = queueBytes >= thresholdBytes && videoBytes > 0 &&
                           m_pecnActiveFlows >= m_pecnMinActiveFlows &&
                           m_pecnActiveVideoFlows >= m_pecnMinVideoFlows;
    if (now < m_pecnNextAction)
    {
        recordDecision(triggered, "feedback_wait");
        return;
    }
    if (!triggered)
    {
        recordDecision(false, "not_triggered");
        return;
    }
    if (m_pecnInitialBudgetSeconds.size() != m_videoFlows)
    {
        recordDecision(true, "budget_unavailable");
        return;
    }

    struct EpisodeInterval
    {
        uint32_t flow;
        Time start;
        Time end;
        uint64_t bytes;
    };
    std::vector<EpisodeInterval> intervals;
    std::vector<Time> boundaries;
    const Time windowStart = now - m_pecnActiveWindow;
    const Time windowEnd = now;
    for (uint32_t flow = 0; flow < m_videoEpisodes.size(); ++flow)
    {
        auto &history = m_videoEpisodeHistory[flow];
        history.erase(std::remove_if(history.begin(), history.end(),
                                     [&](const VideoEpisode &episode)
                                     { return episode.last + m_pecnActiveWindow <= windowStart; }),
                      history.end());
        auto addInterval = [&](const VideoEpisode &episode)
        {
            if (episode.start < Seconds(0) || episode.last < Seconds(0))
            {
                return;
            }
            if (m_lastVideoArrival[flow] < Seconds(0) ||
                now - m_lastVideoArrival[flow] > m_pecnActiveWindow)
            {
                return;
            }
            const Time end = episode.last + m_pecnActiveWindow;
            if (end <= windowStart || episode.start > windowEnd)
            {
                return;
            }
            const Time start = episode.start < windowStart ? windowStart : episode.start;
            if (start <= windowEnd && end > start)
            {
                intervals.push_back({flow, start, end, episode.bytes});
                boundaries.push_back(start);
                boundaries.push_back(end < windowEnd ? end : windowEnd);
            }
        };
        for (const auto &episode : history)
        {
            addInterval(episode);
        }
        addInterval(m_videoEpisodes[flow]);
    }
    if (intervals.empty())
    {
        recordDecision(true, "no_overlap_cluster");
        return;
    }

    std::sort(boundaries.begin(), boundaries.end(), [](const Time &left, const Time &right)
              { return left.GetNanoSeconds() < right.GetNanoSeconds(); });
    boundaries.erase(std::unique(boundaries.begin(), boundaries.end(),
                                 [](const Time &left, const Time &right)
                                 { return left.GetNanoSeconds() == right.GetNanoSeconds(); }),
                     boundaries.end());

    std::vector<uint32_t> clusterFlows;
    uint64_t clusterBytes = 0;
    Time clusterPeak = Seconds(-1);
    auto considerPoint = [&](Time point)
    {
        if (point < windowStart || point > windowEnd)
        {
            return;
        }
        std::vector<uint32_t> members;
        uint64_t bytes = 0;
        for (const auto &interval : intervals)
        {
            const bool activeNow = m_lastVideoArrival[interval.flow] >= Seconds(0) &&
                                   now - m_lastVideoArrival[interval.flow] <= m_pecnActiveWindow;
            if (activeNow && interval.start <= point && point < interval.end)
            {
                members.push_back(interval.flow);
                bytes += interval.bytes;
            }
        }
        std::sort(members.begin(), members.end());
        const bool better =
            members.size() > clusterFlows.size() ||
            (members.size() == clusterFlows.size() && bytes > clusterBytes) ||
            (members.size() == clusterFlows.size() && bytes == clusterBytes && point > clusterPeak);
        if (better)
        {
            clusterFlows = std::move(members);
            clusterBytes = bytes;
            clusterPeak = point;
        }
    };
    for (const Time &point : boundaries)
    {
        considerPoint(point);
    }
    if (clusterFlows.empty())
    {
        recordDecision(true, "no_overlap_cluster");
        return;
    }
    m_pecnClusterId = static_cast<uint32_t>((epoch + 1) & 0xffffffffULL);
    m_pecnClusterPeakTimeSeconds = clusterPeak.GetSeconds();
    m_pecnClusterPeakAgeSeconds = std::max(0.0, now.GetSeconds() - clusterPeak.GetSeconds());
    m_pecnClusterSize = clusterFlows.size();
    {
        std::ostringstream members;
        for (size_t index = 0; index < clusterFlows.size(); ++index)
        {
            if (index > 0)
            {
                members << ';';
            }
            members << clusterFlows[index];
        }
        m_pecnClusterMembers = members.str();
    }
    if (m_pecnClusterSize < m_pecnMinVideoFlows)
    {
        recordDecision(true, "cluster_below_min");
        return;
    }

    struct Candidate
    {
        uint32_t flow;
        double remaining;
        double charge;
        uint64_t recentBytes;
    };
    std::vector<Candidate> candidates;
    const uint32_t level = m_pecnIntensityLevel;
    const double probability = m_pecnMarkProbabilityForTrace;
    const double charge = PecnActionCharge(probability);
    for (const uint32_t flow : clusterFlows)
    {
        if (m_lastVideoArrival[flow] < Seconds(0) ||
            now - m_lastVideoArrival[flow] > m_pecnActiveWindow)
        {
            continue;
        }
        // PECN history is an observation counter only.  Candidate admission
        // and ordering use the local DBSP balance without pre-deducting
        // previous PECN actions.
        const double remaining = m_pecnInitialBudgetSeconds[flow];
        if (remaining >= m_pecnMinBudgetSeconds + charge)
        {
            candidates.push_back({flow, remaining, charge,
                                  m_pecnContributionOrder ? RecentVideoBytes(flow, now) : 0});
        }
    }
    m_pecnEligibleClusterFlows = candidates.size();
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate &left, const Candidate &right)
              {
                  if (left.recentBytes != right.recentBytes)
                  {
                      return left.recentBytes > right.recentBytes;
                  }
                  if (left.remaining != right.remaining)
                  {
                      return left.remaining > right.remaining;
                  }
                  return left.flow < right.flow;
              });
    if (candidates.empty())
    {
        recordDecision(true, "no_eligible_cluster_flows");
        return;
    }

    uint32_t selected = std::min<uint32_t>(
        candidates.size(),
        static_cast<uint32_t>(std::ceil(static_cast<double>(candidates.size()) /
                                        std::max<uint32_t>(m_pecnSelectionModulo, 1))));
    if (m_pecnMaxSelectedFlows > 0)
    {
        selected = std::min(selected, m_pecnMaxSelectedFlows);
    }
    for (uint32_t index = 0; index < selected; ++index)
    {
        const auto &candidate = candidates[index];
        m_pecnSelected[candidate.flow] = true;
        m_pecnSelectedRank[candidate.flow] = index + 1;
        m_pecnFlowLevel[candidate.flow] = level;
        m_pecnFlowProbability[candidate.flow] = probability;
        m_pecnUsedBudgetSeconds[candidate.flow] += candidate.charge;
    }
    recordDecision(true, "selected");
}

void RubatoQueueDisc::MaybeMarkPecn(Ptr<QueueDiscItem> item, uint32_t queue)
{
    if (!m_pecnEnabled || m_quotaPecn)
    {
        return;
    }
    const Time now = Simulator::Now();
    uint32_t payloadBytes = 0;
    const bool payload = GetTcpPayloadBytes(item, payloadBytes);
    uint64_t key = 0;
    if (payload && GetTcpFlowKey(item, key))
    {
        m_lastFlowArrival[key] = now;
    }
    uint32_t flow = 0;
    const bool video = queue > 0 && GetVideoFlow(item, flow);
    if (video && payload)
    {
        if (m_pecnContributionOrder)
        {
            RecentVideoBytes(flow, now);
            m_recentPayload[flow].packets.emplace_back(now, payloadBytes);
            m_recentPayload[flow].bytes += payloadBytes;
        }
        m_lastVideoArrival[flow] = now;
        auto &episode = m_videoEpisodes[flow];
        if (episode.last < Seconds(0) || now - episode.last > m_pecnActiveWindow)
        {
            if (episode.last >= Seconds(0))
            {
                m_videoEpisodeHistory[flow].push_back(episode);
                if (m_recordOn)
                {
                    m_onIntervals.push_back({flow, episode.start.GetSeconds(),
                                             episode.last.GetSeconds(), episode.bytes});
                }
            }
            episode.start = now;
            episode.last = Seconds(-1);
            episode.bytes = 0;
        }
        episode.last = now;
        episode.bytes += payloadBytes;
    }
    RefreshPecnState(now);
    if (!m_markGateEnabled || now < m_markGateStart)
    {
        return;
    }
    if (!video || !payload || flow >= m_pecnSelected.size() || !m_pecnSelected[flow])
    {
        return;
    }
    const double probability = m_pecnFlowProbability[flow];
    // A new chunk may update the DBSP balance within this control epoch.
    // Revoke stale admission before drawing randomness or issuing CE; do not
    // deduct historical PECN observations or replace the flow from another cluster.
    if (m_pecnInitialBudgetSeconds[flow] < m_pecnMinBudgetSeconds + PecnActionCharge(probability))
    {
        m_pecnSelected[flow] = false;
        return;
    }
    if (m_pecnRandom->GetValue() >= probability)
    {
        return;
    }
    if (Mark(item, PECN_MARK))
    {
        // Finish this epoch's pulse, then observe feedback. Admission without
        // an actual CE must not start the waiting interval.
        if (m_pecnFeedbackWait.IsStrictlyPositive() && now >= m_pecnNextAction)
        {
            m_pecnNextAction = now + m_pecnFeedbackWait;
        }
        m_pecnMarkEvents.push_back({now.GetSeconds(),
                                    flow,
                                    queue,
                                    GetCurrentSize().GetValue(),
                                    m_pecnActiveFlows,
                                    m_pecnActiveVideoFlows,
                                    m_pecnInitialBudgetSeconds[flow],
                                    m_pecnUsedBudgetSeconds[flow],
                                    m_pecnHistoricalPeakBytesForTrace,
                                    m_pecnThresholdBytesForTrace,
                                    m_pecnQueueLevelPercent,
                                    m_pecnIntensityLevel,
                                    probability,
                                    m_pecnClusterId,
                                    m_pecnClusterPeakTimeSeconds,
                                    m_pecnClusterPeakAgeSeconds,
                                    m_pecnClusterSize,
                                    m_pecnEligibleClusterFlows,
                                    m_pecnSelectedRank[flow],
                                    m_pecnClusterMembers,
                                    m_pecnContributionOrder ? RecentVideoBytes(flow, now) : 0});
    }
}

void RubatoQueueDisc::ConfigureQuotaPecn(PecnQuota::Config config)
{
    NS_ABORT_MSG_IF(!m_pecnEnabled, "Quota PECN requires an enabled deployment node");
    m_quotaPecn = std::make_unique<PecnQuota>(m_videoFlows, config);
}

void RubatoQueueDisc::QueryQuotaPecn()
{
    m_quotaPecn->Query(Simulator::Now().GetNanoSeconds(), m_pecnInitialBudgetSeconds);
    m_quotaQueryEvent = Simulator::Schedule(NanoSeconds(m_quotaPecn->GetConfig().epochNs),
                                            &RubatoQueueDisc::QueryQuotaPecn, this);
}

void RubatoQueueDisc::ObserveQuotaDeparture(Ptr<QueueDiscItem> item, uint32_t queue)
{
    if (!m_quotaPecn)
        return;
    const auto now = Simulator::Now();
    const auto ns = now.GetNanoSeconds();
    m_quotaPecn->ObservePort(item->GetSize());
    if (queue == 0)
    {
        // QueueDisc's enqueue timestamp emulates real ingress-to-egress metadata.
        m_quotaPecn->ObserveQ0(ns, (now - item->GetTimeStamp()).GetNanoSeconds());
        return;
    }
    uint32_t flow = 0, payload = 0;
    uint64_t key = 0;
    if (!GetVideoFlow(item, flow) || !GetTcpPayloadBytes(item, payload) || !payload ||
        !GetTcpFlowKey(item, key))
        return;
    m_quotaPecn->ObserveVideo(flow, key, item->GetSize());
    const auto ipv4 = DynamicCast<Ipv4QueueDiscItem>(item);
    if (!ipv4)
        return;
    const auto ecn = ipv4->GetHeader().GetEcn();
    if (ecn != Ipv4Header::ECN_ECT0 && ecn != Ipv4Header::ECN_ECT1)
        return;
    if (!m_markGateEnabled || now < m_markGateStart || !m_quotaPecn->CanMark(flow, ns))
        return;
    const double probability = m_quotaPecn->GetConfig().packetProbability;
    // p=1 preserves the original behavior without drawing RNG. The quota is
    // still a hard cap; sampling spreads eligible marks rather than filling it.
    const double sample = probability < 1.0 ? m_pecnRandom->GetValue() : 0.0;
    if (!m_quotaPecn->CanMark(flow, ns, sample))
        return;
    if (Mark(item, PECN_MARK))
    {
        m_quotaPecn->CommitMark(flow, ns, sample);
        const auto &lease = m_quotaPecn->GetLease(flow);
        // Compatibility file only: quota mode has no legacy phase-cluster fields.
        m_pecnMarkEvents.push_back({now.GetSeconds(),
                                    flow,
                                    queue,
                                    GetCurrentSize().GetValue(),
                                    0,
                                    0,
                                    lease.budgetSeconds,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    probability,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    lease.rank,
                                    "",
                                    lease.estimateBytes});
    }
}

void RubatoQueueDisc::ConfigureVideoRed(uint32_t minBytes, double maxProbability, DataRate linkRate)
{
    NS_ABORT_MSG_IF(minBytes == 0 || minBytes >= GetMaxSize().GetValue() / 2 ||
                        !std::isfinite(maxProbability) || maxProbability < 0 ||
                        maxProbability > 1 || linkRate.GetBitRate() == 0,
                    "Invalid classify-RED configuration");
    m_videoRedEnabled = true;
    m_redMinBytes = minBytes;
    m_redMaxProbability = maxProbability;
    m_redPacketTime = 1500.0 * 8.0 / linkRate.GetBitRate();
    m_redRandom = CreateObject<UniformRandomVariable>();
    // Separate reproducible stream: enabling RED does not shift workload RNGs.
    m_redRandom->SetStream(73001);
}

bool RubatoQueueDisc::VideoRedDrop(Ptr<QueueDiscItem> item, uint32_t queue)
{
    uint32_t payload = 0;
    if (queue != 1 || !GetTcpPayloadBytes(item, payload) || payload == 0)
    {
        return false;
    }
    constexpr double weight = 0.002;
    const Time now = Simulator::Now();
    if (GetInternalQueue(1)->IsEmpty())
    {
        const double slots = std::max(0.0, (now - m_redIdleSince).GetSeconds()) / m_redPacketTime;
        m_redAverageBytes *= std::pow(1.0 - weight, slots);
        m_redIdleSince = now;
    }
    m_redAverageBytes = (1.0 - weight) * m_redAverageBytes + weight * GetQueueBytes(1);
    if (m_redAverageBytes < m_redMinBytes)
    {
        m_redCount = -1;
        return false;
    }
    if (m_redAverageBytes >= 2.0 * m_redMinBytes)
    {
        m_redCount = 0;
        return true;
    }
    ++m_redCount;
    const double pb = m_redMaxProbability * (m_redAverageBytes - m_redMinBytes) / m_redMinBytes;
    const double denominator = 1.0 - m_redCount * pb;
    const double pa = denominator <= 0 ? 1.0 : std::min(1.0, pb / denominator);
    if (m_redRandom->GetValue() < pa)
    {
        m_redCount = 0;
        return true;
    }
    return false;
}

bool RubatoQueueDisc::DoEnqueue(Ptr<QueueDiscItem> item)
{
    if (m_dynamicClassEpoch.IsStrictlyPositive())
    {
        // Count bytes offered to this egress, including arrivals rejected by
        // the hard buffer and excluding repeated dequeue attempts.
        (Classify(item) == 0 ? m_sensitiveArrivalBytes : m_videoArrivalBytes) += item->GetSize();
    }
    if (GetCurrentSize() + item > GetMaxSize())
    {
        DropBeforeEnqueue(item, HARD_LIMIT_DROP);
        return false;
    }
    const uint32_t queue = Classify(item);
    if (m_videoRedEnabled && VideoRedDrop(item, queue))
    {
        DropBeforeEnqueue(item, "CLASSIFY_RED");
        return false;
    }
    MaybeMarkPecn(item, queue);
    if (queue > 0 && GetInternalQueue(queue)->IsEmpty() && m_policies[queue - 1].gated)
    {
        auto &policy = m_policies[queue - 1];
        const Time now = Simulator::Now();
        Time gate = now;
        if (policy.relativePhase)
        {
            if (now >= policy.nextPhaseArm)
            {
                gate = now + policy.phase;
                policy.nextPhaseArm = now + policy.period;
            }
        }
        else
        {
            const int64_t cycle = now.GetNanoSeconds() / policy.period.GetNanoSeconds();
            const Time target = policy.period * cycle + policy.phase;
            gate = target > now ? target : now;
        }
        // A phase may delay a release but never move it earlier.
        //
        // DoDequeue advances nextEligible until enough tokens accumulate.
        // Overwriting it here would erase token debt whenever a fast egress
        // drains between packets, effectively disabling shaping.
        //
        // A slow, continuously backlogged egress masks this bug; it appears
        // when the actuator itself is not the bottleneck.
        policy.nextEligible = std::max(policy.nextEligible, gate);
    }
    const bool accepted = GetInternalQueue(queue)->Enqueue(item);
    if (accepted)
    {
        UpdateSafetyRelease();
    }
    return accepted;
}

bool RubatoQueueDisc::Eligible(uint32_t queue, Time now, Time &wake) const
{
    if (queue == 0 || m_safetyReleaseActive || !m_policies[queue - 1].gated)
    {
        return true;
    }
    const auto &policy = m_policies[queue - 1];
    if (now >= policy.nextEligible)
    {
        return true;
    }
    wake = std::min(wake, policy.nextEligible);
    return false;
}

Ptr<QueueDiscItem> RubatoQueueDisc::DoDequeue()
{
    const uint32_t queueCount = GetNInternalQueues();
    if (queueCount == 0)
    {
        return nullptr;
    }
    Time wake = Time::Max();
    const Time now = Simulator::Now();

    // Strict priority: serve the sensitive queue whenever it is non-empty;
    // video traffic uses only residual capacity.
    if (m_strictPriority && !GetInternalQueue(0)->IsEmpty())
    {
        Ptr<QueueDiscItem> item = GetInternalQueue(0)->Dequeue();
        if (item)
        {
            ObserveQuotaDeparture(item, 0);
            return item;
        }
    }

    uint64_t visitLimit = queueCount * 2;
    for (uint64_t visited = 0; visited < visitLimit; ++visited)
    {
        // Under strict priority q0 was handled above; DWRR rotates only among
        // video queues.
        if (m_strictPriority && m_cursor == 0)
        {
            m_cursor = queueCount > 1 ? 1 : 0;
            if (queueCount == 1)
            {
                break;
            }
        }
        const uint32_t queue = m_cursor;
        Ptr<const QueueDiscItem> head = GetInternalQueue(queue)->Peek();
        if (!head)
        {
            m_deficit[queue] = 0;
            m_cursor = (m_cursor + 1) % queueCount;
            continue;
        }
        if (!Eligible(queue, now, wake))
        {
            m_cursor = (m_cursor + 1) % queueCount;
            continue;
        }

        const uint64_t quantum = queue == 0 ? (m_dynamicSensitiveQuantum > 0
                                                   ? m_dynamicSensitiveQuantum
                                                   : uint64_t(m_baseQuantum) * m_sensitiveWeight)
                                 : m_videoQuanta.empty() ? uint64_t(m_baseQuantum) * m_videoWeight
                                                         : m_videoQuanta[queue - 1];
        // Credits below one MTU accumulate over multiple rounds. Preserve the
        // legacy two-round packet order for equal weights, and extend scanning
        // only for non-empty sendable queues. If all queues are shape-blocked,
        // schedule the normal wake-up.
        if (!m_videoQuanta.empty())
        {
            visitLimit =
                std::max(visitLimit, (1 + (head->GetSize() + quantum - 1) / quantum) * queueCount);
        }
        if (m_deficit[queue] < static_cast<int64_t>(head->GetSize()))
        {
            m_deficit[queue] += quantum;
            m_cursor = (m_cursor + 1) % queueCount;
            continue;
        }

        Ptr<QueueDiscItem> item = GetInternalQueue(queue)->Dequeue();
        if (m_videoRedEnabled && queue == 1 && GetInternalQueue(queue)->IsEmpty())
        {
            m_redIdleSince = now;
        }
        m_deficit[queue] -= item->GetSize();
        if (queue > 0)
        {
            auto &policy = m_policies[queue - 1];
            if (policy.gated)
            {
                if (policy.burstBytes > 0)
                {
                    // Token bucket: refill by elapsed time up to bucket depth,
                    // then charge this packet. If tokens are insufficient, advance
                    // nextEligible to the time at which enough tokens exist.
                    const double elapsed = (now - policy.lastRefill).GetSeconds();
                    policy.tokenBytes = std::min<double>(
                        policy.burstBytes,
                        policy.tokenBytes + elapsed * policy.rate.GetBitRate() / 8.0);
                    policy.lastRefill = now;
                    policy.tokenBytes -= static_cast<double>(item->GetSize());
                    if (policy.tokenBytes < 0.0)
                    {
                        const double deficitSeconds =
                            -policy.tokenBytes * 8.0 / policy.rate.GetBitRate();
                        policy.nextEligible = now + Seconds(deficitSeconds);
                    }
                    else
                    {
                        policy.nextEligible = now;
                    }
                }
                else
                {
                    const double spacing = item->GetSize() * 8.0 / policy.rate.GetBitRate();
                    policy.nextEligible = std::max(now, policy.nextEligible) + Seconds(spacing);
                }
            }
        }
        UpdateSafetyRelease();
        ObserveQuotaDeparture(item, queue);
        return item;
    }

    if (wake != Time::Max())
    {
        ScheduleWake(wake);
    }
    return nullptr;
}

Ptr<const QueueDiscItem> RubatoQueueDisc::DoPeek()
{
    for (uint32_t offset = 0; offset < GetNInternalQueues(); ++offset)
    {
        Ptr<const QueueDiscItem> item =
            GetInternalQueue((m_cursor + offset) % GetNInternalQueues())->Peek();
        if (item)
        {
            return item;
        }
    }
    return nullptr;
}

bool RubatoQueueDisc::CheckConfig()
{
    NS_ABORT_MSG_IF(m_dynamicClassEpoch.IsStrictlyPositive() &&
                        (m_strictPriority || !m_videoQuanta.empty()),
                    "Dynamic class weighting requires equal video quanta and DWRR");
    // Legacy equal-weight scheduling requires a per-round budget of at least
    // one MTU. Otherwise large packets cannot collect enough credit before the
    // queueCount*2 scan limit, and dequeue can stall without a wake-up. Guard
    // with the 1500-byte Ethernet MTU so rounded BaseQuantum*VideoWeight never
    // falls just below a full packet.
    constexpr uint32_t MTU_GUARD = 1500;
    NS_ABORT_MSG_IF(m_videoQuanta.empty() && m_baseQuantum * m_videoWeight < MTU_GUARD,
                    "DWRR video quantum " << m_baseQuantum * m_videoWeight << " B < MTU guard "
                                          << MTU_GUARD
                                          << " B; raise BaseQuantum or lower VideoWeight");
    NS_ABORT_MSG_IF(m_baseQuantum * m_sensitiveWeight < MTU_GUARD,
                    "DWRR sensitive quantum " << m_baseQuantum * m_sensitiveWeight
                                              << " B < MTU guard " << MTU_GUARD << " B");
    if (GetNInternalQueues() == 0)
    {
        for (uint32_t i = 0; i <= VideoQueueCount(); ++i)
        {
            AddInternalQueue(CreateObjectWithAttributes<DropTailQueue<QueueDiscItem>>(
                "MaxSize", QueueSizeValue(GetMaxSize())));
        }
    }
    return GetNInternalQueues() == VideoQueueCount() + 1;
}

void RubatoQueueDisc::SetVideoQuanta(std::vector<uint32_t> quanta)
{
    NS_ABORT_MSG_IF(quanta.size() != VideoQueueCount() ||
                        std::any_of(quanta.begin(), quanta.end(), [](auto q) { return q == 0; }),
                    "Video quanta must contain a positive byte quantum for every video queue");
    m_videoQuanta = std::move(quanta);
}

void RubatoQueueDisc::SetClassQuanta(uint32_t sensitiveQuantum, std::vector<uint32_t> videoQuanta)
{
    NS_ABORT_MSG_IF(sensitiveQuantum == 0 || videoQuanta.size() != VideoQueueCount() ||
                        std::any_of(videoQuanta.begin(), videoQuanta.end(),
                                    [](uint32_t value) { return value == 0; }),
                    "Class quanta must be positive and cover every video queue");
    m_dynamicSensitiveQuantum = sensitiveQuantum;
    m_videoQuanta = std::move(videoQuanta);
}

void RubatoQueueDisc::UpdateSafetyRelease()
{
    if (!m_safetyReleaseEnabled)
    {
        return;
    }
    NS_ABORT_MSG_IF(m_safetyLowWatermark >= m_safetyHighWatermark,
                    "Safety low watermark must be below high watermark");
    const uint32_t bytes = GetCurrentSize().GetValue();
    const double fraction = static_cast<double>(bytes) / GetMaxSize().GetValue();
    const bool next =
        m_safetyReleaseActive ? fraction > m_safetyLowWatermark : fraction >= m_safetyHighWatermark;
    if (next != m_safetyReleaseActive)
    {
        m_safetyReleaseActive = next;
        m_safetyReleaseEvents.push_back({Simulator::Now().GetSeconds(), next, bytes});
        if (next)
        {
            m_wakeEvent.Cancel();
            Simulator::ScheduleNow(&QueueDisc::Run, this);
        }
    }
}

const std::vector<RubatoQueueDisc::SafetyReleaseEvent> &
RubatoQueueDisc::GetSafetyReleaseEvents() const
{
    return m_safetyReleaseEvents;
}

void RubatoQueueDisc::InitializeParams()
{
    m_cursor = 0;
    m_deficit.assign(VideoQueueCount() + 1, 0);
    if (m_policies.size() != VideoQueueCount())
    {
        m_policies.resize(VideoQueueCount());
    }
    m_lastVideoArrival.assign(m_videoFlows, Seconds(-1));
    m_recentPayload.assign(m_videoFlows, RecentPayload{});
    m_videoEpisodes.assign(m_videoFlows, VideoEpisode{});
    m_videoEpisodeHistory.assign(m_videoFlows, {});
    m_lastFlowArrival.clear();
    // SetPecnFlowBudgets() is called after queue-disc installation but before
    // QueueDisc::Initialize().  Preserve that control-plane state here.
    if (m_pecnInitialBudgetSeconds.size() != m_videoFlows)
    {
        m_pecnInitialBudgetSeconds.assign(m_videoFlows, 0.0);
    }
    if (m_pecnUsedBudgetSeconds.size() != m_videoFlows)
    {
        m_pecnUsedBudgetSeconds.assign(m_videoFlows, 0.0);
    }
    m_pecnFlowProbability.assign(m_videoFlows, 0.0);
    m_pecnFlowLevel.assign(m_videoFlows, 0);
    m_pecnSelected.assign(m_videoFlows, false);
    m_pecnSelectedRank.assign(m_videoFlows, 0);
    m_pecnEpochIndex = std::numeric_limits<uint64_t>::max();
    m_pecnActiveFlows = 0;
    m_pecnActiveVideoFlows = 0;
    m_pecnClusterPeakAgeSeconds = 0.0;
    m_pecnClusterId = 0;
    m_pecnClusterPeakTimeSeconds = 0.0;
    m_pecnClusterSize = 0;
    m_pecnEligibleClusterFlows = 0;
    m_pecnHistoricalPeakBytesForTrace = 0;
    m_pecnThresholdBytesForTrace = 0;
    m_pecnQueueLevelPercent = 0.0;
    m_pecnIntensityLevel = 0;
    m_pecnMarkProbabilityForTrace = 0.0;
    m_pecnClusterMembers.clear();
    m_pecnMarkEvents.clear();
    m_pecnDecisionEvents.clear();
    if (m_quotaPecn)
    {
        m_quotaQueryEvent = Simulator::Schedule(NanoSeconds(m_quotaPecn->GetConfig().epochNs),
                                                &RubatoQueueDisc::QueryQuotaPecn, this);
    }
    m_safetyReleaseActive = false;
    m_safetyReleaseEvents.clear();
    if (m_dynamicClassEpoch.IsStrictlyPositive())
    {
        m_dynamicSensitiveQuantum = m_baseQuantum * m_sensitiveWeight;
        m_classWeightSamples.push_back({Simulator::Now().GetSeconds(), 0, 0,
                                        m_dynamicSensitiveQuantum, m_baseQuantum * m_videoWeight});
        m_classWeightEvent =
            Simulator::Schedule(m_dynamicClassEpoch, &RubatoQueueDisc::UpdateClassWeights, this);
    }
}

void RubatoQueueDisc::UpdateClassWeights()
{
    const uint32_t count = VideoQueueCount();
    const uint64_t totalQuantum =
        uint64_t(m_baseQuantum) * (m_sensitiveWeight + uint64_t(count) * m_videoWeight);
    const uint64_t totalBytes = m_sensitiveArrivalBytes + m_videoArrivalBytes;
    if (totalBytes > 0)
    {
        // Keep total bytes per round fixed and weight video queues equally.
        // Give every queue at least one byte so new arrivals can advance. The
        // class-share error from integer quantization is at most Q/totalQuantum.
        const auto ideal =
            static_cast<long double>(totalQuantum) * m_videoArrivalBytes / totalBytes / count;
        const uint32_t videoQuantum =
            std::clamp<uint64_t>(std::llround(ideal), 1, (totalQuantum - 1) / count);
        m_videoQuanta.assign(count, videoQuantum);
        m_dynamicSensitiveQuantum = totalQuantum - uint64_t(count) * videoQuantum;
        // Preserve accumulated sub-packet credit without allowing a previous
        // large-weight budget to persist across windows.
        m_deficit[0] = std::min<int64_t>(m_deficit[0], m_dynamicSensitiveQuantum);
        for (uint32_t q = 1; q <= count; ++q)
        {
            m_deficit[q] = std::min<int64_t>(m_deficit[q], videoQuantum);
        }
    }
    m_classWeightSamples.push_back(
        {Simulator::Now().GetSeconds(), m_sensitiveArrivalBytes, m_videoArrivalBytes,
         m_dynamicSensitiveQuantum,
         m_videoQuanta.empty() ? m_baseQuantum * m_videoWeight : m_videoQuanta[0]});
    m_sensitiveArrivalBytes = m_videoArrivalBytes = 0;
    m_classWeightEvent =
        Simulator::Schedule(m_dynamicClassEpoch, &RubatoQueueDisc::UpdateClassWeights, this);
}

const std::vector<RubatoQueueDisc::ClassWeightSample> &
RubatoQueueDisc::GetClassWeightSamples() const
{
    return m_classWeightSamples;
}

void RubatoQueueDisc::DoDispose()
{
    m_quotaQueryEvent.Cancel();
    m_classWeightEvent.Cancel();
    m_wakeEvent.Cancel();
    QueueDisc::DoDispose();
}

void RubatoQueueDisc::ScheduleWake(Time when)
{
    const Time delay = std::max(NanoSeconds(1), when - Simulator::Now());
    if (!m_wakeEvent.IsPending() || Simulator::GetDelayLeft(m_wakeEvent) > delay)
    {
        m_wakeEvent.Cancel();
        m_wakeEvent = Simulator::Schedule(delay, &QueueDisc::Run, this);
    }
}

} // namespace ns3
