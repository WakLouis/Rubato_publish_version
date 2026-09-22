#include "dbsp-solver.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ns3
{
namespace
{

constexpr double RATE_SCALE = 1'000'000.0;
constexpr double LP_EPS = 1e-9;

/** Two-phase simplex: maximize c*x subject to A*x <= b and x >= 0. */
class LinearProgram
{
  public:
    LinearProgram(const std::vector<std::vector<double>> &a, const std::vector<double> &b,
                  const std::vector<double> &c)
        : m_rows(b.size()), m_columns(c.size()), m_basic(m_rows), m_nonBasic(m_columns + 1),
          m_tableau(m_rows + 2, std::vector<double>(m_columns + 2, 0.0))
    {
        for (std::size_t row = 0; row < m_rows; ++row)
        {
            for (std::size_t column = 0; column < m_columns; ++column)
            {
                m_tableau[row][column] = a[row][column];
            }
            m_basic[row] = static_cast<int>(m_columns + row);
            m_tableau[row][m_columns] = -1.0;
            m_tableau[row][m_columns + 1] = b[row];
        }
        for (std::size_t column = 0; column < m_columns; ++column)
        {
            m_nonBasic[column] = static_cast<int>(column);
            m_tableau[m_rows][column] = -c[column];
        }
        m_nonBasic[m_columns] = -1;
        m_tableau[m_rows + 1][m_columns] = 1.0;
    }

    double Solve(std::vector<double> &solution)
    {
        std::size_t pivotRow = 0;
        for (std::size_t row = 1; row < m_rows; ++row)
        {
            if (m_tableau[row][m_columns + 1] < m_tableau[pivotRow][m_columns + 1])
            {
                pivotRow = row;
            }
        }
        if (m_tableau[pivotRow][m_columns + 1] < -LP_EPS)
        {
            Pivot(pivotRow, m_columns);
            if (!RunPhase(1) || m_tableau[m_rows + 1][m_columns + 1] < -LP_EPS)
            {
                throw std::runtime_error("DBSP linear program is infeasible");
            }
            if (std::abs(m_tableau[m_rows + 1][m_columns + 1]) > LP_EPS)
            {
                throw std::runtime_error("DBSP phase-I feasibility residual is non-zero");
            }
            for (std::size_t row = 0; row < m_rows; ++row)
            {
                if (m_basic[row] != -1)
                {
                    continue;
                }
                std::size_t column = 0;
                for (std::size_t candidate = 1; candidate <= m_columns; ++candidate)
                {
                    if (m_tableau[row][candidate] < m_tableau[row][column] - LP_EPS ||
                        (std::abs(m_tableau[row][candidate] - m_tableau[row][column]) <= LP_EPS &&
                         m_nonBasic[candidate] < m_nonBasic[column]))
                    {
                        column = candidate;
                    }
                }
                Pivot(row, column);
            }
        }
        if (!RunPhase(2))
        {
            throw std::runtime_error("DBSP linear program is unbounded");
        }
        solution.assign(m_columns, 0.0);
        for (std::size_t row = 0; row < m_rows; ++row)
        {
            if (m_basic[row] >= 0 && static_cast<std::size_t>(m_basic[row]) < m_columns)
            {
                solution[m_basic[row]] = m_tableau[row][m_columns + 1];
            }
        }
        return m_tableau[m_rows][m_columns + 1];
    }

  private:
    void Pivot(std::size_t row, std::size_t column)
    {
        const double inverse = 1.0 / m_tableau[row][column];
        for (std::size_t otherRow = 0; otherRow < m_rows + 2; ++otherRow)
        {
            if (otherRow == row)
            {
                continue;
            }
            for (std::size_t otherColumn = 0; otherColumn < m_columns + 2; ++otherColumn)
            {
                if (otherColumn != column)
                {
                    m_tableau[otherRow][otherColumn] -=
                        m_tableau[row][otherColumn] * m_tableau[otherRow][column] * inverse;
                }
            }
        }
        for (std::size_t otherColumn = 0; otherColumn < m_columns + 2; ++otherColumn)
        {
            if (otherColumn != column)
            {
                m_tableau[row][otherColumn] *= inverse;
            }
        }
        for (std::size_t otherRow = 0; otherRow < m_rows + 2; ++otherRow)
        {
            if (otherRow != row)
            {
                m_tableau[otherRow][column] *= -inverse;
            }
        }
        m_tableau[row][column] = inverse;
        std::swap(m_basic[row], m_nonBasic[column]);
    }

    bool RunPhase(int phase)
    {
        const std::size_t objectiveRow = phase == 1 ? m_rows + 1 : m_rows;
        while (true)
        {
            std::size_t column = m_columns + 1;
            for (std::size_t candidate = 0; candidate <= m_columns; ++candidate)
            {
                if (phase == 2 && m_nonBasic[candidate] == -1)
                {
                    continue;
                }
                if (column == m_columns + 1 ||
                    m_tableau[objectiveRow][candidate] < m_tableau[objectiveRow][column] - LP_EPS ||
                    (std::abs(m_tableau[objectiveRow][candidate] -
                              m_tableau[objectiveRow][column]) <= LP_EPS &&
                     m_nonBasic[candidate] < m_nonBasic[column]))
                {
                    column = candidate;
                }
            }
            if (column == m_columns + 1)
            {
                return true;
            }
            if (m_tableau[objectiveRow][column] >= -LP_EPS)
            {
                return true;
            }
            std::size_t row = m_rows;
            for (std::size_t candidate = 0; candidate < m_rows; ++candidate)
            {
                if (m_tableau[candidate][column] <= LP_EPS)
                {
                    continue;
                }
                if (row == m_rows)
                {
                    row = candidate;
                    continue;
                }
                const double ratio =
                    m_tableau[candidate][m_columns + 1] / m_tableau[candidate][column];
                const double best = m_tableau[row][m_columns + 1] / m_tableau[row][column];
                if (ratio < best - LP_EPS ||
                    (std::abs(ratio - best) <= LP_EPS && m_basic[candidate] < m_basic[row]))
                {
                    row = candidate;
                }
            }
            if (row == m_rows)
            {
                return false;
            }
            Pivot(row, column);
        }
    }

    std::size_t m_rows;
    std::size_t m_columns;
    std::vector<int> m_basic;
    std::vector<int> m_nonBasic;
    std::vector<std::vector<double>> m_tableau;
};

void Validate(const DbspProblem &problem)
{
    if (!std::isfinite(problem.capacityBps) || problem.capacityBps < 0.0 ||
        !std::isfinite(problem.bufferBits) || problem.bufferBits < 0.0 || problem.flows.empty())
    {
        throw std::invalid_argument("invalid DBSP capacity, buffer, or empty flow set");
    }
    std::unordered_set<std::string_view> ids;
    ids.reserve(problem.flows.size());
    for (const auto &flow : problem.flows)
    {
        if (flow.id.empty() || !std::isfinite(flow.burstBits) || flow.burstBits <= 0.0 ||
            !std::isfinite(flow.periodSeconds) || flow.periodSeconds <= 0.0 ||
            !std::isfinite(flow.onDurationSeconds) || flow.onDurationSeconds <= 0.0 ||
            flow.onDurationSeconds > flow.periodSeconds || !std::isfinite(flow.maxDelaySeconds) ||
            flow.maxDelaySeconds < 0.0 || !std::isfinite(flow.weight) || flow.weight < 0.0)
        {
            throw std::invalid_argument("invalid DBSP flow input: " + flow.id);
        }
        if (!ids.insert(flow.id).second)
        {
            throw std::invalid_argument("duplicate DBSP flow id: " + flow.id);
        }
    }
}

struct FlowSignature
{
    double burstBits;
    double periodSeconds;
    double onDurationSeconds;
    double maxDelaySeconds;
    double weight;

    bool operator==(const FlowSignature &other) const
    {
        return burstBits == other.burstBits && periodSeconds == other.periodSeconds &&
               onDurationSeconds == other.onDurationSeconds &&
               maxDelaySeconds == other.maxDelaySeconds && weight == other.weight;
    }
};

struct FlowSignatureHash
{
    std::size_t operator()(const FlowSignature &signature) const
    {
        std::size_t result = 0;
        const auto combine = [&](double value)
        {
            const auto hashed = std::hash<double>{}(value);
            result ^= hashed + 0x9e3779b9 + (result << 6) + (result >> 2);
        };
        combine(signature.burstBits);
        combine(signature.periodSeconds);
        combine(signature.onDurationSeconds);
        combine(signature.maxDelaySeconds);
        combine(signature.weight);
        return result;
    }
};

struct FlowGroup
{
    std::size_t representative;
    std::size_t count;
};

std::vector<FlowGroup> BuildGroups(const DbspProblem &problem,
                                   std::vector<std::size_t> &flowToGroup)
{
    std::unordered_map<FlowSignature, std::size_t, FlowSignatureHash> groupBySignature;
    groupBySignature.reserve(problem.flows.size());
    std::vector<FlowGroup> groups;
    flowToGroup.resize(problem.flows.size());
    for (std::size_t index = 0; index < problem.flows.size(); ++index)
    {
        const auto &flow = problem.flows[index];
        const FlowSignature signature{flow.burstBits, flow.periodSeconds, flow.onDurationSeconds,
                                      flow.maxDelaySeconds, flow.weight};
        const auto [position, inserted] = groupBySignature.emplace(signature, groups.size());
        if (inserted)
        {
            groups.push_back({index, 1});
        }
        else
        {
            ++groups[position->second].count;
        }
        flowToGroup[index] = position->second;
    }
    return groups;
}

std::vector<double> SolveStage(const DbspProblem &problem, const std::vector<FlowGroup> &groups,
                               const std::vector<double> &lowerMbps,
                               const std::vector<double> &upperMbps,
                               const std::vector<double> &objective, double capacityMbps,
                               bool includeSlack, double *slackMbps)
{
    const std::size_t count = groups.size();
    const std::size_t variables = count + (includeSlack ? 1 : 0);
    std::vector<std::vector<double>> constraints;
    std::vector<double> limits;

    std::vector<double> capacityRow(variables, 0.0);
    for (std::size_t index = 0; index < count; ++index)
    {
        capacityRow[index] = static_cast<double>(groups[index].count);
    }
    if (includeSlack)
    {
        capacityRow[count] = -1.0;
    }
    constraints.push_back(capacityRow);
    double rateAtLowerMbps = 0.0;
    for (std::size_t index = 0; index < count; ++index)
    {
        rateAtLowerMbps += groups[index].count * lowerMbps[index];
    }
    limits.push_back(capacityMbps - rateAtLowerMbps);

    std::vector<double> bufferRow(variables, 0.0);
    double bufferedAtLowerMbit = 0.0;
    for (std::size_t index = 0; index < count; ++index)
    {
        const auto &group = groups[index];
        const auto &flow = problem.flows[group.representative];
        bufferRow[index] = -static_cast<double>(group.count) * flow.onDurationSeconds;
        bufferedAtLowerMbit +=
            group.count * (flow.burstBits / RATE_SCALE - flow.onDurationSeconds * lowerMbps[index]);
    }
    constraints.push_back(bufferRow);
    limits.push_back(problem.bufferBits / RATE_SCALE - bufferedAtLowerMbit);

    for (std::size_t index = 0; index < count; ++index)
    {
        std::vector<double> bound(variables, 0.0);
        bound[index] = 1.0;
        constraints.push_back(std::move(bound));
        limits.push_back(upperMbps[index] - lowerMbps[index]);
    }

    std::vector<double> maximize(variables, 0.0);
    for (std::size_t index = 0; index < count; ++index)
    {
        maximize[index] = -objective[index];
    }
    if (includeSlack)
    {
        maximize[count] = -1.0;
    }

    std::vector<double> shifted;
    LinearProgram(constraints, limits, maximize).Solve(shifted);
    std::vector<double> rates(count, 0.0);
    for (std::size_t index = 0; index < count; ++index)
    {
        rates[index] =
            std::clamp(lowerMbps[index] + shifted[index], lowerMbps[index], upperMbps[index]);
    }
    if (slackMbps)
    {
        *slackMbps = includeSlack ? std::max(0.0, shifted[count]) : 0.0;
    }
    return rates;
}

} // namespace

double DbspFlowInput::AverageRateBps() const { return burstBits / periodSeconds; }

double DbspFlowInput::OnRateBps() const { return burstBits / onDurationSeconds; }

double DbspFlowInput::SafeMinRateBps() const
{
    return std::max(AverageRateBps(), burstBits / (onDurationSeconds + maxDelaySeconds));
}

double DbspSolver::ComputeSafeDelayBudget(double bufferMarginSeconds, double throughputHeadroom,
                                          double confidence, double periodSeconds,
                                          double onDurationSeconds)
{
    if (!std::isfinite(bufferMarginSeconds) || bufferMarginSeconds < 0.0 ||
        !std::isfinite(throughputHeadroom) || throughputHeadroom < 1.0 ||
        !std::isfinite(confidence) || confidence < 0.0 || confidence > 1.0 ||
        !std::isfinite(periodSeconds) || periodSeconds <= 0.0 ||
        !std::isfinite(onDurationSeconds) || onDurationSeconds <= 0.0 ||
        onDurationSeconds > periodSeconds)
    {
        throw std::invalid_argument("invalid DBSP safe-delay budget input");
    }
    return confidence *
           std::max(0.0, std::min({bufferMarginSeconds,
                                   periodSeconds / throughputHeadroom - onDurationSeconds,
                                   periodSeconds - onDurationSeconds}));
}

DbspResult DbspSolver::Solve(const DbspProblem &problem)
{
    Validate(problem);
    const std::size_t count = problem.flows.size();
    std::vector<double> lowerMbps(count);
    std::vector<double> upperMbps(count);
    std::vector<double> secondObjective(count, 0.0);
    for (std::size_t index = 0; index < count; ++index)
    {
        lowerMbps[index] = problem.flows[index].SafeMinRateBps() / RATE_SCALE;
        upperMbps[index] = problem.flows[index].OnRateBps() / RATE_SCALE;
        secondObjective[index] =
            problem.flows[index].weight * problem.flows[index].AverageRateBps() / RATE_SCALE;
    }

    // Every objective is nondecreasing in each rate (weights are nonnegative).
    // Feasible componentwise lower bounds attain both lexicographic optima,
    // including when capacity requires positive slack.
    double backlogAtLower = 0.0;
    for (const auto &flow : problem.flows)
    {
        backlogAtLower +=
            std::max(0.0, flow.burstBits - flow.onDurationSeconds * flow.SafeMinRateBps());
    }
    const bool useLowerBounds = backlogAtLower <= problem.bufferBits;
    std::vector<double> ratesMbps = lowerMbps;
    double firstSlackMbps = std::max(0.0, std::accumulate(lowerMbps.begin(), lowerMbps.end(), 0.0) -
                                              problem.capacityBps / RATE_SCALE);
    if (!useLowerBounds)
    {
        std::vector<std::size_t> flowToGroup;
        const auto groups = BuildGroups(problem, flowToGroup);
        std::vector<double> groupLowerMbps(groups.size());
        std::vector<double> groupUpperMbps(groups.size());
        std::vector<double> groupZeroObjective(groups.size(), 0.0);
        std::vector<double> groupSecondObjective(groups.size());
        for (std::size_t index = 0; index < groups.size(); ++index)
        {
            const auto &group = groups[index];
            groupLowerMbps[index] = lowerMbps[group.representative];
            groupUpperMbps[index] = upperMbps[group.representative];
            groupSecondObjective[index] = group.count * secondObjective[group.representative];
        }

        std::vector<double> firstGroupRatesMbps;
        try
        {
            firstGroupRatesMbps =
                SolveStage(problem, groups, groupLowerMbps, groupUpperMbps, groupZeroObjective,
                           problem.capacityBps / RATE_SCALE, true, &firstSlackMbps);
        }
        catch (const std::exception &error)
        {
            throw std::runtime_error(std::string("DBSP first-stage solve failed: ") + error.what());
        }
        double firstAggregateRateMbps = 0.0;
        for (std::size_t index = 0; index < groups.size(); ++index)
        {
            firstAggregateRateMbps += groups[index].count * firstGroupRatesMbps[index];
        }
        firstSlackMbps =
            std::max(firstSlackMbps, firstAggregateRateMbps - problem.capacityBps / RATE_SCALE);
        // The second stage fixes the first-stage optimum as a capacity bound.  The
        // simplex tableau is expressed in Mbps, so reusing a 1e-9 relative slack
        // can make a numerically identical optimum appear infeasible after the
        // first-stage pivot (especially for the high-overload VBR chunk).  This is
        // a feasibility tolerance only; it does not relax any flow or buffer bound.
        const double slackTolerance = std::max(1e-6, std::abs(firstSlackMbps) * 1e-6);
        try
        {
            const auto groupRatesMbps = SolveStage(
                problem, groups, groupLowerMbps, groupUpperMbps, groupSecondObjective,
                problem.capacityBps / RATE_SCALE + firstSlackMbps + slackTolerance, false, nullptr);
            for (std::size_t index = 0; index < count; ++index)
            {
                ratesMbps[index] = groupRatesMbps[flowToGroup[index]];
            }
        }
        catch (const std::exception &error)
        {
            throw std::runtime_error(std::string("DBSP second-stage solve failed: ") +
                                     error.what());
        }
    }

    DbspResult result;
    result.solverStatus = "optimal";
    result.solverMessage =
        useLowerBounds ? "C++ exact lower-bound solution" : "C++ two-stage simplex completed";
    result.flows.reserve(count);
    result.firstStageObjective = firstSlackMbps * RATE_SCALE;
    for (std::size_t index = 0; index < count; ++index)
    {
        const auto &input = problem.flows[index];
        const double rate = ratesMbps[index] * RATE_SCALE;
        // The simplex tableau is solved in Mbps.  Use the same scale-aware
        // feasibility tolerance as the benchmark validator when converting
        // back to bit/s; a fixed 1e-6 bit/s check rejects harmless roundoff.
        const double rateToleranceBps = std::max(1e-6, input.OnRateBps() * 1e-9);
        if (rate < input.SafeMinRateBps() - rateToleranceBps ||
            rate > input.OnRateBps() + rateToleranceBps)
        {
            throw std::runtime_error("DBSP solution violates rate bounds for " + input.id);
        }
        const double backlog = std::max(0.0, input.burstBits - input.onDurationSeconds * rate);
        const double delay = std::max(0.0, input.burstBits / rate - input.onDurationSeconds);
        result.flows.push_back({input.id, rate, input.AverageRateBps(), input.OnRateBps(),
                                input.SafeMinRateBps(), backlog, delay, input.maxDelaySeconds,
                                input.maxDelaySeconds > 0.0 ? delay / input.maxDelaySeconds : 0.0});
        result.aggregateReleaseRateBps += rate;
        result.bufferUsedBits += backlog;
        result.secondStageObjective +=
            input.weight * input.AverageRateBps() * (rate - input.AverageRateBps());
    }
    result.residualOverloadBps =
        std::max(0.0, result.aggregateReleaseRateBps - problem.capacityBps);
    result.bufferUtilization =
        problem.bufferBits > 0.0 ? result.bufferUsedBits / problem.bufferBits : 0.0;
    const double bufferTolerance = std::max(1.0, problem.bufferBits * 1e-7);
    if (result.bufferUsedBits > problem.bufferBits + bufferTolerance)
    {
        throw std::runtime_error("DBSP solution violates the buffer constraint: used=" +
                                 std::to_string(result.bufferUsedBits) +
                                 " bits, limit=" + std::to_string(problem.bufferBits) +
                                 " bits, tolerance=" + std::to_string(bufferTolerance) + " bits");
    }
    return result;
}

} // namespace ns3
