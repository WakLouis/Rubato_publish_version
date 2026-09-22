#ifndef DBSP_SOLVER_H
#define DBSP_SOLVER_H

#include <string>
#include <vector>

namespace ns3
{

struct DbspFlowInput
{
    std::string id;
    double burstBits{0.0};
    double periodSeconds{0.0};
    double onDurationSeconds{0.0};
    double maxDelaySeconds{0.0};
    double weight{1.0};

    double AverageRateBps() const;
    double OnRateBps() const;
    double SafeMinRateBps() const;
};

struct DbspProblem
{
    double capacityBps{0.0};
    double bufferBits{0.0};
    std::vector<DbspFlowInput> flows;
};

struct DbspFlowResult
{
    std::string id;
    double baseReleaseRateBps{0.0};
    double averageRateBps{0.0};
    double onRateBps{0.0};
    double safeMinRateBps{0.0};
    double plannedBacklogBits{0.0};
    double actualDelaySeconds{0.0};
    double maxDelaySeconds{0.0};
    double delayBudgetUtilization{0.0};
};

struct DbspResult
{
    std::vector<DbspFlowResult> flows;
    double aggregateReleaseRateBps{0.0};
    double residualOverloadBps{0.0};
    double bufferUsedBits{0.0};
    double bufferUtilization{0.0};
    double firstStageObjective{0.0};
    double secondStageObjective{0.0};
    std::string solverStatus;
    std::string solverMessage;
};

class DbspSolver
{
  public:
    /** Paper Equation (3): confidence * [min(M, T/theta-d, T-d)]+. */
    static double ComputeSafeDelayBudget(double bufferMarginSeconds, double throughputHeadroom,
                                         double confidence, double periodSeconds,
                                         double onDurationSeconds);

    /** Two-stage lexicographic LP equivalent to dbsp_solver.solve_dbsp. Throws std::runtime_error
     * on failure. */
    static DbspResult Solve(const DbspProblem &problem);
};

} // namespace ns3

#endif
