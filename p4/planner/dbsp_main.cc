// Line-framed, versioned IPC adapter shared with the ns-3 implementation.
#include "dbsp-solver.h"
#include "dqa-allocation.h"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

int main()
{
    std::cout << std::setprecision(17);
    std::string line;
    while (std::getline(std::cin, line))
    {
        unsigned version = 0, count = 0;
        try
        {
            std::istringstream in(line);
            std::string magic;
            ns3::DbspProblem problem;
            if (!(in >> magic >> version >> count) || count == 0 || count > 4096)
                throw std::invalid_argument("invalid request header");
            if (magic == "DQA2" || magic == "QNT2")
            {
                unsigned total;
                if (!(in >> total))
                    throw std::invalid_argument("invalid allocation header");
                std::vector<ns3::DqaFlow> members;
                std::vector<double> demands;
                for (unsigned i = 0; i < count; ++i)
                {
                    unsigned id;
                    double demand;
                    if (!(in >> id >> demand))
                        throw std::invalid_argument("invalid allocation member");
                    members.push_back({id, "", demand});
                    demands.push_back(demand);
                }
                std::string extra;
                if (in >> extra)
                    throw std::invalid_argument("trailing allocation input");
                std::map<uint32_t, uint32_t> allocation;
                if (magic == "DQA2")
                {
                    allocation = ns3::AllocateDqaQueues(members, total);
                    for (auto &item : allocation)
                        ++item.second; // physical q0 is sensitive
                }
                else
                {
                    const auto weights = ns3::AllocateDqaQuanta(demands, total);
                    for (unsigned i = 0; i < count; ++i)
                        allocation[members[i].id] = weights[i];
                }
                std::cout << "{\"schema\":\"" << magic << "\",\"version\":" << version
                          << ",\"status\":\"optimal\",\"allocation\":[";
                bool first = true;
                for (const auto &item : allocation)
                {
                    if (!first)
                        std::cout << ',';
                    first = false;
                    std::cout << '[' << item.first << ',' << item.second << ']';
                }
                std::cout << "]}" << std::endl;
                continue;
            }
            if (magic != "DBSP2" || !(in >> problem.capacityBps >> problem.bufferBits))
                throw std::invalid_argument("invalid DBSP header");
            for (unsigned i = 0; i < count; ++i)
            {
                ns3::DbspFlowInput flow;
                if (!(in >> flow.id >> flow.burstBits >> flow.periodSeconds >>
                      flow.onDurationSeconds >> flow.maxDelaySeconds >> flow.weight) ||
                    !std::isfinite(flow.maxDelaySeconds) || flow.maxDelaySeconds < 0)
                    throw std::invalid_argument("invalid flow input");
                // Python has conservatively derived the remaining delay budget.
                // Never recompute it from the physical envelope ON or subtract used twice.
                problem.flows.push_back(flow);
            }
            std::string extra;
            if (in >> extra)
                throw std::invalid_argument("trailing input");
            const auto result = ns3::DbspSolver::Solve(problem);
            std::cout << "{\"schema\":\"DBSP2\",\"version\":" << version
                      << ",\"status\":\"optimal\",\"overload_bps\":" << result.residualOverloadBps
                      << ",\"buffer_bits\":" << result.bufferUsedBits
                      << ",\"first_objective\":" << result.firstStageObjective
                      << ",\"second_objective\":" << result.secondStageObjective << ",\"flows\":[";
            bool first = true;
            for (const auto &f : result.flows)
            {
                if (!first)
                    std::cout << ',';
                first = false;
                // IDs are generated integers by the Python adapter, never user strings.
                std::cout << "{\"id\":" << std::stoul(f.id)
                          << ",\"rate_bps\":" << f.baseReleaseRateBps
                          << ",\"backlog_bits\":" << f.plannedBacklogBits
                          << ",\"delay_s\":" << f.actualDelaySeconds
                          << ",\"budget_s\":" << f.maxDelaySeconds << '}';
            }
            std::cout << "]}" << std::endl;
        }
        catch (const std::exception &error)
        {
            std::cerr << "DBSP: " << error.what() << std::endl;
            std::cout << "{\"schema\":\"DBSP2\",\"version\":" << version << ",\"status\":\"error\"}"
                      << std::endl;
        }
    }
}
