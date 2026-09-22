build_lib(
    LIBNAME rubato
    SOURCE_FILES
        model/dbsp-solver.cc
        model/rubato-queue-disc.cc
    HEADER_FILES
        model/dbsp-solver.h
        model/dqa-allocation.h
        model/pecn-quota.h
        model/rubato-queue-disc.h
    LIBRARIES_TO_LINK
        ${libcore}
        ${libnetwork}
        ${libinternet}
        ${libtraffic-control}
)

