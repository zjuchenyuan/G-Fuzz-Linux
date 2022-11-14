set (AnalyzerSourceCodes
  Common.h
  Common.cc
	Analyzer.h
	Analyzer.cc

	CallGraph/CallGraph.h
  CallGraph/CallGraph.cc
  Tools.h
  Tools.cc


)

#file(COPY configs/ DESTINATION configs)

# Build libraries.
add_library (AnalyzerObj OBJECT ${AnalyzerSourceCodes})
#add_library (Analyzer SHARED $<TARGET_OBJECTS:AnalyzerObj>)
add_library (AnalyzerStatic STATIC $<TARGET_OBJECTS:AnalyzerObj>)

# Build executable analyzer.
set (EXECUTABLE_OUTPUT_PATH ${UNISAN_BINARY_DIR})
link_directories (${UNISAN_BINARY_DIR}/lib)
add_executable(analyzer ${AnalyzerSourceCodes})
target_link_libraries(analyzer
  LLVMAsmParser 
  LLVMSupport 
  LLVMCore 
  LLVMAnalysis
  LLVMIRReader
  AnalyzerStatic
  mysqlclient
  )

FIND_PACKAGE(OpenMP)
IF(OPENMP_FOUND)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
ENDIF()