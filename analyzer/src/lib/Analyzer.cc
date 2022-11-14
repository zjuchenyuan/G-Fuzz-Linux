//===-- KRace.cc - the KRace framework------------------------===//
// 
// This file implemets the KRace framework. It calls the pass for
// building call-graph and the pass for finding lacking security operation bugs.
//
//===-----------------------------------------------------------===//

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/Path.h"

#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>

#include "Analyzer.h"
#include "TypeBuilder/TypeBuilder.h"
#include "CallGraph/CallGraph.h"
#include "Config.h"
#include "PointerAnalysis/PointerAnalysis.h"
#include "AliasAnalysis/AliasAnalysis.h"
#include "PairAnalysis/PairAnalysis.h"
#include "IndirectCallAnalysis/IndirectCallAnalysis.h"
#include "DBTools.h"

#include <omp.h>

using namespace llvm;

// Command line parameters.
cl::list<std::string> InputFilenames(
    cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<unsigned> VerboseLevel(
    "verbose-level", cl::desc("Print information at which verbose level"),
    cl::init(0));

cl::opt<bool> CriticalVar(
    "krc", 
    cl::desc("Identify compiler-introduced TOCTTOU bugs"), 
    cl::NotHidden, cl::init(false));

GlobalContext GlobalCtx;


void IterativeModulePass::run(ModuleList &modules) {

	ModuleList::iterator i, e;
	OP << "[" << ID << "] Initializing " << modules.size() << " modules ";
	bool again = true;

	//Initialize
	while (again) {
		again = false;
		for (i = modules.begin(), e = modules.end(); i != e; ++i) {
			again |= doInitialization(i->first);
			OP << ".";
		}
	}
	OP << "\n";

	//Execute main analysis pass
	unsigned iter = 0, changed = 1;
	while (changed) {
		++iter;
		changed = 0;
		unsigned counter_modules = 0;
		unsigned total_modules = modules.size();

		//#pragma omp parallel for
		for (int it = 0; it < total_modules; ++it) {
			OP << "[" << ID << " / " << iter << "] ";
			OP << "[" << ++counter_modules << " / " << total_modules << "] ";
			OP << "[" << modules[it].second << "]\n";

			bool ret = doModulePass(modules[it].first);
			if (ret) {
				++changed;
				OP << "\t [CHANGED]\n";
			} else
				OP << "\n";
				
			//OP << "it: "<<it<<"Thread ID: "<< omp_get_thread_num()<<"\n";
		}
		OP << "[" << ID << "] Updated in " << changed << " modules.\n";
	}

	//Postprocessing
	OP << "[" << ID << "] Postprocessing ...\n";
	again = true;
	while (again) {
		again = false;
		for (i = modules.begin(), e = modules.end(); i != e; ++i) {
			// TODO: Dump the results.
			again |= doFinalization(i->first);
		}
	}

	OP << "[" << ID << "] Done!\n\n";
}

void LoadStaticData(GlobalContext *GCtx) {

	// Load skip functions
	SetSkipFuncs(GCtx->SkipFuncs);
	
	// Load auto freed alloc functions
	SetAutoFreedFuncs(GCtx->AutoFreedFuncs);

	// Set value escape functions
	SetEscapeFuncs(GCtx->EscapeFuncs);

	// Load member get functions
	SetMemberGetFuncs(GCtx->MemberGetFuncs);

	// Load error-handling functions
	SetErrorHandleFuncs(GCtx->ErrorHandleFuncs);

	// load functions that copy/move values
	SetCopyFuncs(GCtx->CopyFuncs);

	// load llvm debug functions
	SetDebugFuncs(GCtx->DebugFuncs);

	// load heap alloc functions
	SetHeapAllocFuncs(GCtx->HeapAllocFuncs);

	// load ignore instructions
	SetBinaryOperandInsts(GCtx->BinaryOperandInsts);

	// load ignore instructions
	SetSingleOperandInsts(GCtx->SingleOperandInsts);

	// Load test functions
	SetTestFuncs(GCtx->TestFuncs);

}

void PrintSecurityCheckResults(GlobalContext *GCtx) {

	OP<<"############## Result Statistics ##############\n";
	/*OP<<"# Number of 1 function structures: \t\t\t"<<GCtx->num_1_pairs<<"\n";
	OP<<"# Number of 2 function structures: \t\t\t"<<GCtx->num_2_pairs<<"\n";
	OP<<"# Number of 3 function structures: \t\t\t"<<GCtx->num_3_pairs<<"\n";
	OP<<"# Number of 4 function structures: \t\t\t"<<GCtx->num_4_pairs<<"\n";
	OP<<"# Number of 5 function structures: \t\t\t"<<GCtx->num_5_pairs<<"\n";
	OP<<"# Number of more function structures: \t\t\t"<<GCtx->num_more_pairs<<"\n";*/

	OP<<"# Number icall targets \t\t\t\t"<<GCtx->icallTargets<<"\n";
	OP<<"# Number valid icall targets \t\t\t"<<GCtx->valied_icallTargets<<"\n";
	OP<<"# Number icalls \t\t\t\t"<<GCtx->IndirectCallInsts.size()<<"\n";
	OP<<"# Number valid icalls \t\t\t\t"<<GCtx->valied_icallNumber<<"\n";
	OP<<"# Number dataflow analysis \t\t\t"<<GCtx->icall_support_dataflow_Number<<"\n";
	OP<<"# Number Global_GV_Func_Map \t\t\t"<<GCtx->Global_GV_Func_Map.size()<<"\n";
	OP<<"# Number Global_Arg_Func_Map \t\t\t"<<GCtx->Global_Arg_Func_Map.size()<<"\n\n";

	OP<<"############## Type Info Statistics ##############\n";
	OP<<"# Number emptyNameWithDebuginfo \t\t"<<GCtx->num_emptyNameWithDebuginfo<<"\n";
	OP<<"# Number emptyNameWithoutDebuginfo \t\t"<<GCtx->num_emptyNameWithoutDebuginfo<<"\n";
	OP<<"# Number num_haveLayerStructName \t\t"<<GCtx->num_haveLayerStructName<<"\n";
	OP<<"# Number num_local_info_name     \t\t"<<GCtx->num_local_info_name<<"\n";
	OP<<"# Number Global_EmptyTy_Funcs    \t\t"<<GCtx->Global_EmptyTy_Funcs.size()<<"\n";
	OP<<"# Number Globa_Union_Set         \t\t"<<GCtx->Globa_Union_Set.size()<<"\n";
	OP<<"# Number num_array_prelayer      \t\t"<<GCtx->num_array_prelayer<<"\n";

}


int main(int argc, char **argv) {
	// Print a stack trace if we signal out.
	sys::PrintStackTraceOnErrorSignal(argv[0]);
	PrettyStackTraceProgram X(argc, argv);

	llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.

	cl::ParseCommandLineOptions(argc, argv, "global analysis\n");
	SMDiagnostic Err;

	// Loading modules
	OP << "Total " << InputFilenames.size() << " file(s)\n";

#if _OPENMP
	OP<<"support openmp\n";
#else
	OP<<"not support openmp\n";
#endif

	//Use omp to speed up bitcode loading
	omp_lock_t lock;
	omp_init_lock(&lock);

	#pragma omp parallel for
	for (unsigned i = 0; i < InputFilenames.size(); ++i) {

		LLVMContext *LLVMCtx = new LLVMContext();
		std::unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

		if (M == NULL) {
			OP << argv[0] << ": error loading file '"
				<< InputFilenames[i] << "'\n";
			continue;
		}
		StringRef MName = StringRef(strdup(InputFilenames[i].data()));

		omp_set_lock(&lock);
		Module *Module = M.release();
		//OP<<"load module: "<<MName<<"\n";
		GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
		GlobalCtx.ModuleMaps[Module] = InputFilenames[i];
		omp_unset_lock(&lock);
	}	

	// Main workflow
	LoadStaticData(&GlobalCtx);

	// Pointer analysis
    //PointerAnalysisPass PTAPass(&GlobalCtx);
    //PTAPass.run(GlobalCtx.Modules);

	//Type builder
	//TypeBuilderPass TBPass(&GlobalCtx);
	//TBPass.run(GlobalCtx.Modules);

	// Build global callgraph.
	CallGraphPass CGPass(&GlobalCtx);
	CGPass.run(GlobalCtx.Modules);

	RecordCFG(&GlobalCtx);
	DumpFunctions(&GlobalCtx);

	/*IcallAnalysisPass ICPass(&GlobalCtx);
	ICPass.run(GlobalCtx.Modules);

	while(GlobalCtx.analysis_Target_Update_Tag){
		IcallAnalysisPass ICPass(&GlobalCtx);
		ICPass.run(GlobalCtx.Modules);
	}*/

	if(CriticalVar){
		//ICallAliasAnalysis(&GlobalCtx);
		//FuncAliasAnalysis(&GlobalCtx);
	}

	//PrintSecurityCheckResults(&GlobalCtx);
	
	//pairFuncDataRecord(&GlobalCtx);
	//messageRecord(&GlobalCtx);
	//keywordsRecord(&GlobalCtx);

	//icallTargetResult(&GlobalCtx);

	//Record info into MYSQL database
	//update_database(&GlobalCtx);

	omp_destroy_lock(&lock);
	return 0;
}

