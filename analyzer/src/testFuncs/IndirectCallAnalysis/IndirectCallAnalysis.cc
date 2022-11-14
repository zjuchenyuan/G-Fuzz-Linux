#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/Instruction.h"
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"  
#include "llvm/IR/InstrTypes.h" 
#include "llvm/IR/BasicBlock.h" 
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include <llvm/IR/LegacyPassManager.h>
#include <map> 
#include <vector> 
#include "llvm/IR/CFG.h" 
#include "llvm/Transforms/Utils/BasicBlockUtils.h" 
#include "llvm/IR/IRBuilder.h"

#include "IndirectCallAnalysis.h"
#include "../Config.h"
#include "../Common.h"

using namespace llvm;

static int analyze_once = 0;

bool IcallAnalysisPass::doFinalization(Module *M) {

	// Update the global state here
	if(analyze_once != 0)
		return false;

	bool updateTag = updateGlobalAnalysisTarget();
	if(updateTag){
		//We need to run this pass again until update stop
		Ctx->analysis_Target_Update_Tag = true;
	}
	else{
		Ctx->analysis_Target_Update_Tag = false;
		
		//Stop analysis and update global state
		updateGlobalState();
		updateICallData();
	}

	analyze_once++;
	return false;
}


bool IcallAnalysisPass::doInitialization(Module *M) { 
	
	analyze_once = 0;
	
	return false;
}

bool IcallAnalysisPass::doModulePass(Module *M) {

	string moduleName = M->getName();

	//
	// Iterate and process globals
	//
	for (Module::global_iterator gi = M->global_begin(); 
			gi != M->global_end(); ++gi) {
		GlobalVariable* GV = &*gi;

		if(!GV->hasName())
        	continue;

		//Only focus on interesting target
   		string GV_Name = GV->getName();
		if(Ctx->Global_Target_GV_Set.count(GV_Name) == 0)
			continue;
		
		string compondName = moduleName + GV_Name;
		hash<string> str_hash;
		if(Ctx->Global_Analyzed_Global_Set.count(str_hash(compondName)) != 0)
			continue;

		findStoreToGlobal(GV);
		Ctx->Global_Analyzed_Global_Set.insert(str_hash(compondName));

	}


	for (Module::iterator f = M->begin(), fe = M->end(); 
			f != fe; ++f) {

		Function *F = &*f;

		/*if(F->getName()!="w100_pll_adjust"){
            continue;
        }*/
		if (F->isDeclaration())
			continue;

		for (auto i = inst_begin(F), e = inst_end(F); i != e; ++i) {
			Instruction *I = &*i;

			if (CallInst *CaI = dyn_cast<CallInst>(I)){
				//if(F.getName() != "asic3_mfd_probe")
				//	continue;
				Function *CF = CaI->getCalledFunction();
				if(!CF)
					continue;
				
				string CFName = CF->getName();
				if(CFName.size()==0)
					continue;
			
				unsigned argnum = CaI->getNumArgOperands();
				
				for (unsigned j = 0; j < argnum; j++) {
                	Value *Arg = CaI->getArgOperand(j);

					//Only analyze our target call
					if(Ctx->Global_Target_Call_Set.count(stringIdHash(CFName,j)) == 0)
						continue;
					
					//Prevent redundant analysis
					string FName = F->getName();
					string compondName = CFName + FName; //caller name + callee name
					if(Ctx->Global_Analyzed_Call_Set.count(stringIdHash(compondName,j)) != 0)
						continue;
					
					//Here we found our target
					//Then we analysis which function could input as a arg to this call
					findFuncArgStoredCall(CaI, Arg, j);
					Ctx->Global_Analyzed_Call_Set.insert(stringIdHash(compondName,j));
				}
			}
		}


	}

  return false;
}