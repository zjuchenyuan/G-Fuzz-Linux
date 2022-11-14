#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Dominators.h>

#include <unistd.h>
#include <thread>
#include <mutex>
#include <omp.h>

#include "PairAnalysis.h"
using namespace llvm;

//#define OP in
//#define TEST_ONE_CASE "ath10k_add_interface"
//#define CONCURRENT
#define MAX_BLOCK_NUM 500

bool PairAnalysisPass::doInitialization(Module *M) {
    return false;
}

bool PairAnalysisPass::doFinalization(Module *M) {
    return false;
}

void PairAnalysisPass::run(ModuleList &modules) {

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

	#ifdef CONCURRENT
		#pragma omp parallel for
	#endif
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

//Main function
bool PairAnalysisPass::doModulePass(Module *M) {

	set<GlobalVariable *> targetSet;
	targetSet.clear();

	ofstream in;
    in.open("PairReports.txt",ios::app);

	//Extract global var
	for (auto v = M->global_begin(); v != M->global_end(); ++v){
		GlobalVariable *V = &*v;

		//OP<<"V: "<<*V<<"\n\n";

		//The target init-fini function pairs usually are stored in global struct pointers
		Type *V_type = V->getType();

		//Global values are always pointers
		/*if(V_type->isPointerTy()) {
			PointerType * pt = dyn_cast<PointerType>(V_type);
			Type *ele_type = pt->getElementType();
			//OP<<"Type: "<<ele_type->getTypeID()<<"\n";
			if(ele_type->isStructTy()){
				//OP<< *V <<"\n";
				targetSet.insert(V);
			}
		}*/
		
		if(V->hasInitializer()){
			Constant* C = V->getInitializer();
			//OP<<"C: "<<*C<<"\n\n";
			//OP<<"C Type: "<<C->getType()->getTypeID()<<"\n";
			if(C->getType()->isStructTy()){
				//OP<<"is struct\n";
				targetSet.insert(V);
			}

			if(C->getType()->isFunctionTy()){
				//OP<<"is function\n\n";
			}

			if(C->getType()->isPointerTy()){
				//OP<<"is pointer\n\n";
			}

			if(C->getType()->isArrayTy()){
				//OP<<"is array\n\n";
			}
		}
		
	}

	StructInfoMap structInfoMap;
	structInfoMap.clear();

	for(auto it = targetSet.begin(); it != targetSet.end(); it++){

		GlobalVariable *V = *it;
		//OP << *V << "\n\n";

		Constant* C = V->getInitializer();
		ConstantStruct *CS = dyn_cast<ConstantStruct>(C);
		if(!CS){
			continue;
		}

		set<Function*> member_func_set;
		member_func_set.clear();

		int function_pointer_num = 0;
		
		unsigned opnum = C->getNumOperands();
		for(auto i = 0; i< opnum; i++){
			Value* field = CS->getOperand(i);
			
			if(field->getType()->isStructTy()){
				//OP<<"is struct\n";
				//OP<<*field<<"\n\n";
			}

			if(field->getType()->isFunctionTy()){
				//OP<<"is function\n";
				//OP<<*field<<"\n\n";
			}

			if(field->getType()->isPointerTy()){
				//OP<<"is pointer\n";
				//OP<<*field<<"\n\n";
				Function* field_F = dyn_cast<Function>(field);
				if(field_F) {
					function_pointer_num++;
					member_func_set.insert(field_F);
				}
			}

			//if(field->getType()->isFunctionTy())
			//	OP<<*field<<"\n";
		}

		structInfoMap[CS] = member_func_set;

		switch(function_pointer_num){
			case 0:
				break;
			case 1:
				Ctx->num_1_pairs++;
				break;
			case 2:
				Ctx->num_2_pairs++;
				break;
			case 3:
				Ctx->num_3_pairs++;
				break;
			case 4:
				Ctx->num_4_pairs++;
				break;
			case 5:
				Ctx->num_5_pairs++;
				break;
			default:
				Ctx->num_more_pairs++;
				break;
		}

	}

	if(!structInfoMap.empty())
		Ctx->Global_Pair_Set.insert(structInfoMap);



	//test
	checkExitFunc(M);
	//container_of_statistics(M);
	//checkStructFuncField(M);

    return false;

}

//i915_pmu_register: a good bug example
