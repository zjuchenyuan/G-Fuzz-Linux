#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>

#include "PointerAnalysis.h"

using namespace llvm;

vector<PointerAnalysisPass::AliasNode*> PointerAnalysisPass::NodeVector;
vector<PointerAnalysisPass::AliasEdge*> PointerAnalysisPass::EdgeVector;

bool PointerAnalysisPass::doInitialization(Module *M) {
	return false;
}

bool PointerAnalysisPass::doFinalization(Module *M) {
	return false;
}


void PointerAnalysisPass::PathAliasAnalysis(vector<BasicBlock*> path){
	
	if(path.empty())
		return;
	
	for(auto it = path.begin(); it != path.end(); it++){
		BasicBlock* bb = *it;
		for(BasicBlock::iterator j = bb->begin(); j != bb->end(); j++){
			Instruction* inst = dyn_cast<Instruction>(j);
			if(!inst)
				continue;
			
			HandleInst(inst);
		}
	}
}

bool PointerAnalysisPass::doModulePass(Module *M) {

	for (Module::iterator f = M->begin(), fe = M->end(); f != fe; ++f) {
		Function *F = &*f;

		if (F->empty())
			continue;

		//Path collection
		vector<BasicBlock*> path;
		for (Function::iterator b = F->begin(), e = F->end(); b != e; ++b) {
			BasicBlock *BB = &*b;
			path.push_back(BB);
		}

		PathAliasAnalysis(path);
		showResults();

		NodeVector.clear();
		EdgeVector.clear();
	}

	return false;
}
