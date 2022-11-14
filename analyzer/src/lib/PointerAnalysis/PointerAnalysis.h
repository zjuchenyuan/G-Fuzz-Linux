#ifndef POINTER_ANALYSIS_H
#define POINTER_ANALYSIS_H

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
#include "llvm/IR/IRBuilder.h"

#include "../Analyzer.h"

class PointerAnalysisPass : public IterativeModulePass {

	typedef struct AliasNode {

		set<Value*> aliasclass;

		AliasNode(){
			aliasclass.clear();
		}

		int count(Value* V){
			return aliasclass.count(V);
		}

		void insert(Value* V){
			aliasclass.insert(V);
		}

		bool empty(){
			return aliasclass.empty();
		}

		void erase(Value* V){
			if(aliasclass.count(V) == 0)
				return;
			
			aliasclass.erase(V);
		}

		void print_set(){
			for(auto it = aliasclass.begin(); it != aliasclass.end(); it++){
				Value *v = *it;
				OP<<*v<<"\n";
			}
		}

	} AliasNode;


	typedef struct AliasEdge {
		
		AliasNode *fromNode;
		AliasNode *toNode;
		int type;

		AliasEdge(){
			fromNode = NULL;
			toNode = NULL;
			type = -1;
		}
		
	} AliasEdge;

	static vector<AliasNode*> NodeVector;
	static vector<AliasEdge*> EdgeVector;
	

	private:

	void PathAliasAnalysis(vector<BasicBlock*> path);

	//InstHandler
	void HandleInst(Instruction* I);

	void HandleLoad(LoadInst* LI);
	void HandleStore(StoreInst* STI);
	void HandleGEP(GetElementPtrInst* GEP);
	void HandleGEP(GEPOperator* GEP);
	void HandleAlloc(AllocaInst* ALI);
	void HandleMove(Value* v1, Value* v2);

	//Tools
	int getEdgeType(Value* V);
	AliasNode* getNode(Value *V);
	AliasNode* findEdge(AliasNode* fromNode, int type);
	void showResults();
	bool isAlias(Value* v1, Value* v2);
	

	public:
	PointerAnalysisPass(GlobalContext *Ctx_)
		: IterativeModulePass(Ctx_, "PointerAnalysis") { }
	virtual bool doInitialization(llvm::Module *);
	virtual bool doFinalization(llvm::Module *);
	virtual bool doModulePass(llvm::Module *);
};

#endif
