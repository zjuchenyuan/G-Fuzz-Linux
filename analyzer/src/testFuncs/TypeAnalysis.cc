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
#include <stdlib.h>
#include <assert.h>
#include "llvm/IR/CFG.h" 
#include "llvm/Transforms/Utils/BasicBlockUtils.h" 
#include "llvm/IR/IRBuilder.h"

#include "CallGraph.h"
#include "../Config.h"
#include "../Common.h"

//#define PRINT_LAYER_SET

//Given the previous layer result of type analysis, current type info,
//Output the next layer result of type analysis into FS
void CallGraphPass::findCalleesWithTwoLayerTA(CallInst *CI, FuncSet PreLayerResult, Type *LayerTy, 
	int FieldIdx, FuncSet &FS, int &LayerNo, int &escape){

	FS.clear();
	escape = 0;
	// Step 1: ensure the type hasn't escaped
	if ((typeEscapeSet.find(typeHash(LayerTy)) != typeEscapeSet.end()) || 
			(typeEscapeSet.find(typeIdxHash(LayerTy, FieldIdx)) !=
			 typeEscapeSet.end())) {
		//OP<<"type escape\n";
		escape = 1;
		return;
	}

	LayerNo++;
	//OP<<"LayerTy: "<<*LayerTy<<"\n";
	//OP<<"FieldIdx: "<<FieldIdx<<"\n";
	//if(LayerTy->isPointerTy())
	//	OP<<"is pointer\n";
	//OP<<"Only Typehash: "<<typeHash(LayerTy)<<"\n";
	//OP<<"Type&offset hash: "<<typeIdxHash(LayerTy, FieldIdx)<<"\n";
	
	FuncSet merge_set, nextLayerResult, FST;
	merge_set.clear();
	
	// Step 2: get the funcset based on current layer and merge
	nextLayerResult.clear();
	nextLayerResult = typeFuncsMap[typeIdxHash(LayerTy, FieldIdx)]; //direct result
	//OP<<"size: "<<nextLayerResult.size()<<"\n";

	if(LayerTy->isStructTy()){

		/*if(LayerTy->getStructName().size() == 0){
			if(Ctx->Global_Literal_Struct_Map.count(typeHash(LayerTy))){
				OP<<"empty struct name but have debug info\n";
			}
			else{
				OP<<"empty struct name \n";
			}
		}*/

		//findEqualTypes(LayerTy, FieldIdx, nextLayerResult);
		if(LayerTy->getStructName().size() != 0){
			string Ty_name = LayerTy->getStructName();

			funcSetMerge(nextLayerResult, typeFuncsMap[typeNameIdxHash(Ty_name, FieldIdx)]);
		}
		else{
			// In all known cases, this case never happen,
			// which means all per-layer struct types here must have struct names
		}
	}
	else{
		// This case also never happen
	}
	
	/*if(nextLayerResult.empty()){
        //OP<<"?\n";
		if(StructType * st = dyn_cast<StructType>(LayerTy)){
			nextLayerResult = typeFuncsMap[typeNameIdxHash(LayerTy, FieldIdx)];
            //escape = 1;
		}
	}*/
	
	//nextLayerResult = newtypeFuncsMap[LayerTy][FieldIdx];
	/*for(size_t th : equalTypeMap[TH]){
		Type* equalty = hashTypeMap[th];
		size_t equalidty = typeIdxHash(equalty,FieldIdx);
		if(typeFuncsMap.count(equalidty))
			funcSetMerge(nextLayerResult, typeFuncsMap[equalidty]);
	}*/

	funcSetMerge(merge_set, nextLayerResult);
	
	// Step 3: get transitted funcsets and merge
	// NOTE: this nested loop can be slow
	size_t TH = typeHash(LayerTy);
	list<size_t> LT;
	LT.push_back(TH);
	while (!LT.empty()) {
		size_t CT = LT.front();
		LT.pop_front();

		//OP<<"typeTransitMap size: "<<typeTransitMap[CT].size()<<"\n";

		for (auto H : typeTransitMap[CT]) {

			nextLayerResult = typeFuncsMap[hashIdxHash(H, FieldIdx)];
			Type* Hty = hashTypeMap[H];
			//OP<<"Hty: "<<*Hty<<"\n";
			if(Hty && Hty->isStructTy()){
				findEqualTypes(Hty, FieldIdx, nextLayerResult);
				if(Hty->getStructName().size() == 0){
					//OP<<"\nliteral struct: "<<*Hty<<"\n";
					//sleep(10);
					// exit(100);
					//OP<<"Func: "<<F->getName()<<"\n";
					//OP<<"Module: "<<SI->getFunction()->getParent()->getName()<<"\n";
					//OP<<"PO: "<<*PO<<"\n";
				}
			}
			//if(FS2.empty()){
			//	FS2 = typeFuncsMap[typeNameIdxHash(H, FieldIdx)];
			//}
			//FST.clear();
			//funcSetIntersection(FS1, FS2, FST);
			funcSetMerge(merge_set, nextLayerResult);
			//if (FST.size() != 0)
			//	FS1 = FST;	
		}
	}

	size_t TDH = typeIdxHash(LayerTy,FieldIdx);
	LT.push_back(TDH);
	while (!LT.empty()) {
		size_t CT = LT.front();
		LT.pop_front();

		//OP<<"typeTransitMap size: "<<typeTransitMap[CT].size()<<"\n";

		for (auto H : typeTransitMap[CT]) {

			nextLayerResult = typeFuncsMap[H];
			/*Type* Hty = hashTypeMap[H];
			//OP<<"Hty: "<<*Hty<<"\n";
			if(Hty && Hty->isStructTy()){
				findEqualTypes(Hty, FieldIdx, nextLayerResult);
			}*/
			//funcSetMerge(merge_set, nextLayerResult);

			if(hashIDTypeMap.count(H) == 0)
				continue;

			auto Hidty = hashIDTypeMap[H];
			if(Hidty.first->isStructTy()){
				findEqualTypes(Hidty.first, Hidty.second, nextLayerResult);
			}
			funcSetMerge(merge_set, nextLayerResult);
		}
	}


	FST.clear();

#ifdef PRINT_LAYER_SET
	OP<<"PreLayerResult: \n";
	for(auto it = PreLayerResult.begin(); it!=PreLayerResult.end();it++){
		Function* f= *it;
		OP<<"f: "<<f->getName()<<"\n";
	}

	OP<<"merge_set: \n";
	for(auto it = merge_set.begin(); it!=merge_set.end();it++){
		Function* f= *it;
		OP<<"f: "<<f->getName()<<"\n";
	}
#endif

	funcSetIntersection(PreLayerResult, merge_set, FST);

	//Add the lost type func
	funcSetMerge(FST, Ctx->Global_EmptyTy_Funcs[callHash(CI)]);

	if(!FST.empty()){
		FS = FST;
	}
	//Update FS1
	//if(FST.empty())
	//	exit(100);

}


//It seems that the function parameter info is not considered?
bool CallGraphPass::findCalleesWithMLTA(CallInst *CI, FuncSet &FS) {

	// Initial set: first-layer results (only function type match)
	FuncSet FS1 = Ctx->sigFuncsMap[callHash(CI)];
	//OP<<"func type hash: "<<callHash(CI)<<"\n";
	if (FS1.size() == 0) {
		//OP<<"first layer empty\n";
		// No need to go through MLTA if the first layer is empty
		// There will be no icall targets in this case
        Ctx->Global_MLTA_Reualt_Map[CI] = OneLayer;
		return false;
	}

	/*OP<<"\nsigFuncsMap: \n";
	for(auto it = FS1.begin(); it!=FS1.end(); it++){
		OP<<"-- "<<(*it)->getName()<<"\n";
	}*/

	FuncSet FS2, FST;

	Type *LayerTy = NULL;
	int FieldIdx = -1;
	Value *CV = CI->getCalledOperand();
	//OP<<"CI: "<<*CI<<"\n";
	//OP<<"CV: "<<*CV<<"\n"; //usually load inst

	// Get the second-layer type
	//OP<<"\nGet the second-layer type\n";

	#ifndef ONE_LAYER_MLTA
	CV = nextLayerBaseType(CV, LayerTy, FieldIdx, DL);
	//if(CV == NULL)
		//OP<<"\none layer result is null \n";
	//else
		//OP<<"\none layer result: "<<*CV<<"\n";
	#else
	CV = NULL;
	#endif

	int LayerNo = 1;
	int escapeTag = 0;
	//The set FS1 will be regarded as the final result
	//Let's try only 2 layer type analysis
	//OP<<"LayerTy: "<<*LayerTy<<"\n";

	/*if(LayerTy->isStructTy()){
		StructType * st = dyn_cast<StructType>(LayerTy);
		for(auto it = st->element_begin(); it != st->element_end(); it++){
			Type* memberty = *it;
			OP<<"memberty: "<<*memberty<< "ID: "<< memberty->getTypeID()<<"\n";
		}
	}*/
	//OP<<"Value: "<<*CV<<"\n";
	//OP<<"FieldIdx: "<<FieldIdx<<"\n";

	if(CV){
		findCalleesWithTwoLayerTA(CI, FS1, LayerTy, FieldIdx, FST, LayerNo, escapeTag);
		if(!FST.empty()){
			//OP<<"succ\n";
            Ctx->Global_MLTA_Reualt_Map[CI] = TwoLayer;
			FS1 = FST;
		}
		else{
			//not escape but still empty, regard this as no target rather than 
			//use the result of a lower layer type analysis
			//OP<<"empty\n";
			if(escapeTag==0){
                Ctx->Global_MLTA_Reualt_Map[CI] = NoLayerInfo;
				FS1.clear();
            }
            else{
                Ctx->Global_MLTA_Reualt_Map[CI] = TypeEscape;
            }
			//OP<<"empty FST\n";
		}
	}
	else{
		//OP<<"not found CV\n";
		//Reset CV
		CV = CI->getCalledOperand();

		set<CompositeType> CTSet;
		CTSet.clear();
		checkTypeStoreFunc(CV,CTSet);
		if(!CTSet.empty()){
			//CV comes from a return value of a function call
			FuncSet mergeFS;
			mergeFS.clear();
            int isTransEscape = 0;
			for(auto it = CTSet.begin(); it != CTSet.end(); it++){
				Type *ty = it->first;
				int fieldIdx = it->second;
				//OP<<"TY: "<<*ty<<"\n";
				//OP<<"fieldID: " <<fieldIdx<<"\n"; 
				findCalleesWithTwoLayerTA(CI, FS1, ty, fieldIdx, FST, LayerNo, escapeTag);
                if(escapeTag == 0)
				    funcSetMerge(mergeFS,FST);
                else{
                    isTransEscape = 1;
                    break;
                }
			}

			if(!mergeFS.empty()){
                Ctx->Global_MLTA_Reualt_Map[CI] = TwoLayer;
				FS1 = mergeFS;
			}
			else{
                if(isTransEscape == 0){
                    Ctx->Global_MLTA_Reualt_Map[CI] = NoLayerInfo;
                    FS1.clear();
                }
                else{
                    Ctx->Global_MLTA_Reualt_Map[CI] = TypeEscape;
                }
				//OP<<"empty merge set\n";
				//FS1.clear();
			}
		}
		else{
            Ctx->Global_MLTA_Reualt_Map[CI] = OneLayer;
			//OP<<"empty CTset\n";
			//FS1.clear();
		}

	}

	FS = FS1;

    //CV = nextLayerBaseType(CV, LayerTy, FieldIdx, DL);

	//Record if current icall benifit mlta
	//if(LayerNo > 1 && FS.size()){
	if(LayerNo > 1){
		Ctx->valied_icallNumber++;
		Ctx->valied_icallTargets+=FS.size();
	}

	#if 0
	if (LayerNo > 1 && FS.size()) {
		OP<<"[CallGraph] Indirect call: "<<*CI<<"\n";
		printSourceCodeInfo(CI);
		OP<<"\n\t Indirect-call targets:\n";
		for (auto F : FS) {
			printSourceCodeInfo(F);
		}
		OP<<"\n";
	}
	#endif
	return true;
}