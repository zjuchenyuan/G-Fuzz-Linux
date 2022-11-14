#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>

#include "AliasAnalysis.h"

//merge n1 into n2
void mergeNode(AliasNode* n1, AliasNode* n2, AliasContext *aliasCtx){

    if(n1 == n2)    
        return;
    
    /*OP<<"\nstart merge\n";
    OP<<"n1: "<<n1<<"\n";
    if(ToNodeMap.count(n1)){
        OP<<"n1 ToNodeMap: "<<ToNodeMap[n1]<<"\n";
    }
    if(FromNodeMap.count(n1)){
        OP<<"n1 FromNodeMap: "<<FromNodeMap[n1]<<"\n";
    }
    OP<<"n2: "<<n2<<"\n";
    if(ToNodeMap.count(n2)){
        OP<<"n2 ToNodeMap: "<<ToNodeMap[n2]<<"\n";
    }
    if(FromNodeMap.count(n2)){
        OP<<"n2 FromNodeMap: "<<FromNodeMap[n2]<<"\n";
    }*/

    //First merge values
    for(auto it = n1->aliasclass.begin(); it != n1->aliasclass.end(); it++){
        Value* v = *it;
        n2->insert(v);
        aliasCtx->NodeMap[v] = n2;
    }
    n1->aliasclass.clear();

    //Then change edges
    //Check n1 points to which node
    if(aliasCtx->ToNodeMap.count(n1)){
        AliasNode* n1_toNode = aliasCtx->ToNodeMap[n1];

        if(aliasCtx->ToNodeMap.count(n2)){
            AliasNode* n2_toNode = aliasCtx->ToNodeMap[n2];

            //n1 and n2 points to the same node
            //This cannot happen for one node only has one pre and post node in field-sensitive analysis
            //But it could occur in field-insensitive analysis
            if(n1_toNode == n2_toNode){
                //do nothing here
                //OP<<"WARNING IN MERGE NODE!\n";
                //sleep(1);
            }
            else{
                aliasCtx->ToNodeMap.erase(n1);
                aliasCtx->ToNodeMap.erase(n2);
                aliasCtx->FromNodeMap.erase(n1_toNode);
                aliasCtx->FromNodeMap.erase(n2_toNode);
                mergeNode(n1_toNode, n2_toNode, aliasCtx);
                aliasCtx->ToNodeMap[n2] = n2_toNode;
                aliasCtx->FromNodeMap[n2_toNode] = n2;
            }
        }

        //n2 has no pointed node
        else{
            aliasCtx->ToNodeMap.erase(n1);
            aliasCtx->ToNodeMap[n2] = n1_toNode;
            aliasCtx->FromNodeMap[n1_toNode] = n2;
        }
    }

    //Check which node points to n1
    if(aliasCtx->FromNodeMap.count(n1)){
        AliasNode* n1_fromNode = aliasCtx->FromNodeMap[n1];

        if(aliasCtx->FromNodeMap.count(n2)){
            AliasNode* n2_fromNode = aliasCtx->FromNodeMap[n2];

            if(n1_fromNode == n2_fromNode){
                //do nothing here
                //OP<<"WARNING IN MERGE NODE!\n";
                //sleep(1);
            }
            else{
                aliasCtx->FromNodeMap.erase(n1);
                aliasCtx->FromNodeMap.erase(n2);
                aliasCtx->ToNodeMap.erase(n1_fromNode);
                aliasCtx->ToNodeMap.erase(n2_fromNode);
                mergeNode(n1_fromNode, n2_fromNode, aliasCtx);
                aliasCtx->FromNodeMap[n2] = n2_fromNode;
                aliasCtx->ToNodeMap[n2_fromNode] = n2;
            }
        }

        //n2 has no pre node
        else{
            aliasCtx->FromNodeMap.erase(n1);
            aliasCtx->FromNodeMap[n2] = n1_fromNode;
            aliasCtx->ToNodeMap[n1_fromNode] = n2;
        }
    }
}


AliasNode* getNode(Value *V, AliasContext *aliasCtx){

    //Constant value is always regarded as different value
    //Note: this check will influence global values!
    /*Constant *Ct = dyn_cast<Constant>(V);
    if(Ct){
        OP<<"node is constant\n";
        return NULL;
    }*/

    //Use a map to speed up query
    if(aliasCtx->NodeMap.count(V))
        return aliasCtx->NodeMap[V];

    /*for(auto it = NodeVector.begin(); it != NodeVector.end(); it++){
        AliasNode* node = *it;
        if(node->count(V)){
            return node;
        }
    }*/

    return NULL;
}


//Filter instructions we do not need to analysis
//Return true if current inst does not need analysis
bool isUselessInst(Instruction* I, GlobalContext *Ctx){

    //Filter debug functions
    CallInst *CAI = dyn_cast<CallInst>(I);
    if(CAI){
        StringRef FName = getCalledFuncName(CAI);
        if(Ctx->DebugFuncs.count(FName)){
            //OP<<"debug func: "<<FName<<"\n";
            return true;
        }
    }

    return false;
}

//merge S2 into S1
void valueSetMerge(set<Value*> &S1, set<Value*> &S2){
	for(auto v : S2)
		S1.insert(v);
}

void funcSetMerge(FuncSet &S1, FuncSet &S2){
    for(auto v : S2){
		S1.insert(v);
    }
}

unsigned getArgIndex(Function* F, Argument *Arg){

    unsigned index = 0;
    for(auto it = F->arg_begin(); it != F->arg_end(); it++){
        Value* F_arg = it;
        if(Arg == F_arg){
            break;
        }
        index++;
    }

    return index;
}

unsigned getMin(unsigned n1, unsigned n2){
    if(n1 < n2)
        return n1;
    else
        return n2;
}

void getGlobalFuncs(Function *F, FuncSet &FSet, GlobalContext *Ctx){

    StringRef FName = F->getName();
    if(Ctx->GlobalFuncs.count(FName.str())){
        //OP<<"here\n";
        set<size_t> hashSet = Ctx->GlobalFuncs[FName.str()];
        for(auto it = hashSet.begin(); it != hashSet.end(); it++){
            Function *f = Ctx->Global_Unique_Func_Map[*it];
            //OP<<"f: "<<*f<<"\n";
			FSet.insert(f);
        }
    }
}