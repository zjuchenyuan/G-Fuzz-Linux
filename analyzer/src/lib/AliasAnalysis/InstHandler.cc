#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>

#include "AliasAnalysis.h"

void HandleOperator(Value* v, AliasContext *aliasCtx){
    //OP<<"operand: "<<*v<<"\n";
    GEPOperator *GEPO = dyn_cast<GEPOperator>(v);
    if(GEPO){
        //OP<<"\nreslove GEPO: "<<*GEPO<<"\n";
        //OP<<"handle gepo\n";
        HandleGEP(GEPO, aliasCtx);
        HandleOperator(GEPO->getOperand(0), aliasCtx);
    }

    BitCastOperator *CastO = dyn_cast<BitCastOperator>(v);
    if(CastO){
        //OP<<"handle casto\n";
        //OP<<"\nreslove CastO: "<<*CastO<<"\n";
        HandleMove(CastO, CastO->getOperand(0), aliasCtx);
        HandleOperator(CastO->getOperand(0), aliasCtx);
    }

    PtrToIntOperator *PTIO = dyn_cast<PtrToIntOperator>(v);
    if(PTIO){
        HandleMove(PTIO, PTIO->getOperand(0), aliasCtx);
        HandleOperator(PTIO->getOperand(0), aliasCtx);
    }
}

void HandleInst(Instruction* I, AliasContext *aliasCtx, GlobalContext *Ctx){

    //OP<<"\nCurrent inst: "<<*I<<"\n";

    //First filter instructions that do not need to consider
    if(isUselessInst(I, Ctx))
        return;

    //OP<<"\nCurrent inst: "<<*I<<"\n";

    // Handle GEP and Cast operator
    // Arguments of call are also caught here
    // Note: func call arch_static_branch in pwm-omap-dmtimer.ll
    int opnum = I->getNumOperands();
    for(int i = 0; i < I->getNumOperands(); i++){
        Value* op = I->getOperand(i);
        /*if(Function* f = dyn_cast<Function>(op))
            OP<<"operand(f): "<<f->getName()<<"\n";
        else
            OP<<"operand: "<< *op <<"\n";
        sleep(1);*/
        HandleOperator(op, aliasCtx);
    }

    //Handle target instruction
    AllocaInst* ALI = dyn_cast<AllocaInst>(I);
    if(ALI){
        HandleAlloc(ALI, aliasCtx);
        return;
    }

    StoreInst *STI = dyn_cast<StoreInst>(I);
    if(STI){
        HandleStore(STI, aliasCtx);
        return;
    }

    LoadInst* LI = dyn_cast<LoadInst>(I);
    if(LI){
        HandleLoad(LI, aliasCtx);
        return;
    }

    GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(I);
    if(GEP){
        HandleGEP(GEP, aliasCtx);
        return;
    }

    BitCastInst *BCI = dyn_cast<BitCastInst>(I);
    ZExtInst *ZEXI = dyn_cast<ZExtInst>(I);
    SExtInst *SEXI = dyn_cast<SExtInst>(I);
    TruncInst *TRUI = dyn_cast<TruncInst>(I);
    IntToPtrInst *ITPI = dyn_cast<IntToPtrInst>(I);
    PtrToIntInst *PTII = dyn_cast<PtrToIntInst>(I);
    if(BCI || ZEXI || SEXI || TRUI || ITPI || PTII){
        auto op = I->getOperand(0);
        HandleMove(I, op, aliasCtx);
        return;
    }

    PHINode *PHI = dyn_cast<PHINode>(I);
    if(PHI){
        for (unsigned i = 0, e = PHI->getNumIncomingValues(); i != e; ++i){
            Value *IV = PHI->getIncomingValue(i);
            HandleMove(I, IV, aliasCtx);
        }
        return;
    }

    SelectInst *SLI = dyn_cast<SelectInst>(I);
    if(SLI){
        auto TV = SLI->getTrueValue();
        auto FV = SLI->getFalseValue();
        HandleMove(I, TV, aliasCtx);
        HandleMove(I, FV, aliasCtx);
        return;
    }

    CallInst *CAI = dyn_cast<CallInst>(I);
    if(CAI){
        HandleCai(CAI, aliasCtx, Ctx);
        return;
    }

}

void HandleAlloc(AllocaInst* ALI, AliasContext *aliasCtx){
    
    if(getNode(ALI, aliasCtx) == NULL){
        AliasNode* node = new AliasNode();
        node->insert(ALI);
        //NodeVector.push_back(node);
        aliasCtx->NodeMap[ALI] = node;
    }
}

// v1 = *v2
void HandleLoad(LoadInst* LI, AliasContext *aliasCtx){
    
    AliasNode* node1 = getNode(LI, aliasCtx);
    if(node1 == NULL){
        node1 = new AliasNode();
        node1->insert(LI);
        //NodeVector.push_back(node1);
        aliasCtx->NodeMap[LI] = node1;
    }

    Value* op = LI->getOperand(0);
    AliasNode* node2 = getNode(op, aliasCtx);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(op);
        //NodeVector.push_back(node2);
        aliasCtx->NodeMap[op] = node2;
    }

    //int edgetype = getEdgeType(LI);

    /*if(AliasNode* nodex = findEdge(node2, edgetype)){
        node1->erase(LI);
        nodex->insert(LI);
    }
    else{
        AliasEdge* edge = new AliasEdge();
        edge->fromNode = node2;
        edge->toNode = node1;
        edge->type = edgetype;
        EdgeVector.push_back(edge);
    }*/

    //node2 has pointed to some nodes
    if(aliasCtx->ToNodeMap.count(node2)){
        AliasNode* node2_toNode = aliasCtx->ToNodeMap[node2];
        mergeNode(node1 ,node2_toNode, aliasCtx);
    }
    else if(aliasCtx->FromNodeMap.count(node1)){
        AliasNode* node1_fromNode = aliasCtx->FromNodeMap[node1];
        mergeNode(node1_fromNode, node2, aliasCtx);
    }
    else{
        aliasCtx->ToNodeMap[node2] = node1;
        aliasCtx->FromNodeMap[node1] = node2;
    }

}

// *v2 = v1
void HandleStore(StoreInst* STI, AliasContext *aliasCtx){
    
    //store vop to pop
    Value* vop = STI->getValueOperand(); //v1
    Value* pop = STI->getPointerOperand(); //v2

    AliasNode* node1 = getNode(vop, aliasCtx);
    if(node1 == NULL){
        //OP<<"c1\n";
        //OP<<"vop: "<<*vop<<"\n";
        //OP<<"vop hash: "<<vop<<"\n";
        node1 = new AliasNode();
        node1->insert(vop);
        //NodeVector.push_back(node1);
        aliasCtx->NodeMap[vop] = node1;
    }

    AliasNode* node2 = getNode(pop, aliasCtx);
    if(node2 == NULL){
        //OP<<"c2\n";
        node2 = new AliasNode();
        node2->insert(pop);
        //NodeVector.push_back(node2);
        aliasCtx->NodeMap[pop] = node2;
    }

    //int edgetype = getEdgeType(STI);

    //node2 has pointed to some nodes
    if(aliasCtx->ToNodeMap.count(node2)){
        //OP<<"case1\n";
        AliasNode* node2_toNode = aliasCtx->ToNodeMap[node2];
        mergeNode(node1 ,node2_toNode, aliasCtx);
    }
    else if(aliasCtx->FromNodeMap.count(node1)){
        //OP<<"case2\n";
        AliasNode* node1_fromNode = aliasCtx->FromNodeMap[node1];
        mergeNode(node1_fromNode, node2, aliasCtx);
    }
    else{
        //OP<<"case3\n";
        aliasCtx->ToNodeMap[node2] = node1;
        aliasCtx->FromNodeMap[node1] = node2;
    }

    /*AliasEdge* edge = new AliasEdge();
    edge->fromNode = node2;
    edge->toNode = node1;
    edge->type = edgetype;
    EdgeVector.push_back(edge);*/

    //ToNodeMap[node2].insert(node1);
    //FromNodeMap[node1].insert(node2);
}

void HandleStore(Value* vop, Value* pop, AliasContext *aliasCtx){

    AliasNode* node1 = getNode(vop, aliasCtx);
    if(node1 == NULL){
        //OP<<"c1\n";
        //OP<<"vop: "<<*vop<<"\n";
        //OP<<"vop hash: "<<vop<<"\n";
        node1 = new AliasNode();
        node1->insert(vop);
        //NodeVector.push_back(node1);
        aliasCtx->NodeMap[vop] = node1;
    }

    AliasNode* node2 = getNode(pop, aliasCtx);
    if(node2 == NULL){
        //OP<<"c2\n";
        node2 = new AliasNode();
        node2->insert(pop);
        //NodeVector.push_back(node2);
        aliasCtx->NodeMap[pop] = node2;
    }

    //node2 has pointed to some nodes
    if(aliasCtx->ToNodeMap.count(node2)){
        //OP<<"case1\n";
        AliasNode* node2_toNode = aliasCtx->ToNodeMap[node2];
        mergeNode(node1 ,node2_toNode, aliasCtx);
    }
    else if(aliasCtx->FromNodeMap.count(node1)){
        //OP<<"case2\n";
        AliasNode* node1_fromNode = aliasCtx->FromNodeMap[node1];
        mergeNode(node1_fromNode, node2, aliasCtx);
    }
    else{
        //OP<<"case3\n";
        aliasCtx->ToNodeMap[node2] = node1;
        aliasCtx->FromNodeMap[node1] = node2;
    }
}

// v1 = &v2->f
void HandleGEP(GetElementPtrInst* GEP, AliasContext *aliasCtx){

    HandleMove(GEP, GEP->getPointerOperand(), aliasCtx);
    /*AliasNode* node1 = getNode(GEP);
    if(node1 == NULL){
        node1 = new AliasNode();
        node1->insert(GEP);
        NodeVector.push_back(node1);
    }

    Value *ParrentValue = GEP->getPointerOperand();
    AliasNode* node2 = getNode(ParrentValue);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(ParrentValue);
        NodeVector.push_back(node2);
    }

    int edgetype = getEdgeType(GEP);

    if(AliasNode* nodex = findEdge(node2, edgetype)){
        node1->erase(GEP);
        nodex->insert(GEP);
    }
    else{
        AliasEdge* edge = new AliasEdge();
        edge->fromNode = node2;
        edge->toNode = node1;
        edge->type = edgetype;
        EdgeVector.push_back(edge);
    }*/
}

void HandleGEP(GEPOperator* GEP, AliasContext *aliasCtx){
    //OP<<"handle GEPO: "<<*GEP<<"\n";
    //OP<<"operand: "<<*GEP->getPointerOperand()<<"\n";
    HandleMove(GEP, GEP->getPointerOperand(), aliasCtx);
    /*AliasNode* node1 = getNode(GEP);
    if(node1 == NULL){
        node1 = new AliasNode();
        node1->insert(GEP);
        NodeVector.push_back(node1);
    }

    Value *ParrentValue = GEP->getPointerOperand();
    AliasNode* node2 = getNode(ParrentValue);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(ParrentValue);
        NodeVector.push_back(node2);
    }

    int edgetype = getEdgeType(GEP);

    if(AliasNode* nodex = findEdge(node2, edgetype)){
        node1->erase(GEP);
        nodex->insert(GEP);
    }
    else{
        AliasEdge* edge = new AliasEdge();
        edge->fromNode = node2;
        edge->toNode = node1;
        edge->type = edgetype;
        EdgeVector.push_back(edge);
    }*/
}



// v1 = v2
void HandleMove(Value* v1, Value* v2, AliasContext *aliasCtx){

    //OP<<"\nhandle move\n";
    //OP<<"v1: "<<*v1<<"\n";
    //OP<<"v2: "<<*v2<<"\n";

    AliasNode* node2 = getNode(v2, aliasCtx);
    if(node2 == NULL){
        //OP<<"creat node2\n";
        node2 = new AliasNode();
        node2->insert(v2);
        //NodeVector.push_back(node2);
        aliasCtx->NodeMap[v2] = node2;
    }


    AliasNode* node1 = getNode(v1, aliasCtx);
    if(node1 == NULL){
        //OP<<"move here\n";
        //OP<<"v1 hash: "<<v1<<"\n";
        node2->insert(v1);
        aliasCtx->NodeMap[v1] = node2;
        return;
    }

    if(node1 == node2)
        return;

    //OP<<"--node1: \n";
    //node1->print_set();
    //OP<<"--node2: \n";
    //node2->print_set();

    //node1->erase(v1);
    mergeNode(node1, node2, aliasCtx);

    //OP<<"--after node1: \n";
    //node1->print_set();
    //OP<<"--after node2: \n";
    //node2->print_set();

}

void HandleCai(CallInst* CAI, AliasContext *aliasCtx, GlobalContext *Ctx){
    
    //OP<<"operand: "<<*CAI->getOperand(0)<<"\n";
    if(getNode(CAI, aliasCtx) == NULL){
        AliasNode* node = new AliasNode();
        node->insert(CAI);
        //NodeVector.push_back(node);
        aliasCtx->NodeMap[CAI] = node;
    }

    // Resolve mem copy functions
    // Usually a copy func is like: copy_func(dst, src, len)
    StringRef FName = getCalledFuncName(CAI);
    if(Ctx->CopyFuncs.count(FName)){
        //OP<<"is copy\n";
        HandleMove(CAI->getArgOperand(0), CAI->getArgOperand(1), aliasCtx);
    }



}

void HandleReturn(Function* F, CallInst* cai, AliasContext *aliasCtx){

    for (inst_iterator i = inst_begin(F), ei = inst_end(F); i != ei; ++i) {
        ReturnInst *RI = dyn_cast<ReturnInst>(&*i);
        if(RI){
            Value* return_v = RI->getReturnValue();
            if(return_v){
                HandleMove(return_v, cai, aliasCtx);
            }
        }
    }

}