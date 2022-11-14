#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>

#include "PointerAnalysis.h"

void PointerAnalysisPass::HandleInst(Instruction* I){

    //OP<<"Current inst: "<<*I<<"\n";

    // Handle GEP and Cast operator
    // note func call arch_static_branch in pwm-omap-dmtimer.ll
    int opnum = I->getNumOperands();
    for(int i = 0; i < I->getNumOperands(); i++){
        Value* op = I->getOperand(i);
        
        GEPOperator *GEPO = dyn_cast<GEPOperator>(op);
        if(GEPO){
            HandleGEP(GEPO);
        }

        BitCastOperator *CastO = dyn_cast<BitCastOperator>(op);
        if(CastO){
            HandleMove(CastO, CastO->getOperand(0));
        }
    }


    //Handle target instruction
    AllocaInst* ALI = dyn_cast<AllocaInst>(I);
    if(ALI){
        HandleAlloc(ALI);
    }

    StoreInst *STI = dyn_cast<StoreInst>(I);
    if(STI){
        HandleStore(STI);
    }

    LoadInst* LI = dyn_cast<LoadInst>(I);
    if(LI){
        HandleLoad(LI);
    }

    GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(I);
    if(GEP){
        HandleGEP(GEP);
    }

    BitCastInst *BCI = dyn_cast<BitCastInst>(I);
    ZExtInst *ZEXI = dyn_cast<ZExtInst>(I);
    SExtInst *SEXI = dyn_cast<SExtInst>(I);
    TruncInst *TRUI = dyn_cast<TruncInst>(I);
    IntToPtrInst *ITPI = dyn_cast<IntToPtrInst>(I);
    PtrToIntInst *PTII = dyn_cast<PtrToIntInst>(I);
    if(BCI || ZEXI || SEXI || TRUI || ITPI || PTII){
        auto op = I->getOperand(0);
        HandleMove(I, op);
    }

    //TODO: support PHI, CALL

}

void PointerAnalysisPass::HandleAlloc(AllocaInst* ALI){
    
    if(getNode(ALI) == NULL){
        AliasNode* node = new AliasNode();
        node->insert(ALI);
        NodeVector.push_back(node);
    }
}

// v1 = *v2
void PointerAnalysisPass::HandleLoad(LoadInst* LI){

    
    AliasNode* node1 = getNode(LI);
    if(node1 == NULL){
        node1 = new AliasNode();
        node1->insert(LI);
        NodeVector.push_back(node1);
    }

    Value* op = LI->getOperand(0);
    AliasNode* node2 = getNode(op);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(op);
        NodeVector.push_back(node2);
    }

    int edgetype = getEdgeType(LI);
    if(AliasNode* nodex = findEdge(node2, edgetype)){
        node1->erase(LI);
        nodex->insert(LI);
    }
    else{
        AliasEdge* edge = new AliasEdge();
        edge->fromNode = node2;
        edge->toNode = node1;
        edge->type = edgetype;
        EdgeVector.push_back(edge);
    }

}

// *v2 = v1
void PointerAnalysisPass::HandleStore(StoreInst* STI){
    
    //store vop to pop
    Value* vop = STI->getValueOperand();
    Value* pop = STI->getPointerOperand();

    AliasNode* node1 = getNode(vop);
    if(node1 == NULL){
        node1 = new AliasNode();
        node1->insert(vop);
        NodeVector.push_back(node1);
    }

    AliasNode* node2 = getNode(pop);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(pop);
        NodeVector.push_back(node2);
    }

    int edgetype = getEdgeType(STI);

    if(AliasNode* nodex = findEdge(node2, edgetype)){
        for(auto it = EdgeVector.begin(); it != EdgeVector.end(); it++){
            AliasEdge* edge = *it;
            if(edge->fromNode == node2 && edge->toNode == nodex && edge->type == edgetype){
                EdgeVector.erase(it);
                break;
            }
        }
    }

    AliasEdge* edge = new AliasEdge();
    edge->fromNode = node2;
    edge->toNode = node1;
    edge->type = edgetype;
    EdgeVector.push_back(edge);
}

// v1 = &v2->f
void PointerAnalysisPass::HandleGEP(GetElementPtrInst* GEP){

    AliasNode* node1 = getNode(GEP);
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
    }
}

void PointerAnalysisPass::HandleGEP(GEPOperator* GEP){

    AliasNode* node1 = getNode(GEP);
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
    }
}



// v1 = v2
void PointerAnalysisPass::HandleMove(Value* v1, Value* v2){

    AliasNode* node1 = getNode(v1);
    if(node1 == NULL){
        node1 = new AliasNode();
        node1->insert(v1);
        NodeVector.push_back(node1);
    }

    AliasNode* node2 = getNode(v2);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(v2);
        NodeVector.push_back(node2);
    }

    node1->erase(v1);
    node2->insert(v1);

}