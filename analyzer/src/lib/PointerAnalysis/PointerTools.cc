#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>

#include "PointerAnalysis.h"

int PointerAnalysisPass::getEdgeType(Value *V){
    
    //1000 : *

    StoreInst *STI = dyn_cast<StoreInst>(V);
    if(STI){
        return 1000;
    }

    LoadInst* LI = dyn_cast<LoadInst>(V);
    if(LI){
        return 1000;
    }

    // strutc field use the index number to represent
    GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V);
    if(GEP){
        if(GEP->hasAllConstantIndices()){
            unsigned indice_num = GEP->getNumIndices();
            if(indice_num>2){
                return -1;
            }

            User::op_iterator ie = GEP->idx_end();
			ConstantInt *ConstI = dyn_cast<ConstantInt>((--ie)->get());
			int Idx = ConstI->getSExtValue();
            return Idx;
        }
    }

    GEPOperator *GEPO = dyn_cast<GEPOperator>(V);
    if(GEPO){
        if(GEPO->hasAllConstantIndices()){
            unsigned indice_num = GEPO->getNumIndices();
            if(indice_num>2){
                return -1;
            }

            User::op_iterator ie = GEPO->idx_end();
			ConstantInt *ConstI = dyn_cast<ConstantInt>((--ie)->get());
			int Idx = ConstI->getSExtValue();
            return Idx;
        }
    }

    return -1;
}

PointerAnalysisPass::AliasNode* PointerAnalysisPass::getNode(Value *V){

    //Constant value is always regarded as different value
    Constant *Ct = dyn_cast<Constant>(V);
    if(Ct)
        return NULL;

    for(auto it = NodeVector.begin(); it != NodeVector.end(); it++){
        AliasNode* node = *it;
        if(node->count(V)){
            return node;
        }
    }

    return NULL;
}

//check if there is an edge in the EdgeVector that satisfies the query
PointerAnalysisPass::AliasNode* PointerAnalysisPass::findEdge(AliasNode* fromNode, int type){
    
    for(auto it = EdgeVector.begin(); it != EdgeVector.end(); it++){
        AliasEdge* edge = *it;
        if(edge->fromNode == fromNode && edge->type == type){
            return edge->toNode;
        }
    }

    return NULL;
}



void PointerAnalysisPass::showResults(){

    map<size_t, set<AliasNode*>> aliasMap;

    OP<<"\n\n=======Show path-based alias result:==========\n";

    map<AliasNode*, bool> analysisNodeMap;
    for(auto it = NodeVector.begin(); it != NodeVector.end(); it++){
        AliasNode* node = *it;
        if(!node->empty())
            analysisNodeMap[node] = false; //tag if this node is analyzed
    }


    //Collect the same point to set
    for(auto it = EdgeVector.begin(); it != EdgeVector.end(); it++){
        AliasEdge* edge = *it;
        AliasNode* fromNode = edge->fromNode;
        AliasNode* toNode = edge->toNode;
        int type = edge->type;
        aliasMap[type + (size_t)toNode].insert(fromNode);
        analysisNodeMap[fromNode] = true;
    }



    for(auto it = aliasMap.begin(); it != aliasMap.end(); it++){
        set<AliasNode*> aliasNodeSet = it->second;
        
        OP<<"\n---Alias class---\n";
        //OP<<"toNode: "<<it->first<<"\n";
        for(auto k = aliasNodeSet.begin(); k != aliasNodeSet.end(); k++){
            AliasNode* node = *k;
            node->print_set();
        }
    }

    for(auto it = analysisNodeMap.begin(); it != analysisNodeMap.end(); it++){
        AliasNode* node = it->first;
        if(analysisNodeMap[node] == false){
            OP<<"\n---Alias class---\n";
            node->print_set();
        }
    
    }
}

//Check if v1 and v2 are aliased
bool PointerAnalysisPass::isAlias(Value* v1, Value* v2){
    
    AliasNode* node1 = getNode(v1);
    AliasNode* node2 = getNode(v2);

    if(node1 == node2)
        return true;
    
    set<AliasEdge*> edgeSet1;
    set<AliasEdge*> edgeSet2;
    edgeSet1.clear(), edgeSet2.clear();

    for(auto it = EdgeVector.begin(); it != EdgeVector.end(); it++){
        AliasEdge* edge = *it;
        AliasNode* fromNode = edge->fromNode;

        if(fromNode == node1)
            edgeSet1.insert(edge);
        
        if(fromNode == node2)
            edgeSet2.insert(edge);
        
    }

    for(auto i = edgeSet1.begin(); i!= edgeSet1.end(); i++){
        AliasEdge* edge1 = *i;
        AliasNode* toNode1 = edge1->toNode;
        int type1 = edge1->type;

        for(auto j = edgeSet2.begin(); j!= edgeSet2.end(); j++){
            AliasEdge* edge2 = *j;
            AliasNode* toNode2 = edge2->toNode;
            int type2 = edge2->type;

            if((type2 == type1) && (toNode1 == toNode2))
                return true;
        }
    }

    return false;

}