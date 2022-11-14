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


//If we have update, return true
bool IcallAnalysisPass::updateGlobalAnalysisTarget(){

    bool updateTag = false;
    //First update global
	for(string GVName : Ctx->Global_Target_GV_Set){

		//Here all global variables in Global_Target_GV_Set have been initialized

		//Current global comes from other global
		if(Ctx->Global_Trans_Global_To_Global_Map.count(GVName)){
			for(string TransGVName : Ctx->Global_Trans_Global_To_Global_Map[GVName]){

				//TransGVName has not been analyzed,
                //analyze them in the next analysis round
				if(Ctx->Global_Target_GV_Set.count(TransGVName) == 0){
					Ctx->Global_Target_GV_Set.insert(TransGVName);
                    //OP<<"Update: "<<TransGVName<<"\n";
                    updateTag = true;
                }
                //Recursively collect all transmitted funcset

			}
		}

		if(Ctx->Global_Trans_Global_To_Arg_Map.count(GVName)){
            for(size_t TransArg : Ctx->Global_Trans_Global_To_Arg_Map[GVName]){
                if(Ctx->Global_Target_Call_Set.count(TransArg) == 0){
					Ctx->Global_Target_Call_Set.insert(TransArg);
                    //OP<<"Update: "<<TransArg<<"\n";
                    updateTag = true;
                }
            }
		}
	}

    //Then update arg
    for(size_t Call : Ctx->Global_Target_Call_Set){

        if(Ctx->Global_Trans_Arg_To_Global_Map.count(Call)){
            for(string TransGVName : Ctx->Global_Trans_Arg_To_Global_Map[Call]){
                if(Ctx->Global_Target_GV_Set.count(TransGVName) == 0){
					Ctx->Global_Target_GV_Set.insert(TransGVName);
                    //OP<<"Update: "<<TransGVName<<"\n";
                    updateTag = true;
                }
            }
        }

        if(Ctx->Global_Trans_Arg_To_Arg_Map.count(Call)){
            for(size_t TransCall : Ctx->Global_Trans_Arg_To_Arg_Map[Call]){
                if(Ctx->Global_Target_Call_Set.count(TransCall) == 0){
					Ctx->Global_Target_Call_Set.insert(TransCall);
                    //OP<<"Update: "<<TransCall<<"\n";
                    updateTag = true;
                }
            }
        }
    }

    return updateTag;

}

int IcallAnalysisPass::isConnect(DataNode DN1, DataNode DN2){
                
    //string & string
    if(DN1.type == 0 && DN2.type == 0){
        if(Ctx->Global_Trans_Global_To_Global_Map[DN1.global].count(DN2.global)){
            return 1;
        }
    }

    //string & call
    if(DN1.type == 0 && DN2.type == 1){
        if(Ctx->Global_Trans_Global_To_Arg_Map[DN1.global].count(DN2.call)){
            return 1;
        }
    }

    //call & string
    if(DN1.type == 1 && DN2.type == 0){
        if(Ctx->Global_Trans_Arg_To_Global_Map[DN1.call].count(DN2.global)){
            return 1;
        }
    }

    //call & call
    if(DN1.type == 1 && DN2.type == 1){
        if(Ctx->Global_Trans_Arg_To_Arg_Map[DN1.call].count(DN2.call)){
            return 1;
        }
    }

    return 0;
}

void IcallAnalysisPass::updateFST(DataNode DN1, DataNode DN2){
    
    if(DN1.type == 0 && DN2.type == 0){
        funcSetMerge(Ctx->Global_GV_Func_Map[DN1.global], Ctx->Global_GV_Func_Map[DN2.global]);
    }

    if(DN1.type == 0 && DN2.type == 1){
        funcSetMerge(Ctx->Global_GV_Func_Map[DN1.global], Ctx->Global_Arg_Func_Map[DN2.call]);
    }

    if(DN1.type == 1 && DN2.type == 0){
        funcSetMerge(Ctx->Global_Arg_Func_Map[DN1.call], Ctx->Global_GV_Func_Map[DN2.global]);
    }

    if(DN1.type == 1 && DN2.type == 1){
        funcSetMerge(Ctx->Global_Arg_Func_Map[DN1.call], Ctx->Global_Arg_Func_Map[DN2.call]);
    }

}

bool IcallAnalysisPass::isDataEscape(DataNode DN){
    
    if(DN.type == 0){
        if(Ctx->Global_Escape_GV_Set.count(DN.global))
            return true;
    }

    if(DN.type == 1){
        if(Ctx->Global_Escape_Call_Set.count(DN.call))
            return true;
    }

    return false;
}

// All we need is already got, 
// Let's update Global_GV_Func_Map, Global_Arg_Func_Map and escape set
// Use warshall algorithm
void IcallAnalysisPass::updateGlobalState(){


    vector<DataNode> DNArray;
    DNArray.clear();

    for(string GVName : Ctx->Global_Target_GV_Set){
        DataNode DN = DataNode(GVName);
        DNArray.push_back(DN);
    }

    for(size_t Call : Ctx->Global_Target_Call_Set){
        DataNode DN = DataNode(Call);
        DNArray.push_back(DN);
    }

    //init adjacency matrix
    vector<vector<int>> adj(DNArray.size());
    for(int i = 0; i < DNArray.size(); i++){
        adj[i].resize(DNArray.size());
    }

    for(int i = 0; i < DNArray.size(); i++){
        for(int j = 0; j < DNArray.size(); j++){
            adj[i][j] = isConnect(DNArray[i], DNArray[j]);
        }
    }

    /*for(int i = 0; i < DNArray.size(); i++){
        for(int j = 0; j < DNArray.size(); j++){
            if(adj[i][j])
                OP<<" "<<adj[i][j];
            else
                OP<<"  ";
        }
        OP<<"\n";
    }*/

    // Warshall algorithm
    for(int k = 0; k < DNArray.size(); k++){
        for(int i = 0; i < DNArray.size(); i++){
            for(int j = 0; j < DNArray.size(); j++){
                adj[i][j] = adj[i][j] | (adj[i][k] & adj[k][j]);
            }
        }
    }

    /*OP<<"\n after Warshall \n";
    for(int i = 0; i < DNArray.size(); i++){
        for(int j = 0; j < DNArray.size(); j++){
            if(adj[i][j])
                OP<<" "<<adj[i][j];
            else
                OP<<"  ";
        }
        OP<<"\n";
    }*/

    for(int i = 0; i < DNArray.size(); i++){
        DataNode DN1 = DNArray[i];
        if(isDataEscape(DN1))
            continue;
        
        bool escape = false;
        for(int j = 0; j < DNArray.size(); j++){
            if (i == j)
                continue;
            
            if(adj[i][j] == 1){
                DataNode DN2 = DNArray[j];
                if(isDataEscape(DN2)){
                    escape = true;
                    break;
                }
                updateFST(DN1, DN2);
            }
        }

        if(escape){
            if(DN1.type == 0){
                Ctx->Global_Escape_GV_Set.insert(DN1.global);
            }

            if(DN1.type == 1){
                Ctx->Global_Escape_Call_Set.insert(DN1.call);
            }
        }
    }

}

void IcallAnalysisPass::updateICallData(){

    for(auto i = Ctx->largeTargetsICalls.begin(), ie = Ctx->largeTargetsICalls.end(); i!= ie; i++){
		
        CallInst* cai = i->first;
		FuncSet targetSets = i->second;

		//OP<<"Cai: "<<*cai<<"\n";
		//OP<<"target: "<<targetSets.size()<<"\n";

		//First find the source of icalls
		map<Value*, SourceFlag> sourceMap;
		sourceMap.clear();
		getICallSource(cai, sourceMap);

		FuncSet merge_FS;
		merge_FS.clear();
		for(auto it = sourceMap.begin(); it != sourceMap.end(); it++){
			Value* V = it->first;
			SourceFlag V_type = it->second;
			FuncSet FS;
            FS.clear();
			
			//Resolve global source
			if(V_type == Global){
				//OP<<"global: "<<*V<<"\n";
				if(V->hasName()){
					string V_Name = V->getName();
					if(V_Name.size()>0){
                        if(Ctx->Global_Escape_GV_Set.count(V_Name) == 0){
                            FS = Ctx->Global_GV_Func_Map[V_Name];
                        }
                        else{
                            //OP<<"escap module: "<<cai->getModule()->getName()<<"\n";
                            //OP<<"escape in global "<<cai->getFunction()->getName()<<"\n";
                        }
                    }
				}
                if(!FS.empty()){
					funcSetMerge(merge_FS,FS);
				}
			}

			//Resolve argument source
			else if(V_type == Argument){
				Function* parrent = cai->getFunction();
				if(!parrent)
					continue;

				unsigned index = 0;
				for(auto j = parrent->arg_begin(); j != parrent->arg_end();j++){
					Value* arg = j;
					if(arg == V){
						break;
					}
					index++;
				}

				//argumentSourceAnalysis(parrent,index,FS);
                string Call_Name = parrent->getName();
                if(Call_Name.size()>0){
                    size_t hash = stringIdHash(Call_Name,index);
                    if(Ctx->Global_Escape_Call_Set.count(hash) == 0){
                        FS = Ctx->Global_Arg_Func_Map[hash];
                    }
                    else{
                        //OP<<"escap module: "<<cai->getModule()->getName()<<"\n";
                        //OP<<"escape in call "<<Call_Name<<"\n";
                    }
                }
                
				if(!FS.empty()){
					funcSetMerge(merge_FS,FS);
				}

				
			
			}

			//Fixme: comes from the return value of function call
		}

		/*OP<<"targetSets: \n";
		for(auto it = targetSets.begin(); it!=targetSets.end();it++){
			Function* f= *it;
			OP<<"f: "<<f->getName()<<"\n";
		}

		OP<<"merge_set: \n";
		for(auto it = merge_FS.begin(); it!=merge_FS.end();it++){
			Function* f= *it;
			OP<<"f: "<<f->getName()<<"\n";
		}*/

		if(!merge_FS.empty()){
			
			Ctx->icallTargets-=targetSets.size();
			Ctx->icallTargets+=merge_FS.size();
			Ctx->Callees[cai] = merge_FS;
			Ctx->ICallees[cai] = merge_FS;
		}

		

    }
}