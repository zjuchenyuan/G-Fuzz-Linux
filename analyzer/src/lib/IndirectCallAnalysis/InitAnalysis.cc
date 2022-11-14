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

void IcallAnalysisPass::findFuncArgStoredCall(CallInst *CI, Value *Arg, unsigned index){

    //OP<<"Call: "<<*CI<<"\n";
    //The simplest case: arg is a function pointer
    if (Function *F = dyn_cast<Function>(Arg)) {
        //OP<<"Call: "<<*CI<<"\n";
        //OP<<"F: "<<F->getName()<<"\n";
        string FName = F->getName();
        if(FName.size() == 0)
            return;

        //Resolve func declare
        if(F->empty() || F->isDeclaration()){
            //OP<<"empty func\n";
            StringRef FName = F->getName();
			if (FName.startswith("SyS_"))
				FName = StringRef("sys_" + FName.str().substr(4));
			if (Function *GF = Ctx->GlobalFuncs_old[FName.str()])
				F = GF;
        }

        Function *CF = CI->getCalledFunction();
        size_t caiHash = stringIdHash(CF->getName(),index);
        Ctx->Global_Arg_Func_Map[caiHash].insert(F);
        return;
    }

    //Arg is not a function, but has func type
    Type* ArgTy = Arg->getType();
    //This check is necessary because ArgTy is always a pointer type
    if(ArgTy->isPointerTy()){
        ArgTy = ArgTy->getPointerElementType();
    }

    if(!ArgTy->isFunctionTy()){
        return;
    }
    //OP<<"has function arg\n";

    //Let's find where this arg comes from
    Function* CIParrentFunc = CI->getFunction();
    set<Value *>argset;
    argset.clear();
    if(CIParrentFunc) {
        for(auto it = CIParrentFunc->arg_begin(); it != CIParrentFunc->arg_end();it++){
            argset.insert(it);
        }
    }

    std::list<Value *> EV; //BFS record list
    std::set<Value *> PV; //Global value set to avoid loop
    EV.clear();
    PV.clear();
    EV.push_back(Arg);

    while (!EV.empty()) {
        Value *TV = EV.front(); //Current checking value
		EV.pop_front();
            
        if (PV.find(TV) != PV.end())
			continue;
        PV.insert(TV);

        //OP<<"TV: "<<*TV<<"\n";

        //This is one type of global, we first check it
        if (Function *F = dyn_cast<Function>(TV)) {
            string FName = F->getName();
            if(FName.size() == 0)
                continue;

            //Resolve func declare
            if(F->empty() || F->isDeclaration()){
                //OP<<"empty func\n";
                StringRef FName = F->getName();
                if (FName.startswith("SyS_"))
                    FName = StringRef("sys_" + FName.str().substr(4));
                if (Function *GF = Ctx->GlobalFuncs_old[FName.str()])
                    F = GF;
            }
            Function *CF = CI->getCalledFunction();
            size_t caiHash = stringIdHash(CF->getName(),index);
            Ctx->Global_Arg_Func_Map[caiHash].insert(F);
            continue;
        }

        auto globalvar = dyn_cast<GlobalValue>(TV);
        if(globalvar){
            //OP<<"global: "<<*TV<<"\n";
            //sourceMap[TV] = Global;
            string GV_Name = globalvar->getName();
            if(GV_Name.size() == 0)
                continue;
            Function *CF = CI->getCalledFunction();
            size_t caiHash = stringIdHash(CF->getName(),index);
            Ctx->Global_Trans_Arg_To_Global_Map[caiHash].insert(GV_Name);
            continue;
        }

        //The arg comes from parrent function
        if(argset.count(TV) == 1){
            //OP<<"in arg\n";
            Function *CF = CI->getCalledFunction();
            size_t caiHash = stringIdHash(CF->getName(),index);
            string parrentName = CIParrentFunc->getName();
            if(parrentName.size() == 0)
                continue;
            //find which arg
            unsigned pindex = 0;
			for(auto j = CIParrentFunc->arg_begin(); j != CIParrentFunc->arg_end();j++){
				Value* arg = j;
				if(arg == TV){
					break;
				}
				pindex++;
			}

            size_t sourceHash = stringIdHash(parrentName,pindex);
            Ctx->Global_Trans_Arg_To_Arg_Map[caiHash].insert(sourceHash);
            continue;
        }



        LoadInst* LI = dyn_cast<LoadInst>(TV);
		if(LI){
			Value *LPO = LI->getPointerOperand();
            EV.push_back(LPO);

			//Get all stored values
            for(User *U : LPO->users()){
                StoreInst *STI = dyn_cast<StoreInst>(U);
                if(STI){
                    
                    Value* vop = STI->getValueOperand(); // store vop to pop
                    Value* pop = STI->getPointerOperand();
                    
					//Store constant is not considered
					//if(isConstant(vop))
					//	continue;
                    if(ConstantData *Ct = dyn_cast<ConstantData>(vop))
                        continue;
                    //OP<<"vop: "<<*vop<<"\n";

					//There must be a path from the store to the load
                    if(pop == LPO && checkBlockPairConnectivity(STI->getParent(), LI->getParent())){
                        EV.push_back(vop);
                    }
                }
            }
			continue;
		}

        GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(TV);
        if(GEP){
			Value* vop = GEP->getPointerOperand();
            EV.push_back(vop);
            continue;
		}

        UnaryInstruction *UI = dyn_cast<UnaryInstruction>(TV);
		if(UI){
			EV.push_back(UI->getOperand(0));
			continue;
		}

        //The return value is a function pointer
        CallInst* CAI = dyn_cast<CallInst>(TV);
        if(CAI){
            //OP<<"func: "<<CAI->getFunction()->getName()<<"\n";
            //OP<<"module: "<<CAI->getModule()->getName()<<"\n";
            //OP<<"arg comes from call\n";
            Function *CF = CI->getCalledFunction();
            size_t caiHash = stringIdHash(CF->getName(),index);

            Function *CAIF = CAI->getCalledFunction();
            if(!CAIF)
                continue;
            string CAIFName = CAIF->getName();
            if(CAIFName.size() == 0)
                continue;
            //Ctx->Global_Trans_Arg_To_Return_Map[caiHash].insert(CAIFName);
            Ctx->Global_Escape_Call_Set.insert(caiHash);
            continue;
        }
    
    }

}

void IcallAnalysisPass::resolveGlobalInitializer(GlobalVariable *GV){
    
    Constant *Ini = GV->getInitializer();
    list<User *>LU;
	LU.push_back(Ini);

	//maybe should consider deadloop
	//should consider global struct array
	while (!LU.empty()) {
		User *U = LU.front();
		LU.pop_front();
        //OP<<"current U: "<<*U<<"\n";

        if (Function *F = dyn_cast<Function>(U)) {
            if(F->empty() || F->isDeclaration()){
                //OP<<"empty func\n";
                StringRef FName = F->getName();
                if (FName.startswith("SyS_"))
                    FName = StringRef("sys_" + FName.str().substr(4));
                if (Function *GF = Ctx->GlobalFuncs_old[FName.str()])
                    F = GF;
            }
            Ctx->Global_GV_Func_Map[GV->getName()].insert(F);
        }

        //Check array init
        for (auto oi = U->op_begin(), oe = U->op_end(); oi != oe; ++oi) {
			Value *O = *oi;
            
            if (Function *F = dyn_cast<Function>(O)) {
                if(F->empty() || F->isDeclaration()){
                    //OP<<"empty func\n";
                    StringRef FName = F->getName();
                    if (FName.startswith("SyS_"))
                        FName = StringRef("sys_" + FName.str().substr(4));
                    if (Function *GF = Ctx->GlobalFuncs_old[FName.str()])
                        F = GF;
                }
                //OP<<"FO: "<<F->getName()<<"\n";
                Ctx->Global_GV_Func_Map[GV->getName()].insert(F);
            }

        }
    }
}

//查找全局变量初始化
void IcallAnalysisPass::findStoreToGlobal(GlobalVariable* GV){
    
    if(!GV->hasName())
        return;
    
    string GV_Name = GV->getName();

    //if(GV_Name != "torture_shutdown_hook")
	//	return;

    //GV itself is a function
    if (Function *F = dyn_cast<Function>(GV)){
        //OP<<"find F: "<<F->getName()<<"\n";

        //Resolve func declare
        if(F->empty() || F->isDeclaration()){
            //OP<<"empty func\n";
            StringRef FName = F->getName();
			if (FName.startswith("SyS_"))
				FName = StringRef("sys_" + FName.str().substr(4));
			if (Function *GF = Ctx->GlobalFuncs_old[FName.str()])
				F = GF;
        }
        Ctx->Global_GV_Func_Map[GV_Name].insert(F);
        return;
    }

   
    //OP<<"GV: "<<GV_Name <<"\n";
    //if(G_Type->isPointerTy())
    //    OP<<"is pointer\n";

    //Find the initializer, usually function pointer array
    if (GV->hasInitializer()){
        //OP<<"GV name: "<<GV_Name<<"\n";
        Constant *Ini = GV->getInitializer();
        resolveGlobalInitializer(GV);
    }

    std::list<Value *> EV; //BFS record list
    std::set<Value *> PV; //Global value set to avoid loop
    EV.clear();
    PV.clear();
    EV.push_back(GV);

    map<Value*, Instruction*> sourceMap;
    sourceMap.clear();

    //Check the use chain to find all stored func (source)
    while (!EV.empty()) {
        Value *TV = EV.front(); //Current checking value
		EV.pop_front();
            
        if (PV.find(TV) != PV.end())
			continue;
        PV.insert(TV);
    
        for(User *U : TV->users()){
            //OP<<"U: "<<*U <<"\n";
            StoreInst *SI = dyn_cast<StoreInst>(U);
            if (SI && GV == SI->getPointerOperand()) {
                Value* vop = SI->getValueOperand(); // store vop to pop
                sourceMap[vop] = SI;
                continue;
            }
        }
    }

    if(sourceMap.empty())
        return;
    

    //Then analyze the source
    for(auto it = sourceMap.begin(); it!= sourceMap.end(); it++){
        EV.clear();
        PV.clear();
        Value* V = it->first;
        EV.push_back(V);

        //Init parrent function arg set
        Instruction* I = it->second;
        Function* IParrentFunc = I->getFunction();
        set<Value *>argset;
        argset.clear();
        if(IParrentFunc) {
            for(auto it = IParrentFunc->arg_begin(); it != IParrentFunc->arg_end();it++){
                argset.insert(it);
            }
        }

        while (!EV.empty()) {
            Value *TV = EV.front(); //Current checking value
            EV.pop_front();
                
            if (PV.find(TV) != PV.end())
                continue;
            PV.insert(TV);

            //This is one type of global, we first check it
            if (Function *F = dyn_cast<Function>(TV)) {
                string FName = F->getName();
                if(FName.size() == 0)
                    continue;

                //Resolve func declare
                if(F->empty() || F->isDeclaration()){
                    //OP<<"empty func\n";
                    StringRef FName = F->getName();
                    if (FName.startswith("SyS_"))
                        FName = StringRef("sys_" + FName.str().substr(4));
                    if (Function *GF = Ctx->GlobalFuncs_old[FName.str()])
                        F = GF;
                }

                Ctx->Global_GV_Func_Map[GV_Name].insert(F);
                continue;
            }

            auto globalvar = dyn_cast<GlobalValue>(TV);
            if(globalvar){
                //OP<<"come from global: "<<*TV<<"\n";
                //sourceMap[TV] = Global;
                string gv_Name = globalvar->getName();
                if(gv_Name.size() == 0)
                    continue;

                Ctx->Global_Trans_Global_To_Global_Map[GV_Name].insert(gv_Name);
                continue;
            }

            //The arg comes from parrent function
            if(argset.count(TV) == 1){

                string parrentName = IParrentFunc->getName();
                if(parrentName.size() == 0)
                    continue;
                //find which arg
                unsigned pindex = 0;
                for(auto j = IParrentFunc->arg_begin(); j != IParrentFunc->arg_end();j++){
                    Value* arg = j;
                    if(arg == TV){
                        break;
                    }
                    pindex++;
                }

                size_t sourceHash = stringIdHash(parrentName,pindex);
                Ctx->Global_Trans_Global_To_Arg_Map[GV_Name].insert(sourceHash);
                continue;
            }


            LoadInst* LI = dyn_cast<LoadInst>(TV);
            if(LI){
                Value *LPO = LI->getPointerOperand();
                EV.push_back(LPO);

                //Get all stored values
                for(User *U : LPO->users()){
                    StoreInst *STI = dyn_cast<StoreInst>(U);
                    if(STI){
                        
                        Value* vop = STI->getValueOperand(); // store vop to pop
                        Value* pop = STI->getPointerOperand();
                        
                        //Store constant is not considered
                        if(ConstantData *Ct = dyn_cast<ConstantData>(vop))
                            continue;
                        //OP<<"vop: "<<*vop<<"\n";

                        //There must be a path from the store to the load
                        if(pop == LPO && checkBlockPairConnectivity(STI->getParent(), LI->getParent())){
                            EV.push_back(vop);
                        }
                    }
                }
                continue;
            }

            GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(TV);
            if(GEP){
                Value* vop = GEP->getPointerOperand();
                EV.push_back(vop);
                continue;
            }

            UnaryInstruction *UI = dyn_cast<UnaryInstruction>(TV);
            if(UI){
                EV.push_back(UI->getOperand(0));
                continue;
            }

            //The return value is a function pointer
            CallInst* CAI = dyn_cast<CallInst>(TV);
            if(CAI){
                //OP<<"comes from call\n";
                //OP<<"func: "<<CAI->getFunction()->getName()<<"\n";
                //OP<<"module: "<<CAI->getModule()->getName()<<"\n";
                //OP<<"global comes from call\n";

                Function *CAIF = CAI->getCalledFunction();
                if(!CAIF)
                    continue;
                string CAIFName = CAIF->getName();
                if(CAIFName.size() == 0)
                    continue;
                //Ctx->Global_Trans_Global_To_Retuen_Map[GV_Name].insert(CAIFName);
                Ctx->Global_Escape_GV_Set.insert(GV_Name);
                continue;
            }
        
        }
    
    }

}

//This function could speed up
//Merge FS2 into FS1
void IcallAnalysisPass::funcSetMerge(FuncSet &FS1, FuncSet &FS2){
	for(auto F : FS2)
		FS1.insert(F);
}

void IcallAnalysisPass::getICallSource(CallInst *CI, map<Value*, SourceFlag> &sourceMap){
    
    Function* F = CI->getFunction();
    set<Value *>argset;
    argset.clear();
    if(F) {
        for(auto it = F->arg_begin(); it != F->arg_end();it++){
            argset.insert(it);
        }
    }

    Value *CV = CI->getCalledOperand();

    std::list<Value *> EV; //BFS record list
    std::set<Value *> PV; //Global value set to avoid loop
    EV.clear();
    PV.clear();
    EV.push_back(CV);

    while (!EV.empty()) {
        Value *TV = EV.front(); //Current checking value
		EV.pop_front();
            
        if (PV.find(TV) != PV.end())
			continue;
        PV.insert(TV);

        auto globalvar = dyn_cast<GlobalValue>(TV);
        if(globalvar){
            //OP<<"global: "<<*TV<<"\n";
            sourceMap[TV] = Global;
            continue;
        }

        if(argset.count(TV) == 1){
            sourceMap[TV] = Argument;
            continue;
        }

        LoadInst* LI = dyn_cast<LoadInst>(TV);
		if(LI){
			Value *LPO = LI->getPointerOperand();
            EV.push_back(LPO);

			//Get all stored values
            for(User *U : LPO->users()){
                StoreInst *STI = dyn_cast<StoreInst>(U);
                if(STI){
                    
                    Value* vop = STI->getValueOperand(); // store vop to pop
                    Value* pop = STI->getPointerOperand();
                    
					//Store constant is not considered
					//if(isConstant(vop))
					//	continue;
                    if(ConstantData *Ct = dyn_cast<ConstantData>(vop))
                        continue;
                    //OP<<"vop: "<<*vop<<"\n";

					//There must be a path from the store to the load
                    if(pop == LPO && checkBlockPairConnectivity(STI->getParent(), LI->getParent())){
                        EV.push_back(vop);
                    }
                }
            }
			continue;
		}

        GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(TV);
        if(GEP){
			Value* vop = GEP->getPointerOperand();
            EV.push_back(vop);
            continue;
		}

        UnaryInstruction *UI = dyn_cast<UnaryInstruction>(TV);
		if(UI){
			EV.push_back(UI->getOperand(0));
			continue;
		}
    
    }
}