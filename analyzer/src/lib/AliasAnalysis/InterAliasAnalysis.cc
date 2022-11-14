#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>

#include "AliasAnalysis.h"

void analyzeFunction(Function* F, AliasContext *aliasCtx, GlobalContext *Ctx){

    if(!F)
        return;

    if(aliasCtx->AnalyzedFuncSet.count(F))
        return;

    OP<<"Handle new func: "<<F->getName()<<"\n";

    for (inst_iterator i = inst_begin(F), ei = inst_end(F); i != ei; ++i) {
        Instruction *iInst = dyn_cast<Instruction>(&*i);
        HandleInst(iInst, aliasCtx, Ctx);
    }
    aliasCtx->AnalyzedFuncSet.insert(F);

    //After we've analyzed F, we need to find related globals, calls and args to
    //entend our analysis if necessary


}

void getClusterNodes(AliasNode* startNode, set<AliasNode*> &nodeSet, AliasContext *aliasCtx){

	if(startNode == NULL)
		return;
	
	nodeSet.insert(startNode);

	list<AliasNode *>LN;
	LN.push_back(startNode);
	set<AliasNode *> PN; //Global value set to avoid loop
	PN.clear();

	while (!LN.empty()) {
		AliasNode *CN = LN.front();
		LN.pop_front();

		if (PN.find(CN) != PN.end()){
			continue;
		}
		PN.insert(CN);

		//OP<<"\ncurrent node:\n";
		//CN->print_set();

		if(aliasCtx->ToNodeMap.count(CN)){
			LN.push_back(aliasCtx->ToNodeMap[CN]);
			nodeSet.insert(aliasCtx->ToNodeMap[CN]);
			//OP<<"ToNode: \n";
			//ToNodeMap[CN]->print_set();
		}

		if(aliasCtx->FromNodeMap.count(CN)){
			LN.push_back(aliasCtx->FromNodeMap[CN]);
			nodeSet.insert(aliasCtx->FromNodeMap[CN]);
			//OP<<"FromNode: \n";
			//FromNodeMap[CN]->print_set();
		}
	}
}

void getClusterValues(Value* v, set<Value*> &valueSet, AliasContext *aliasCtx){

    if(v == NULL)
        return;

    AliasNode *n = getNode(v, aliasCtx);
	if(!n){
		//OP<<"empty n\n";
		return;
	}

	//Get the cluster value to enable inter-procedural analysis
	set<AliasNode*> targetNodeSet;
	targetNodeSet.clear();
	getClusterNodes(n, targetNodeSet, aliasCtx);
	
	valueSet.clear();
	for(auto it = targetNodeSet.begin(); it != targetNodeSet.end(); it++){
		AliasNode *n = *it;
		//n->print_set();
		valueSetMerge(valueSet, n->aliasclass);
	}
}


void interCaseHandler(Value* aliased_v, list<Value *>&LV, 
    set<Value *>Analyzed_Set, AliasContext *aliasCtx, GlobalContext *Ctx){


    if(aliased_v == NULL)
        return;

    if (isa<ConstantData>(aliased_v)){
        return;
    }

    OP<<"aliased_v: "<<*aliased_v<<"\n";

    //The aliased value is a function
    //Filter this case from checking GlobalValue
    Function *F = dyn_cast<Function>(aliased_v);
    if(F){
        //OP<<"F: "<<*F<<"\n";
        //return;

        if(!F->isDeclaration()){
            return;
        }

        //F is a function declare
        StringRef FName = F->getName();

        //F has definition
        if(Ctx->GlobalFuncs.count(FName.str())){
            return;
        }

        //Here F has no global definition
        aliasCtx->Is_Analyze_Success = false;
        return;


        auto GID = F->getGUID();
        for(auto it = Ctx->Global_Unique_GV_Map[GID].begin(); it != Ctx->Global_Unique_GV_Map[GID].end(); it++){
            GlobalValue* Global_Value = *it;
            Function* f = dyn_cast<Function>(Global_Value);
            if(!f)
                continue;

            if(f != F){
                HandleMove(f, F, aliasCtx);
            }
            
            //OP<<"aliased f: "<<*f<<"\n";
            //Use BFS to execute use-chain check
            list<User *>LU;
            set<User *> GU; //Global value set to avoid loop
            for(User *U : f->users()){
                LU.push_back(U);
            }

            while (!LU.empty()) {
                User *U = LU.front();
                LU.pop_front();

                if (GU.find(U) != GU.end()){
                    continue;
                }
                GU.insert(U);

                Instruction *iInst = dyn_cast<Instruction>(U);
                if(iInst){
                    //OP<<"is instruction\n";
                    Function* icaller = iInst->getFunction();
                    analyzeFunction(icaller, aliasCtx, Ctx);
                    continue;
                }

                GEPOperator *GEPO = dyn_cast<GEPOperator>(U);
                BitCastOperator *CastO = dyn_cast<BitCastOperator>(U);
                PtrToIntOperator *PTIO = dyn_cast<PtrToIntOperator>(U);
                ConstantAggregate *CA = dyn_cast<ConstantAggregate>(U);
                
                if(GEPO || CastO || PTIO || CA){
                    for(User *u : U->users()){
                        LU.push_back(u);
                    }
                    continue;
                }

                GlobalVariable* Gv = dyn_cast<GlobalVariable>(U);
                if(Gv){
                    LV.push_back(U);
                    continue;
                }

                OP<<"WARNNING: unsupported user: "<<*U<<"\n";
                
            }

            //Now the graph has been extened, update analysis targets
            set<Value*> Covered_value_Set;
            Covered_value_Set.clear();
            valueSetMerge(Covered_value_Set, Analyzed_Set);
            for(auto it = LV.begin(); it != LV.end(); it++){
                Covered_value_Set.insert(*it);
            }

            set<Value*> targetValueSet;
	        getClusterValues(aliased_v, targetValueSet, aliasCtx);
            for(auto it = targetValueSet.begin(); it != targetValueSet.end(); it++){
                Value* target_v = *it;
                if(Covered_value_Set.count(target_v))
                    continue;
                
                LV.push_back(target_v);
            }

            if(LV.size() > MAX_ANALYSIS_NUM){
                aliasCtx->Is_Analyze_Success = false;
                break;
            }

            Analyzed_Set.insert(Global_Value);

        }
        return;
    }

    //OP<<"aliased_v: "<<*aliased_v<<"\n";

    Instruction* I = dyn_cast<Instruction>(aliased_v);
    if(I){
        auto opcodeName = I->getOpcodeName();
        if(Ctx->BinaryOperandInsts.count(opcodeName)){
            aliasCtx->Is_Analyze_Success = false;
            return;
        }
    }
    

    //The aliased value is the argument of some callee functions
    for(User *aliased_U : aliased_v->users()){

        if(aliased_U == aliased_v)
            continue;

        CallInst *cai = dyn_cast<CallInst>(aliased_U);
        if(!cai)
            continue;
        
        //check if aliased_v is cai's arg
        bool is_arg = false;
        unsigned argnum = cai->getNumArgOperands();
         for(unsigned j = 0; j < argnum; j++){
            Value* cai_arg = cai->getArgOperand(j);
            if(cai_arg == aliased_U){
                is_arg = true;
                break;
            }
        }
        if(!is_arg)
            continue;
        
        if(!Ctx->Callees.count(cai))
            continue;

        for(Function *f : Ctx->Callees[cai]){

            HandleReturn(f, cai, aliasCtx);

            //OP<<"Used in func: "<<f->getName()<<"\n";

            analyzeFunction(f, aliasCtx, Ctx);

            //f's caller is cai, so we do not need to analysis its args in the futhure
            vector<Value *>f_arg_vec;
            f_arg_vec.clear();
            for(auto it = f->arg_begin(); it != f->arg_end(); it++){
                f_arg_vec.push_back(it);
                Analyzed_Set.insert(it);
            }

            auto f_arg_size = f->arg_size();
            unsigned min_num = getMin(f_arg_size, argnum);
            for(unsigned j = 0; j < min_num; j++){
                Value* cai_arg = cai->getArgOperand(j);
                HandleMove(cai_arg, f_arg_vec[j], aliasCtx);
                //OP<<"move handled\n";
            }

            //Now the graph has been extened, update analysis targets
            set<Value*> Covered_value_Set;
            Covered_value_Set.clear();
            valueSetMerge(Covered_value_Set, Analyzed_Set);
            for(auto it = LV.begin(); it != LV.end(); it++){
                Covered_value_Set.insert(*it);
            }

            set<Value*> targetValueSet;
	        getClusterValues(aliased_v, targetValueSet, aliasCtx);
            for(auto it = targetValueSet.begin(); it != targetValueSet.end(); it++){
                Value* target_v = *it;
                if(Covered_value_Set.count(target_v))
                    continue;
                
                LV.push_back(target_v);
            }

            if(LV.size() > MAX_ANALYSIS_NUM){
                aliasCtx->Is_Analyze_Success = false;
                break;
            }

        }
        Analyzed_Set.insert(aliased_U);
    }

    //The aliased value is a non-func global variable
    GlobalVariable* GV = dyn_cast<GlobalVariable>(aliased_v);
    if(GV){
        //OP<<"is global\n";

        if(GV->getName() == "llvm.used")
            return;

        //Get all global uses of GV
        auto GID = GV->getGUID();
        for(auto it = Ctx->Global_Unique_GV_Map[GID].begin(); it != Ctx->Global_Unique_GV_Map[GID].end(); it++){
            GlobalValue* Global_Value = *it;
            GlobalVariable* Global_GV = dyn_cast<GlobalVariable>(Global_Value);
            if(!Global_GV)
                continue;
            //OP<<"\nUse in Global_GV: "<<*Global_GV<<"\n";
            //OP<<"Global_GV Ty: "<<*Global_GV->getType()<<"\n";

            //Globals in different modules are aliased with each other
            if(Global_GV != GV){
                HandleMove(Global_GV, GV, aliasCtx);
            }

            //First check the Initializer of the GV
            if(Global_GV->hasInitializer()){
                //TODO: resolve initializer
                analyzeGlobalInitializer(Global_GV, LV, aliasCtx);
            }

            //Use BFS to execute use-chain check
            list<User *>LU;
            set<User *> GU; //Global value set to avoid loop
            for(User *U : Global_GV->users()){
                LU.push_back(U);
            }

            while (!LU.empty()) {
                User *U = LU.front();
                LU.pop_front();

                if (GU.find(U) != GU.end()){
                    continue;
                }
                GU.insert(U);

                Instruction *iInst = dyn_cast<Instruction>(U);
                if(iInst){
                    //OP<<"is instruction\n";
                    Function* icaller = iInst->getFunction();
                    analyzeFunction(icaller, aliasCtx, Ctx);
                    continue;
                }

                GEPOperator *GEPO = dyn_cast<GEPOperator>(U);
                BitCastOperator *CastO = dyn_cast<BitCastOperator>(U);
                PtrToIntOperator *PTIO = dyn_cast<PtrToIntOperator>(U);
                
                if(GEPO || CastO || PTIO ){
                    for(User *u : U->users()){
                        LU.push_back(u);
                    }
                    continue;
                }

                GlobalVariable* Gv = dyn_cast<GlobalVariable>(U);
                if(Gv){
                    LV.push_back(U);
                    continue;
                }

                ConstantAggregate *CA = dyn_cast<ConstantAggregate>(U);
                if(CA){
                    for(User *u : U->users()){
                        //OP<<"u: "<<*u<<"\n";
                        LU.push_back(u);
                    }
                    continue;
                }

                OP<<"WARNNING: unsupported user: "<<*U<<"\n";
                
            }

            //Now the graph has been extened, update analysis targets
            set<Value*> Covered_value_Set;
            Covered_value_Set.clear();
            valueSetMerge(Covered_value_Set, Analyzed_Set);
            for(auto it = LV.begin(); it != LV.end(); it++){
                Covered_value_Set.insert(*it);
            }

            set<Value*> targetValueSet;
	        getClusterValues(aliased_v, targetValueSet, aliasCtx);
            for(auto it = targetValueSet.begin(); it != targetValueSet.end(); it++){
                Value* target_v = *it;
                if(Covered_value_Set.count(target_v))
                    continue;
                
                LV.push_back(target_v);
            }

            if(LV.size() > MAX_ANALYSIS_NUM){
                aliasCtx->Is_Analyze_Success = false;
                break;
            }

            Analyzed_Set.insert(Global_GV);
        }
        return;
    }

    //The aliased value is a return value of a call
    CallInst *CAI = dyn_cast<CallInst>(aliased_v);
    if(CAI){

        //OP<<"from call: "<<*CAI<<"\n";

        //Ignore the return value of alloc functions
        StringRef FName = getCalledFuncName(CAI);
        if(Ctx->HeapAllocFuncs.count(FName))
            return;

        if(!Ctx->Callees.count(CAI))
            return;
        
        unsigned argnum = CAI->getNumArgOperands();

        for(Function *f : Ctx->Callees[CAI]){
            HandleReturn(f, CAI, aliasCtx);

            analyzeFunction(f, aliasCtx, Ctx);

            //f's caller is CAI, so we do not need to analysis its args in the futhure
            vector<Value *>f_arg_vec;
            f_arg_vec.clear();
            for(auto it = f->arg_begin(); it != f->arg_end(); it++){
                f_arg_vec.push_back(it);
                Analyzed_Set.insert(it);
            }

            auto f_arg_size = f->arg_size();
            unsigned min_num = getMin(f_arg_size, argnum);
            for(unsigned j = 0; j < min_num; j++){
                Value* CAI_arg = CAI->getArgOperand(j);
                HandleMove(CAI_arg, f_arg_vec[j], aliasCtx);
                //OP<<"move handled\n";
            }

            //Now the graph has been extened, update analysis targets
            set<Value*> Covered_value_Set;
            Covered_value_Set.clear();
            valueSetMerge(Covered_value_Set, Analyzed_Set);
            for(auto it = LV.begin(); it != LV.end(); it++){
                Covered_value_Set.insert(*it);
            }

            set<Value*> targetValueSet;
	        getClusterValues(aliased_v, targetValueSet, aliasCtx);
            for(auto it = targetValueSet.begin(); it != targetValueSet.end(); it++){
                Value* target_v = *it;
                if(Covered_value_Set.count(target_v))
                    continue;
                
                LV.push_back(target_v);
            }

            if(LV.size() > MAX_ANALYSIS_NUM){
                aliasCtx->Is_Analyze_Success = false;
                break;
            }

        }

        return;
    }

    //The aliased value is the argument of some caller functions
    Argument *arg = dyn_cast<Argument>(aliased_v);
    if(arg){
        //OP<<"is arg: "<<*arg<<"\n";
        Function* caller = arg->getParent();
        if(!caller)
            return;
        
        auto caller_arg_size = caller->arg_size();
        
        //OP<<"caller: "<<caller->getName()<<"\n";
        if(!Ctx->Callers.count(caller))
            return;

        unsigned arg_index = getArgIndex(caller, arg);

        vector<Value *>caller_arg_vec;
        caller_arg_vec.clear();
        for(auto it = caller->arg_begin(); it != caller->arg_end(); it++){
            caller_arg_vec.push_back(it);
        }

        CallInstSet callset = Ctx->Callers[caller];

        for(auto it = callset.begin(); it != callset.end(); it++){
            CallInst* cai = *it;
            //OP<<"caller cai: "<<*cai<<"\n";
            unsigned argnum = cai->getNumArgOperands();
            unsigned min_num = getMin(caller_arg_size, argnum);
            for(unsigned j = 0; j < min_num; j++){
            
                Value* cai_arg = cai->getArgOperand(j);
                HandleMove(cai_arg, caller_arg_vec[j], aliasCtx);
                //OP<<"move handled\n";
            }

            //OP<<"here\n";

            Function* cai_parent = cai->getFunction();
            //OP<<"cai_parent: "<<*cai_parent<<"\n";
            analyzeFunction(cai_parent, aliasCtx, Ctx);

            //Now the graph has been extened, update analysis targets
            set<Value*> Covered_value_Set;
            Covered_value_Set.clear();
            valueSetMerge(Covered_value_Set, Analyzed_Set);
            for(auto it = LV.begin(); it != LV.end(); it++){
                Covered_value_Set.insert(*it);
            }

            set<Value*> targetValueSet;
	        getClusterValues(aliased_v, targetValueSet, aliasCtx);
            for(auto it = targetValueSet.begin(); it != targetValueSet.end(); it++){
                Value* target_v = *it;
                if(Covered_value_Set.count(target_v))
                    continue;
                
                LV.push_back(target_v);
            }

            if(LV.size() > MAX_ANALYSIS_NUM){
                aliasCtx->Is_Analyze_Success = false;
                break;
            }
        }

        return;
    }

}

void analyzeGlobalInitializer(GlobalVariable* GV, list<Value *>&Future_analysis_list,
    AliasContext *aliasCtx){

    //OP<<"\ncheck initializer: "<<GV->getName()<<"\n";

    Constant *Ini = GV->getInitializer();
	if (!isa<ConstantAggregate>(Ini))
		return;
    
    HandleMove(Ini, GV, aliasCtx);
    
    list<User *>LU;
	LU.push_back(Ini);
	set<User *> PB; //Global value set to avoid loop
	PB.clear();

	//should consider global struct array
	while (!LU.empty()) {
		User *U = LU.front();
		LU.pop_front();

		if (PB.find(U) != PB.end()){
			continue;
		}
		PB.insert(U);

        //OP<<"Global U: "<<*U<<"\n";
        for (auto oi = U->op_begin(), oe = U->op_end(); oi != oe; ++oi) {
			Value *O = *oi;
            //OP<<"O: "<<*O<<"\n";
            HandleStore(O, U, aliasCtx);

            GlobalVariable* inner_GV = dyn_cast<GlobalVariable>(O);
            if(inner_GV){
                Future_analysis_list.push_back(inner_GV);
            }

            GEPOperator *GEPO = dyn_cast<GEPOperator>(O);
            BitCastOperator *CastO = dyn_cast<BitCastOperator>(O);
            PtrToIntOperator *PTIO = dyn_cast<PtrToIntOperator>(O);
            
            if(GEPO || CastO || PTIO ){
                //OP<<"handle operator\n";
                HandleOperator(O, aliasCtx);
            }

            Type *OTy = O->getType();
            if(isCompositeType(OTy)){
                User *OU = dyn_cast<User>(O);
				LU.push_back(OU);
            }


        }
    }
}

void FuncinterCaseHandler(Value* aliased_v, list<Value *> &LV, set<Value *>Analyzed_Set, 
     AliasContext *aliasCtx, GlobalContext *Ctx){

    if(aliased_v == NULL)
        return;

    if (isa<ConstantData>(aliased_v)){
        return;
    }

    //


}