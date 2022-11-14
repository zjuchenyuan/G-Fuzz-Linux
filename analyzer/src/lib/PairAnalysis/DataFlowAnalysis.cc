#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Dominators.h>

#include <unistd.h>
#include <thread>
#include <mutex>
#include <omp.h>

#include "PairAnalysis.h"

using namespace llvm;


void PairAnalysisPass::checkStructFuncField(Module *M){

    for (Function &F : *M) { 
        if (F.hasAddressTaken()) {
			//OP<<"address taken f: "<<F.getName()<<"\n";
		}
        if(F.getName()!= "platform_legacy_resume")
            continue;
        
        for (inst_iterator i = inst_begin(F), ei = inst_end(F); i != ei; ++i) {
            Instruction *iInst = dyn_cast<Instruction>(&*i);
            if (BitCastInst *BCI = dyn_cast<BitCastInst>(iInst)){
                OP<<"BCI: "<<*BCI<<"\n";
                Type * srcty = BCI->getSrcTy();
                OP<<"src type: "<<*srcty<<"\n";
                Type * destty = BCI->getDestTy();
                OP<<"dest type: "<<*destty<<"\n";
                OP<<"test: "<<*BCI->getOperand(0)<<"\n";
            }
        }
        
    }

    for (auto v = M->global_begin(); v != M->global_end(); ++v){
		
        GlobalVariable *V = &*v;
        Type *V_type = V->getType();
        if(V->hasInitializer()){
            Constant* C = V->getInitializer();

            if(C->getType()->isStructTy()){
                ConstantStruct *CS = dyn_cast<ConstantStruct>(C);
                if(!CS){
                    continue;
                }
                
                unsigned opnum = C->getNumOperands();
                int function_pointer_num = 0;
		        for(auto i = 0; i< opnum; i++){
                    Value* field = CS->getOperand(i);
                    if(field->getType()->isPointerTy()){
                        //OP<<"is pointer\n";
                        //OP<<*field<<"\n\n";
                        Function* field_F = dyn_cast<Function>(field);
                        if(field_F) {
                            function_pointer_num++;
                        }
                    }
                }
                if (function_pointer_num < 2)
                    continue;

                /*for (auto oi = C->op_begin(), oe = C->op_end(); oi != oe; oi++){
                    Value *O = *oi;
                    Type *OTy = O->getType();
                    unsigned ONo = oi->getOperandNo();
                    if (Function *F = dyn_cast<Function>(O)) {
                        OP<<"num: "<<ONo <<  " O: "<<F->getName()<<"\n";
                    }
                    else
                        OP<<"num: "<<ONo <<" O: "<<*O<<"\n";
                }*/
                
                set<string> sourceSet = get_global_source(V);
                if(sourceSet.empty())
                    continue;
                
                for(auto i = 0; i< opnum; i++){
                    Value* field = CS->getOperand(i);
                    if(field->getType()->isPointerTy()){
                        //OP<<"is pointer\n";
                        //OP<<*field<<"\n\n";
                        Function* field_F = dyn_cast<Function>(field);
                        if(field_F) {
                            keywords_statistics(sourceSet, field_F);
                        }
                    }
                }
            }
        }
    
    }

}

//Find the pair function through the module_exit function
//One module only has one such pair
void PairAnalysisPass::checkExitFunc(Module *M){

    set<Function*> module_function_set;
    module_function_set.clear();
    for(Module::iterator f = M->begin(), fe = M->end();	f != fe; ++f){
        Function *F = &*f;

        if(F->empty())
            continue;
        
        module_function_set.insert(F);
    }

    
    for (auto v = M->global_begin(); v != M->global_end(); ++v){
		GlobalVariable *V = &*v;

        //OP<<"V: "<<*V<<"\n\n";
        string V_name = getValueName(V);
        if(!checkStringContainSubString(V_name,"@__exitcall")){
            continue;
        }
        
        //No we found the exit function in module_exit()
        //exit func has a function pointer initializer
        if(V->hasInitializer()){
            Constant* C = V->getInitializer();
            Function* exit_func = dyn_cast<Function>(C);
            if(exit_func){
                //Found the exit function
                //Then check if it is related to a macro
                StringRef Exit_FName = exit_func->getName();
                //OP<<"F name: "<<FName<<"\n";
                //printSourceCodeInfo(exit_F);
                string src_code = getSourceLine(exit_func);
                
                //If source code contains FName, this is case：
                //Use module_init and module_exit function pair
                //The function pair is defined by developer
                int pairtype = 0;
                if(checkStringContainSubString(src_code,Exit_FName)){
                    pairtype = MODULE_FUNC;
                }

                //Also use module_init and module_exit, but with a macro wrapper
                //The function pair is usually defined in a structure
                else{
                    pairtype = MODULE_FUNC_WRAPPER;
                    string src_code = getSourceLine(exit_func);
                    Ctx->Global_Debug_Message_Set.insert(src_code);
                }
                
                //OP<<"exit func: "<<Exit_FName<<"\n";
                string asm_str = M->getModuleInlineAsm();
                //OP<<"asm: "<<asm_str<<"\n";
                if(!checkStringContainSubString(asm_str,"__initcall")){
                    continue;
                }

                //The target call is inside the asm string line with "__initcall"
                string target_macro = get_init_macro_line(asm_str);
                if(target_macro.length() == 0)
                    continue;

                //If there are multipul inits, choose the func with the longest name
                set<Function*> init_set;
                init_set.clear();

                for(Module::iterator f = M->begin(), fe = M->end();	f != fe; ++f){
                    Function *F = &*f;

                    if(F->empty())
                        continue;
                        
                    auto FName = F->getName();
                    if(checkStringContainSubString(target_macro,FName)){

                        //Both init and fini functions have been found
                        init_set.insert(F);
                    }
                }

                if(init_set.empty())
                    continue;
                    
                Function* init_func = get_func_with_longest_name(init_set);
                PairInfo pairinfo(init_func,exit_func,pairtype);
                Ctx->Global_Func_Pair_Set.insert(pairinfo);

            }
        }


    }

    //dataPrint();

}


