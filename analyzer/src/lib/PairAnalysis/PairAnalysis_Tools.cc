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
#include <algorithm>

#include "PairAnalysis.h"

using namespace llvm;



//Used for debug
void PairAnalysisPass::dataPrint(){

    if(Ctx->Global_Func_Pair_Set.empty())
        return;

    for(auto it = Ctx->Global_Func_Pair_Set.begin(); it != Ctx->Global_Func_Pair_Set.end(); it++){

        PairInfo funcpair = *it;
        Function* initfunc = funcpair.initfunc;
        Function* finifunc = funcpair.finifunc;

        OP<<initfunc->getName() << " - "<< finifunc->getName() <<"\n";
    }

}

//Get the macro line with __initcall
std::string PairAnalysisPass::get_init_macro_line(string macro_str){

    if(macro_str.length() == 0)
        return "";

    if(!checkStringContainSubString(macro_str,"__initcall"))
        return "";

    string line = "";
    string target = "__initcall";

    int index = macro_str.find(target);
    //OP<<"index: "<<index<<"\n";

    line = macro_str.substr(index, 100);

    return line;
}

//Get the function with the longest name
Function* PairAnalysisPass::get_func_with_longest_name(set<Function*> funcset){

    if(funcset.empty())
        return NULL;
    
    Function* longest = NULL;
    for(auto it = funcset.begin(); it!= funcset.end(); it++){
        
        Function* F = *it;
        StringRef FName = F->getName();

        if(longest == NULL)
            longest = F;
        
        StringRef longestName = longest->getName();
        if(longestName.size() < FName.size())
            longest = F;
    }

    return longest;
}


//Get the line number of a global variable
int PairAnalysisPass::get_global_line_number(GlobalVariable* G){

    if(!G)
        return 0;
    
    MDNode *N = G->getMetadata("dbg");
    if (!N) {
        OP<<"here\n";
        return 0;
    }

    DIGlobalVariableExpression *DIGVE = dyn_cast<DIGlobalVariableExpression>(N);
    if (!DIGVE ){
        OP<<"here2\n";
        return 0;
    }

    DIGlobalVariable *DGV = DIGVE->getVariable();
    if(!DGV)
        return 0;

    return DGV->getLine();
}

//Get the line number of a global variable
set<string> PairAnalysisPass::get_global_source(GlobalVariable* G){

    set<string> sourceSet;
    sourceSet.clear();

    if(!G)
        return sourceSet;
    
    MDNode *N = G->getMetadata("dbg");
    if (!N) {
        return sourceSet;
    }

    DIGlobalVariableExpression *DIGVE = dyn_cast<DIGlobalVariableExpression>(N);
    if (!DIGVE ){
        return sourceSet;
    }

    DIGlobalVariable *DGV = DIGVE->getVariable();
    if(!DGV)
        return sourceSet;

    int startline = DGV->getLine();
    if(startline == 0)
        return sourceSet;
    
    string FN = getFileName(NULL, NULL, DGV);
    string line = getSourceLine(FN, startline);

    int line_len = line.size();
	if(line_len == 0)
		return sourceSet;
    
    if(!checkStringContainSubString(line, "struct"))
        return sourceSet;
	
	//解决指令跨行的问题
	auto lastchar = line.at(line.size()-1);
    //OP<<line<<"\n";
	//while(lastchar == ',' || lastchar == '('){
	while(lastchar != ';'){
        //OP<<line<<"\n";
        sourceSet.insert(line);
        line = getSourceLine(FN, ++startline);
        if(line.size() == 0) 
            continue;
		lastchar = line.at(line.size()-1);
	}
    //OP<<line<<"\n";
    sourceSet.insert(line);

    return sourceSet;

}

void PairAnalysisPass::keywords_statistics(set<string> structstr, Function* F){

    //Extract the keywords
    if(structstr.empty() || !F)
        return;

    auto FName = F->getName();
    if(FName.size() == 0)
        return;
    
    for(auto it = structstr.begin(); it != structstr.end(); it++){
        string linestr = *it;
        //OP<<linestr<<"\n";
        //OP <<FName<<"\n";

        if(!checkStringContainSubString(linestr, FName))
            continue;
        //OP<<"line: "<< linestr<<"\n";
        //The keyword starts with '.' and end with ' ' or '\t'
        int start_point = linestr.find(".");
        string substr = linestr.substr(start_point+1, linestr.size()-1);
        int end_point1 = substr.find(" ");
        int end_point2 = substr.find("\t");
        int end_point;
        if(end_point1<0 && end_point2 <0){
            continue;
        }
        else if(end_point1 < 0)
            end_point = end_point2;
        else if(end_point2 < 0)
            end_point = end_point1;
        else
            end_point = min(end_point1, end_point2);
        string keyword = substr.substr(0, end_point);

        //OP<<"keyword: "<<keyword<<"\n";
        if(keyword.size() == 0)
            continue;

        Ctx->Global_Keywords_Map[keyword]++;
    }
}

//statistics of container_of method
void PairAnalysisPass::container_of_statistics(Module *M){

    for(Module::iterator f = M->begin(), fe = M->end();	f != fe; ++f){
        Function *F = &*f;

        if(F->empty())
            continue;
        
        for (inst_iterator i = inst_begin(F), ei = inst_end(F); i != ei; ++i) {
            Instruction *iInst = dyn_cast<Instruction>(&*i);
            GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(iInst);
            if(GEP){
                auto numindices = GEP->getNumIndices();
                if(numindices == 0)
                    continue;

                Value* first_indice = GEP->getOperand(1);
                //OP<<"GEP: "<<*GEP<<"\n";
                //OP<<"indice: "<<*first_indice<<"\n";
                ConstantInt *Ct = dyn_cast<ConstantInt>(first_indice);
                if(Ct){
                    if(Ct->isMinusOne()) {
                        //Found the target
                        string src = getSourceLine(GEP);
                        //OP<<src<<"\n";
                        ofstream oFile;
                        oFile.open("container_of.txt", ios::app);

                        oFile << src<<"\n";
                            
                        oFile.close();
                    }
                }
            }
        }
    }
}