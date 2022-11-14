#ifndef _GLOBAL_TOOLS_H
#define _GLOBAL_TOOLS_H

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
#include <llvm/Analysis/BasicAliasAnalysis.h>

#include "Analyzer.h"
#include "Common.h"
#include "Config.h"
#include "CallGraph/CallGraph.h"
#include <algorithm>

//Used for debug
std::string getBlockName(BasicBlock *bb);

//Used for debug
std::string getValueName(Value* V);

//Used for debug
std::string getValueContent(Value* V);

//Used for debug
std::string getInstFilename(Instruction *I);

//Used for debug
unsigned getInstLineNo(Instruction *I);

//Used for debug
unsigned getInstLineNo(Function *F);

//Used for debug
void printInstMessage(Instruction *inst);

//Used for debug
void printBlockMessage(BasicBlock *bb);

//Used for debug
void printBlockLineNoRange(BasicBlock *bb);

//Used for debug
void printFunctionMessage(Function *F);

//Check if there exits common element of two sets
bool findCommonOfSet(std::set<Value *> setA, std::set<Value *> setB);
bool findCommonOfSet(std::set<std::string> setA, std::set<std::string> setB);

// Check alias result of two values.
bool checkAlias(Value *, Value *, PointerAnalysisMap &);

bool checkStringContainSubString(string origstr, string targetsubstr);

//Check if there is a path from fromBB to toBB 
bool checkBlockPairConnectivity(BasicBlock* fromBB, BasicBlock* toBB);

/////////////////////////////////////////////////
//    ICall identification methods
/////////////////////////////////////////////////

bool isCompositeType(Type *Ty);

bool isStructorArrayType(Type *Ty);

//Check if two types are equal (for compond type)
bool checkTypeEuqal_old(Type* Ty1, Type* Ty2);

/////////////////////////////////////////////////
//    Data recording methods
/////////////////////////////////////////////////

//Used for data recording of pair functions
void pairFuncDataRecord(GlobalContext *Ctx);

//Used for debug
void messageRecord(GlobalContext *Ctx);

//Used for data recording of structure keywords
void keywordsRecord(GlobalContext *Ctx);

//Used for global call graph debug
void icallTargetResult(GlobalContext *Ctx);

//Calculate a unique hash for a function pointer
size_t funcInfoHash(Function *F);

void RecordCFG(GlobalContext *Ctx);
void DumpFunctions(GlobalContext *Ctx);
#endif