#ifndef _ICALL_ANALYSIS_H
#define _ICALL_ANALYSIS_H

#include <llvm/Analysis/BasicAliasAnalysis.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <queue>
#include "../Analyzer.h"
#include "../Tools.h"
#include <fstream>

//Path pairs collection and comparition
class IcallAnalysisPass : public IterativeModulePass {


    //Type info

    private:

        static map<string, set<Function*>> globalFuncInitMap;
		static set<string> globalFuncEscapeSet;
		static DenseMap<size_t, FuncSet> argStoreFuncSet;
		static unordered_map<size_t, set<size_t>>argStoreFuncTransitMap;

        //Define compound basic block structure
        typedef struct DataNode {
            size_t call;
            string global;
            int type = -1;
            //Todo: Add other features and tags

            DataNode(size_t input){
                call = input;
                global = "";
                type = 1;
            }

            DataNode(string input){
                global = input;
                call = 0;
                type = 0;
            }


        } DataNode;

        enum SourceFlag {
		// error returning, mask:0xF
			Global = 1,
			Argument = 2,
			Local = 3,
			Return = 4,
		};

        void findFuncArgStoredCall(CallInst *CI, Value *Arg, unsigned index);
        void findStoreToGlobal(GlobalVariable* GV);
        void resolveGlobalInitializer(GlobalVariable *GV);

        //If we have update, return true
        bool updateGlobalAnalysisTarget();
        void updateGlobalState();
        void updateICallData();
        void funcSetMerge(FuncSet &FS1, FuncSet &FS2);
        int isConnect(DataNode DN1, DataNode DN2);    
        void updateFST(DataNode DN1, DataNode DN2);
        bool isDataEscape(DataNode DN);

        void getICallSource(CallInst *CI, map<Value*, SourceFlag> &sourceMap);


    public:
        IcallAnalysisPass(GlobalContext *Ctx_)
         : IterativeModulePass(Ctx_, "IcallAnalysis") { }
        virtual bool doInitialization(llvm::Module *);
        virtual bool doFinalization(llvm::Module *);
        virtual bool doModulePass(llvm::Module *);

};


#endif
