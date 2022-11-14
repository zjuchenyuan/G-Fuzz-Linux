#ifndef _PAIR_ANALYSIS_H
#define _PAIR_ANALYSIS_H

#include <llvm/Analysis/BasicAliasAnalysis.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <queue>
#include "../Analyzer.h"
#include "../Tools.h"
#include <fstream>

#define USE_RECURSION 0

//Path pairs collection and comparition
class PairAnalysisPass : public IterativeModulePass {


    typedef std::pair<Instruction *, BasicBlock *> CFGEdge;
    typedef std::pair<CFGEdge, Value *> EdgeValue;

    //<1:ignore  >=1: not ignore
    //Use int rather than bool, int is used to record 
    //block num in path in recurMarkComplexIfEdgeMap
    typedef std::map<CFGEdge, int> EdgeIgnoreMap;
    
    typedef std::pair<BasicBlock*, BasicBlock*> Blockpair;
    typedef std::map<Blockpair, bool> ConnectGraph;

    private:
    
        //Todo: Add functino here

        // Pattern 1:
        // Use module_platform_driver or moudule_init & module_exit
        // There will be an structurename_init and structurename_fini function pair

        void checkExitFunc(Module *M);

        //Find pair funcs defined as global struct member
        void checkStructFuncField(Module *M);




        //////////////////////////////////////////////////////
        //Tool functions
        //////////////////////////////////////////////////////

        //Used for debug
        void dataPrint();

        //Get the macro line with __initcall
        std::string get_init_macro_line(string macro_str);

        //Get the function with the longest name
        Function* get_func_with_longest_name(set<Function*> funcset);

        //Get the line number of a global variable
        int get_global_line_number(GlobalVariable* G);

        //Get the line number of a global variable
        set<string> get_global_source(GlobalVariable* G);

        //statistics of structure field function keywords
        void keywords_statistics(set<string> structstr, Function* F);

        //statistics of container_of method
        void container_of_statistics(Module *M);

    public:
        PairAnalysisPass(GlobalContext *Ctx_)
         : IterativeModulePass(Ctx_, "PairAnalysis") { }
        virtual bool doInitialization(llvm::Module *);
        virtual bool doFinalization(llvm::Module *);
        virtual bool doModulePass(llvm::Module *);
        
        virtual void run(ModuleList &modules);

};


#endif
