#include "Tools.h"

//Used for debug
unsigned getInstLineNo(Instruction *I){

    begin:

    if(!I){
        //OP << "No such Inst\n";
        return 0;
    }
        
    //DILocation *Loc = dyn_cast<DILocation>(N);
    DILocation *Loc = I->getDebugLoc();
    if (!Loc ){
        //OP << "No such DILocation\n";
        auto nextinst = I->getNextNonDebugInstruction();
        I = nextinst;
		//return 0;
        goto begin;
    }

    unsigned Number = Loc->getLine();
    //Loc->getFilename();
    //Loc->getDirectory();

    if(Number < 1){
        //OP << "Number < 1\n";
        auto nextinst = I->getNextNonDebugInstruction();
        I = nextinst;
        goto begin;
    }

    return Number;
}

DISubprogram* getInstLineNo_Loc(Function *F){
    if(!F){
        //OP << "No such Inst\n";
        return 0;
    }

    //DILocation *Loc = dyn_cast<DILocation>(N);
    MDNode *N = F->getMetadata("dbg");
    
    if (!N) {
        //OP << "no dbg metadata\n";
        return 0;
    }

    //DILocation *Loc = F->getDebugLoc();
    DISubprogram *Loc = dyn_cast<DISubprogram>(N);
    if (!Loc ){
        //OP << "No such Loc\n";
		return 0;
    }
    return Loc;
}

//Used for debug
unsigned getInstLineNo(Function *F){
    DISubprogram* Loc = getInstLineNo_Loc(F);
    if(!Loc) return 0;
    unsigned Number = Loc->getLine();
    //Loc->getFilename();
    //Loc->getDirectory();

    return Number;
}


//Used for debug
std::string getInstFilename(Instruction *I){
    begin:

    if(!I){
        //OP << "No such Inst\n";
        return "";
    }
        
    //DILocation *Loc = dyn_cast<DILocation>(N);
    DILocation *Loc = I->getDebugLoc();
    if (!Loc ){
        //OP << "No such DILocation\n";
        auto nextinst = I->getNextNonDebugInstruction();
        I = nextinst;
		//return 0;
        goto begin;
    }

    string Filename = Loc->getFilename();
    //Loc->getFilename();
    //Loc->getDirectory();

    if(Filename.length() == 0){
        //OP << "Number < 1\n";
        auto nextinst = I->getNextNonDebugInstruction();
        I = nextinst;
        goto begin;
    }

    return Filename;
}

//Used for debug
string getBlockName(BasicBlock *bb){
    if(bb == NULL)
        return "NULL block";
    std::string Str;
    raw_string_ostream OS(Str);
    bb->printAsOperand(OS,false);
    return OS.str();
}

//Used for debug
string getValueName(Value* V){
    std::string Str;
    raw_string_ostream OS(Str);
    V->printAsOperand(OS,false);
    return OS.str();
}

//Used for debug
std::string getValueContent(Value* V){
    std::string Str;
    raw_string_ostream OS(Str);
    V->print(OS,false);
    return OS.str();
}

//Used for debug
void printInstMessage(Instruction *inst){
    if(!inst){
        OP << "No such instruction";
        return;
    }
        
    MDNode *N = inst->getMetadata("dbg");

    if (!N)
        return;
    
    DILocation *Loc = dyn_cast<DILocation>(N);
    string SCheckFileName = Loc->getFilename().str();
    unsigned SCheckLineNo = Loc->getLine();
    //OP << "Filename: "<<SCheckFileName<<"\n";
    OP << "LineNo: " << SCheckLineNo<<"\n";

}

//Used for debug
void printBlockMessage(BasicBlock *bb){

    if(!bb){
        OP << "No such block";
        return;
    }
    
    auto begininst = dyn_cast<Instruction>(bb->begin());
    auto endinst = bb->getTerminator();

    OP << "\nBegin at --- ";
    printInstMessage(begininst);
    OP << "End   at --- ";
    printInstMessage(endinst);

    /* for(BasicBlock::iterator i = bb->begin(); 
        i != bb->end(); i++){

        auto midinst = dyn_cast<Instruction>(i);
        printInstMessage(midinst);        
    } */

}

//Used for debug
void printBlockLineNoRange(BasicBlock *bb){
    if(!bb){
        OP << "No such block";
        return;
    }
    
    auto begininst = dyn_cast<Instruction>(bb->begin());
    auto endinst = bb->getTerminator();

    OP << "("<<getInstLineNo(begininst)<<"-"<<getInstLineNo(endinst)<<")";

}

//Used for debug
void printFunctionMessage(Function *F){

    if(!F)
        return;
    
    for(Function::iterator b = F->begin(); 
        b != F->end(); b++){
        
        BasicBlock * bb = &*b;
        OP << "\nCurrent block: block-"<<getBlockName(bb)<<"\n";
        //printBlockMessage(bb);

        OP << "Succ block: \n";
        for (BasicBlock *Succ : successors(bb)) {
			//printBlockMessage(Succ);
            OP << " block-"<<getBlockName(Succ)<<" ";
		}

        OP<< "\n";
    }
}

//Check if there exits common element of two sets
bool findCommonOfSet(set<Value *> setA, set<Value *> setB){
    if(setA.empty() || setB.empty())
        return false;
    
    bool foundtag = false;
    for(auto i = setA.begin(); i != setA.end(); i++){
        Value * vi = *i;
        for(auto j = setB.begin(); j != setB.end(); j++){
            Value * vj = *j;
            if(vi == vj){
                foundtag = true;
                return foundtag;
            }
        }
    }

    return foundtag;
}

bool findCommonOfSet(set<std::string> setA, set<std::string> setB){
    if(setA.empty() || setB.empty())
        return false;
    
    bool foundtag = false;
    for(auto i = setA.begin(); i != setA.end(); i++){
        string vi = *i;
        for(auto j = setB.begin(); j != setB.end(); j++){
            string vj = *j;
            if(vi == vj){
                foundtag = true;
                return foundtag;
            }
        }
    }

    return foundtag;
}


/// Check alias result of two values.
/// True: alias, False: not alias.
bool checkAlias(Value *Addr1, Value *Addr2,
		PointerAnalysisMap &aliasPtrs) {

	if (Addr1 == Addr2)
		return true;

	auto it = aliasPtrs.find(Addr1);
	if (it != aliasPtrs.end()) {
		if (it->second.count(Addr2) != 0)
			return true;
	}

	// May not need to do this further check.
	it = aliasPtrs.find(Addr2);
	if (it != aliasPtrs.end()) {
		if (it->second.count(Addr1) != 0)
			return true;
	}

	return false;
}


bool checkStringContainSubString(string origstr, string targetsubstr){
    
    if(origstr.length() == 0 || targetsubstr.length() == 0)
        return false;
    
    string::size_type idx;
    idx = origstr.find(targetsubstr);
    if(idx == string::npos)
        return false;
    else
        return true;
}

//Check if there is a path from fromBB to toBB 
bool checkBlockPairConnectivity(
    BasicBlock* fromBB, 
    BasicBlock* toBB){

    if(fromBB == NULL || toBB == NULL)
        return false;
    
    //Use BFS to detect if there is a path from fromBB to toBB
    std::list<BasicBlock *> EB; //BFS record list
    std::set<BasicBlock *> PB; //Global value set to avoid loop
    EB.push_back(fromBB);

    while (!EB.empty()) {

        BasicBlock *TB = EB.front(); //Current checking block
		EB.pop_front();

		if (PB.find(TB) != PB.end())
			continue;
		PB.insert(TB);

        //Found a path
        if(TB == toBB)
            return true;

        auto TI = TB->getTerminator();

        for(BasicBlock *Succ: successors(TB)){

            EB.push_back(Succ);
        }

    }//end while

    return false;
}

//Used for data recording
void pairFuncDataRecord(GlobalContext *Ctx){

    if(Ctx->Global_Func_Pair_Set.empty())
        return;

    ofstream oFile;
    oFile.open("Pair_func_sheet.csv", ios::out | ios::trunc);

    //oFile << "name"<<","<<"age"<< ","<<"class"<<","<<"people"<<"\n";
    //oFile << "zhangsan"<<","<<"22"<< ","<<"1"<<","<<"JIM"<<"\n";
    //oFile << "lish"<<","<<"23"<< ","<<"3"<<","<<"TOM"<<"\n";
    oFile << "Number"<<","<<"init function"<< ","<<"fini function"<< "," << "pair type" <<"\n";
    int count = 1;
    for(auto it = Ctx->Global_Func_Pair_Set.begin(); it != Ctx->Global_Func_Pair_Set.end(); it++){

        PairInfo funcpair = *it;
        Function* initfunc = funcpair.initfunc;
        Function* finifunc = funcpair.finifunc;
        int pairtype = funcpair.type;

        switch(pairtype){
            case MODULE_FUNC:
                oFile << count <<"," << initfunc->getName().str() << "," << finifunc->getName().str() << "," << "module func" <<"\n";
                break;
            case MODULE_FUNC_WRAPPER:
                oFile << count <<"," << initfunc->getName().str() << "," << finifunc->getName().str() << "," << "module func wrapper" <<"\n";
                break;
            default:
                oFile << count <<"," << initfunc->getName().str() << "," << finifunc->getName().str() << "," << "unknown" <<"\n";
                break;
        }

        count++;
    }
        
    oFile.close();

}

//Used for debug
void messageRecord(GlobalContext *Ctx){

    if(Ctx->Global_Debug_Message_Set.empty())
        return;

    ofstream oFile;
    oFile.open("Other_source.csv", ios::out | ios::trunc);

    //oFile << "name"<<","<<"age"<< ","<<"class"<<","<<"people"<<"\n";
    //oFile << "zhangsan"<<","<<"22"<< ","<<"1"<<","<<"JIM"<<"\n";
    //oFile << "lish"<<","<<"23"<< ","<<"3"<<","<<"TOM"<<"\n";
    oFile << "Number"<<","<<"source line"<<"\n";
    int count = 1;
    for(auto it = Ctx->Global_Debug_Message_Set.begin(); it != Ctx->Global_Debug_Message_Set.end(); it++){

        string func = *it;
        oFile << count <<"," << func << "\n";

        count++;
    }
        
    oFile.close();
}

//Used for data recording of structure keywords
void keywordsRecord(GlobalContext *Ctx){

    if(Ctx->Global_Keywords_Map.empty())
        return;

    ofstream oFile;
    oFile.open("Keywords_sheet.csv", ios::out | ios::trunc);
    oFile << "Number"<<","<<"keywords"<< ","<<"quantity" <<"\n";
    int count = 1;

    for(auto it = Ctx->Global_Keywords_Map.begin(); it != Ctx->Global_Keywords_Map.end(); it++){

        pair<string, int> pair = *it;
        string keywords = pair.first;
        int num = pair.second;
        oFile << count <<"," << keywords << "," << num << "\n";

        count++;
    }

    oFile.close();
}

//Used for global call graph debug
void icallTargetResult(GlobalContext *Ctx){

    if(Ctx->Callers.empty())
        return;

    unsigned long long NumCallee = 0;

    /*for(auto i = Ctx->Callers.begin(); i!= Ctx->Callers.end(); i++){
        Function* F = i->first;
        CallInstSet callset = i->second;
        if(F->getName() != "dptf_power_add")
            continue;
        OP<<"F: "<<F->getName()<<"\n";
        for(auto j = callset.begin(); j!= callset.end(); j++){
            NumCallee++;
            CallInst* callinst = *j;
            //OP<<" --callinst: "<<*callinst<<"\n";
            Function* parrent = callinst->getFunction();
            OP<<" --caller: "<<parrent->getName()<< " " << *callinst<< "\n";
        }
    }*/

    //Test callee set
    if(Ctx->Callees.empty())
        return;
    unsigned long long maxicall = 0;
    unsigned long long icallnum = Ctx->IndirectCallInsts.size();
    unsigned long long total_icall_targets = 0;

    std::vector<std::pair<unsigned long long, CallInst*>> icall_vec;
    icall_vec.clear();

    ofstream oFile;
    oFile.open("ICall_analysis_sheet.csv", ios::out | ios::trunc);
    oFile << "ID"<<","<<"icall target num"<< "," << "caller" << ",";
    oFile << "line number" << "," << "location" << "," << "MLTA result" <<"\n";

    for(auto i = Ctx->ICallees.begin(); i!= Ctx->ICallees.end(); i++){
        CallInst* cai = i->first;
        FuncSet fset = i->second;
        unsigned long long num = fset.size();
        icall_vec.push_back(make_pair(num,cai));
        total_icall_targets+=num;
        if(num>maxicall)
            maxicall = num;
    }
    unsigned long long id = 1;
    std::sort(icall_vec.begin(), icall_vec.end());
    for(auto i = icall_vec.begin(); i != icall_vec.end(); i++){
        
        CallInst* cai = i->second;
        Function* caller = cai->getFunction();

        oFile << id << "," << i->first << "," << caller->getName().str() << ",";
        //oFile << Ctx->ValidICalls.count(cai);
        unsigned lineNo = getInstLineNo(cai);
        oFile<< lineNo <<",";

        Module* M = caller->getParent();
        oFile << M->getName().str() <<",";

        switch(Ctx->Global_MLTA_Reualt_Map[cai]){
            case TypeEscape:
                oFile << "TypeEscape";
                break;
            case OneLayer:
                oFile << "OneLayer";
                break;
            case TwoLayer:
                oFile << "TwoLayer";
                break;
            case ThreeLayer:
                oFile << "ThreeLayer";
                break;
            case NoTwoLayerInfo:
                oFile << "NoTwoLayerInfo";
                break;
            default:
                oFile << "unknown";
                break;
        }

        oFile << "\n";
        id++;
    }

    oFile.close();

    OP<<"Max callee num: "<<maxicall<<"\n";
    OP<<"Total icall targets num: "<<total_icall_targets<<"\n";

}

void DumpFunctions(GlobalContext *Ctx){
    ofstream oFile;
    size_t num = 0;
    oFile.open("Functions.csv", ios::out | ios::trunc);
    oFile << "Function name,Filename,Line number,BB count\n";
    std::string str;
    raw_string_ostream rawstr(str);
    for(auto m : Ctx->Modules){
        for(Function& f : m.first->functions()){
            DISubprogram* Loc = getInstLineNo_Loc(&f);
            if(Loc && !f.isDeclaration()){
                rawstr << f.getName() << "," << Loc->getFilename() << "," << Loc->getLine() << "," << f.size() <<"\n";
            }
        }
    }
    oFile << rawstr.str();
}


void RecordCFG(GlobalContext *Ctx){

    ofstream oFile;
    size_t num = 0;
    oFile.open("CG_sheet.csv", ios::out | ios::trunc);
    oFile << "Caller func,Caller filename,Caller line number,is indirect call?" << ",";
    oFile << "Callee func,Callee filename,Callee line number"<<"\n";

    for(auto i = Ctx->Callees.begin(); i!= Ctx->Callees.end(); i++){
        CallInst* cai = i->first;
        FuncSet fset = i->second;
        Function* caller = cai->getFunction();

        for(Function* f : fset){
            
            oFile << caller->getName().str() <<","<<getInstFilename(cai) <<","<<getInstLineNo(cai) <<",";
            if (cai->isIndirectCall()){
                oFile << "yes,";
            }
            else{
                oFile << "no,";
            }
            DISubprogram* Loc = getInstLineNo_Loc(f);
            int lineno=0;
            std::string filename = "";
            if(Loc){
                lineno = Loc->getLine();
                filename = Loc->getFilename();
            }
            oFile << f->getName().str() << "," << filename << "," << lineno <<"\n";
            num++;
        }

    }
    oFile.close();

    OP<<"total: "<<num<<"\n";
}

bool isCompositeType(Type *Ty) {
	if (Ty->isStructTy() 
			|| Ty->isArrayTy() 
			|| Ty->isVectorTy())
		return true;
	else 
		return false;
}

bool isStructorArrayType(Type *Ty) {
	if (Ty->isStructTy() || Ty->isArrayTy() )
		return true;
	else 
		return false;
}

bool checkTypeEuqal_old(Type *Ty1, Type *Ty2){
	
    //OP<<"Ty1: "<<*Ty1<<"\n";
	//OP<<"\nTy2: "<<*Ty2<<"\n";

    if(Ty1 == Ty2)
        return true;

    if(typeHash(Ty1) == typeHash(Ty2))
        return true;

    //This comp is not correct, some array type could be equal to a struct type
    if(Ty1->getTypeID() != Ty2->getTypeID())
        return false;
    
    ///OP<<"\nTy1: "<<*Ty1<<"\n";
    //OP<<"Ty2: "<<*Ty2<<"\n";

    //if(!isCompositeType(Ty1) || !isCompositeType(Ty2))
    //    return false;

    unsigned subnum1 = Ty1->getNumContainedTypes();
    //OP<<"subnum1: "<<subnum1<<"\n";
    unsigned subnum2 = Ty2->getNumContainedTypes();
    //OP<<"subnum2: "<<subnum2<<"\n";
    if(subnum1 != subnum2)
        return false;

    //OP<<"member num: "<<subnum1<<"\n";
    bool isequal = true;

    //This compare shoud be recursive
    for(int it = 0; it < subnum1; it ++){
        Type* subtype1 = Ty1->getContainedType(it);
        Type* subtype2 = Ty2->getContainedType(it);

        //OP<<"subty1: "<< subtype1 <<" "<< *subtype1<<"\n";
        //OP<<"subty2: "<< subtype2 <<" "<< *subtype2<<"\n\n";

        //check each field
        if(subtype1 == subtype2) //address check
            continue;

        if(typeHash(subtype1) == typeHash(subtype2))
            continue;

        //The two pointer is not equal
        //Resolve the case that an expected function pointer is {}*
        if(subtype1->isPointerTy() && subtype2->isPointerTy()){
            //OP<<"here\n";
            PointerType* psubtype1 = dyn_cast<PointerType>(subtype1);
            PointerType* psubtype2 = dyn_cast<PointerType>(subtype2);
            Type* subsubty1 = psubtype1->getElementType();
            Type* subsubty2 = psubtype2->getElementType();

            //OP<<"subsubty1: "<< subsubty1 <<" "<< *subsubty1<<"\n";
            //OP<<"subsubty2: "<< subsubty2 <<" "<< *subsubty2<<"\n\n";
             if(subsubty1 == subsubty2) //address check
                continue;

            if(typeHash(subsubty1) == typeHash(subsubty2))
                continue;
            
            if(subsubty1->isEmptyTy() || subsubty2->isEmptyTy())
                continue;
        }
        else if(subtype1->isArrayTy() && subtype2->isArrayTy()){
            //OP<<"is array\n";
        }
        else{
            //OP<<"unknown\n";
            if(subtype1->isArrayTy()){
                //OP<<"subtype1 is array\n";
                //OP<<subtype1->getTypeID()<<"\n";
            }

            if(subtype2->isStructTy()){
                //OP<<"subtype2 is str\n";
                //OP<<subtype1->getTypeID()<<"\n";
            }
        }

        //OP<<"not equal\n";

        isequal = false;
        break;
    }


	return isequal;
}

size_t funcInfoHash(Function *F){
    
    hash<string> str_hash;
	string output;
    
    DISubprogram *SP = F->getSubprogram();

	if (SP) {
		output = SP->getFilename();
        stringstream ss;
        unsigned linenum = SP->getLine();
        ss<<linenum;
		output += ss.str();
	}

	//string sig;
	//raw_string_ostream rso(sig);
	//Type *FTy = F->getFunctionType();
	//FTy->print(rso);
	//output += rso.str();
	output += F->getName();

	string::iterator end_pos = remove(output.begin(), 
			output.end(), ' ');
	output.erase(end_pos, output.end());
	
	//OP<<"output: "<<output<<"\n";

	return str_hash(output);

}

