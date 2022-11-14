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
#include <stdlib.h>
#include <assert.h>
#include "llvm/IR/CFG.h" 
#include "llvm/Transforms/Utils/BasicBlockUtils.h" 
#include "llvm/IR/IRBuilder.h"

#include "TypeBuilder.h"
#include "../Config.h"
#include "../Common.h"

using namespace llvm;

//#define TEST_ONE_INIT_GLOBAL "ath11k_host_ce_config_ipq8074"
//#define DEBUG_PRINT


map<size_t, DIType*> TypeBuilderPass::structDebugInfoMap;
map<string, StructType*> TypeBuilderPass::identifiedStructType;

map<size_t, string> TypeBuilderPass::ArrayBaseDebugTypeMap;
set<GlobalVariable*> TypeBuilderPass::targetGVSet;

void TypeBuilderPass::checkGlobalDebugInfo(GlobalVariable *GV, size_t Tyhash){
    //OP<<"\n\ncheck here\n";
    //SmallVectorImpl< DIGlobalVariableExpression * > GV_Debug_vec;
    //GV->getDebugInfo(GV_Debug_vec);
    MDNode *N = GV->getMetadata("dbg");
    if (!N)
        return;
    
    DIGlobalVariableExpression *DLGVE = dyn_cast<DIGlobalVariableExpression>(N);
    if(!DLGVE)
        return;
    //OP<<"DLGVE: "<<*DLGVE<<"\n";

    DIGlobalVariable* DIGV = DLGVE->getVariable();
    if(!DIGV)
        return;
    //OP<<"DIGV: "<<*DIGV<<"\n";

    DIType *DITy = DIGV->getType();
    if(!DITy)
        return;
    //OP<<"DITy: "<<*DITy<<"\n";

    DIType * currentDITy = DITy;
    while(true){

        DIDerivedType *DIDTy = dyn_cast<DIDerivedType>(currentDITy);
        if(DIDTy){
            //OP<<"DIDerivedType: " << *currentDITy<<"\n";
            currentDITy = DIDTy->getBaseType();
            //OP<<"baseTy: "<<*currentDITy<<"\n";
            continue;
        }

        //Our target is CompositeType
        DICompositeType *DICTy = dyn_cast<DICompositeType>(currentDITy);
        if(DICTy){
            //OP<<"DICompositeType: " << *currentDITy<<"\n";
            //currentDITy = DIDTy->getBaseType();
            
            unsigned tag = DICTy->getTag();
            //OP<<"tag: "<<tag<<"\n";

            //DW_TAG_array_type is 1
            if(tag == 1){
                structDebugInfoMap[Tyhash] = currentDITy;
                Ctx->Global_Literal_Struct_Map[Tyhash] = "Array";
                //OP<<"get array: "<<*currentDITy<<"\n";

                //return;
                currentDITy = DICTy->getBaseType();
                //continue;

                DIDerivedType *DIDTy = dyn_cast<DIDerivedType>(currentDITy);
                if(DIDTy){
                    currentDITy = DIDTy->getBaseType();
                }

                DICTy = dyn_cast<DICompositeType>(currentDITy);
                if(!DICTy)
                    return;
                        
                tag = DICTy->getTag();
                if(tag == 19){

                    StringRef typeName = DICTy->getName();
                    if(typeName.size() != 0)
                        ArrayBaseDebugTypeMap[Tyhash] = typeName.str();
                    return;
                }
                return;
            }

            //DW_TAG_structure_type is 19, only record this debuginfo
            if(tag == 19){
                structDebugInfoMap[Tyhash] = currentDITy;
                StringRef typeName = DICTy->getName();
                if(typeName.size() != 0)
                    Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
                return;
            }

            //OP<<"typeName: "<<typeName<<"\n";
            
            //unsigned line = DICTy->getLine();
            //OP<<"line: "<< line <<"\n";

            //DIFile * DIF = DICTy->getFile();
            //StringRef fileName = DIF->getFilename();
            //OP<<"file: "<<fileName<<"\n";

            break;
        }

        DIBasicType *DIBTy = dyn_cast<DIBasicType>(currentDITy);
        if(DIBTy){
            //OP<<"DIBasicType: " << *currentDITy<<"\n";
            break;
        }

        //DODO: support more other` types
    }

    //OP<<"\nDICompositeType: "<<*currentDITy<<"\n\n";
    return;
}



void TypeBuilderPass::matchStructTypes(Type *identifiedTy, User *U){

    if(!identifiedTy || !U)
        return;
    
    Type *UTy = U->getType();
    //OP<<"\nUTy:         "<<*UTy<<"\n";
    //OP<<"identifiedTy: "<<*identifiedTy<<"\n";

    deque<Type*> Ty1_queue;
    deque<User*> U2_queue;
	deque<Type*> Ty2_queue;
	Ty1_queue.push_back(identifiedTy);
    U2_queue.push_back(U);
	Ty2_queue.push_back(UTy);

	//bool isequal = true;
	while (!(Ty1_queue.empty() || U2_queue.empty())){

		Type* type1 = Ty1_queue.front();
        User* u2 = U2_queue.front();
		Type* type2 = u2->getType();
		Ty1_queue.pop_front();
		U2_queue.pop_front();

        //OP<<"type1: "<<*type1<<"\n";
        //OP<<"type2: "<<*type2<<"\n";
        //OP<<"Ty1_queue size: "<<Ty1_queue.size()<<"\n";
        //OP<<"U2_queue size: "<<U2_queue.size()<<"\n";
    
        if(type1 == type2){
			continue;
		}
		
		if(typeHash(type1) == typeHash(type2)){
			continue;
		}

        if(type1->isPointerTy() && type2->isPointerTy()){
            continue;
        }

        if(type1->isFunctionTy() && type2->isFunctionTy()){
			continue;
		}

        if(type1->isIntegerTy() && type2->isIntegerTy()){
			//OP<<"integer: "<<*type<<"\n";
			IntegerType* inty1 = dyn_cast<IntegerType>(type1);
			IntegerType* inty2 = dyn_cast<IntegerType>(type2);
			unsigned bitwidth1 = inty1->getBitWidth();
			unsigned bitwidth2 = inty2->getBitWidth();
			//OP<<"bitwidth: "<<bitwidth<<"\n";

			//This will not happen for the type hash is different
			if(bitwidth1 == bitwidth2)
				continue;

			LLVMContext &C = type1->getContext();
            IntegerType* generated_int = IntegerType::get(C,bitwidth2);

            int times = bitwidth1/bitwidth2;
            for(int i = 0; i < times; i++){
				Ty1_queue.push_front(generated_int);
			}
            U2_queue.push_front(u2);
			
			continue;
		}

		if(type2->isStructTy() ){
            
            //We have got the name of type2
            StringRef type2_structname = type2->getStructName();
            if(type2_structname.size() != 0)
                continue;
            
            if(type1->isStructTy()){
                
                //type2 has no name, find it
                if(Ctx->Global_Literal_Struct_Map.count(typeHash(type2)) == 0){
                    StringRef type1_structname = type1->getStructName();
                    string parsed_name = parseIdentifiedStructName(type1_structname);
                    if(parsed_name.size() != 0){
                        Ctx->Global_Literal_Struct_Map[typeHash(type2)] = parsed_name;
                    }
                }

                StringRef type1_structname = type1->getStructName();
                if(type1_structname.contains("union.")){
                    //Once we meet a union, stop further analysis 
                    //OP<<"stop at union\n";
                    Ctx->Globa_Union_Set.insert(typeHash(type2));
                    continue;
                }

                //OP<<"here1\n";
                bool userqueue_updatr = updateUserQueue(u2, U2_queue);
                if(userqueue_updatr){
                    updateTypeQueue(type1, Ty1_queue);
                }
                continue;
            }
            else if (type1->isArrayTy()){
                //OP<<"here\n";
                //OP<<"type1: "<<*type1<<"\n";
                //OP<<"type2: "<<*type2<<"\n";
                //OP<<"identifiedTy: "<<*identifiedTy<<"\n";
                //OP<<"U: "<<*U<<"\n";

                //We need to mark this case
                if(Ctx->Global_Literal_Struct_Map.count(typeHash(type2)) == 0){
                    Ctx->Global_Literal_Struct_Map[typeHash(type2)] = "Array";
                }

                bool userqueue_updatr = updateUserQueue(u2, U2_queue);
                if(userqueue_updatr == false)
                    continue;

                ArrayType* arrty = dyn_cast<ArrayType>(type1);
                unsigned subnum = arrty->getNumElements();
                Type* subtype = arrty->getElementType();
                if(subnum > 0){
                    for(auto it = 0; it < subnum; it++){
                        Ty1_queue.push_front(subtype);
                    }
                }
                else{
                    //dynamic array
                    //OP<<"here\n";
                }

                continue;
            }
            continue;
		}

        if(type2->isArrayTy()){
            //OP<<"inner type1: "<<*type1<<"\n";
            //OP<<"inner type2: "<<*type2<<"\n";
            Type* subtype2 = type2->getArrayElementType();
            unsigned subnum2 = type2->getArrayNumElements();


            if(type1->isArrayTy()){
                
                Type* subtype1 = type1->getArrayElementType();
                unsigned subnum1 = type1->getArrayNumElements();

                if((subnum2 == subnum1) || (subnum1 == 0)){
                    Ty1_queue.push_front(subtype1);
                    Value *O = *(u2->op_begin());
                    User *OU = dyn_cast<User>(O);
                    U2_queue.push_front(OU);
                }

                else{
                    //OP<<"array size is not equal!\n";
                    if(subtype2->getTypeID() == type1->getTypeID()){

                    }
                }
            }
            else{
                //Here type1 usuallt is a single value
                //OP<<"type1 is not array\n";
                updateQueues(type1, type2, Ty1_queue);

            }


            continue;
        }

        OP<<"Unexpected case!\n";

    }

    if(Ty1_queue.size() != U2_queue.size()){
        OP<<"WARNING: matchStructTypes problem!\n";
    }

}

void TypeBuilderPass::checkLayeredDebugInfo(GlobalVariable *GV){

    Constant *Ini = GV->getInitializer();
    list<User *>LU;
	LU.push_back(Ini);

	//OP<<"\ncurrent: "<<*Ini<<"\n";

	//maybe should consider deadloop
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


        Type *ITy = U->getType();
        size_t PreTyhash = typeHash(ITy);

#ifdef DEBUG_PRINT
        OP<<"\n\nU: "<<*U<<"\n";
        OP<<"UTY: "<<*ITy<<"\n";
#endif

        if(ITy->isArrayTy()){
            Type* subtype = ITy->getArrayElementType();
        }

        if(Ctx->Global_Literal_Struct_Map.count(PreTyhash)){
            string PreLayerName = Ctx->Global_Literal_Struct_Map[PreTyhash];
            //OP<<" -> U Source Type name: "<<PreLayerName<<"\n";
            
            if(identifiedStructType.count(PreLayerName)){
                //OP<<" exist in identifiedStructType\n";
                matchStructTypes(identifiedStructType[PreLayerName], U);
                continue;
            }

            else if(PreLayerName == "Array"){
                //OP<<" -- is Array\n";
                if(ITy->isStructTy() || ITy->isArrayTy()){
                    //this is an array in source, but strutc in bc
                    //OP<<"bc is struct\n";
                    for (auto oi = U->op_begin(), oe = U->op_end(); oi != oe; ++oi) {
                        Value *O = *oi;
                        Type *OTy = O->getType();
                        //OP<<"O: "<<*O<<"\n";
                        UndefValue *UV = dyn_cast<UndefValue>(O);
                        if(UV){
                            //OP<<"UndefValue\n";
                            continue;
                        }

                        if(ArrayBaseDebugTypeMap.count(PreTyhash)){
                            string ArrayEleTypeName = ArrayBaseDebugTypeMap[PreTyhash];
                            //OP<<" -> U ArrayEleTypeName: "<<ArrayEleTypeName<<"\n";
                            if(identifiedStructType.count(ArrayEleTypeName) == 0){
                                continue;
                            }

                            if(OTy->isArrayTy())
                                continue;

                            User *OU = dyn_cast<User>(O);
                            matchStructTypes(identifiedStructType[ArrayEleTypeName], OU);
                            continue;
                        }
                        else{
                            //OP<<"not found in ArrayEleTypeName\n";
                        }
                        //User *OU = dyn_cast<User>(O);
                        //LU.push_back(OU);
                    }

                }

                continue;
            }
            
            else{
                //Usuall this is the case that the struct type definition
                // does not exist in current module
                //OP<<"no found in identifiedStructType\n";
                
            }
        }


    }
}

bool TypeBuilderPass::doInitialization(Module *M) {

    //OP<<"Module: "<<M->getName()<<"\n";

    for (Module::global_iterator gi = M->global_begin(); 
			gi != M->global_end(); ++gi) {
		GlobalVariable* GV = &*gi;

		//findArgStoreToGlobal(GV);

        //Init global variable map for dataflow analysis
        Ctx->Global_Unique_GV_Map[GV->getGUID()].insert(GV);

        /*if(GV->getName() == "__start_lsm_info"){
            OP<<"GV: "<<*GV<<"\n";
            sleep(3);
        }*/

		if (!GV->hasInitializer())
			continue;

		Constant *Ini = GV->getInitializer();
		if (!isa<ConstantAggregate>(Ini))
			continue;
		
#ifdef TEST_ONE_INIT_GLOBAL
		if(GV->getName() != TEST_ONE_INIT_GLOBAL)
			continue;
#endif

        Type* GType = GV->getType();
        Type* GPType = GType->getPointerElementType();
        size_t Tyhash = typeHash(GPType);
		//OP<<"\nGV: "<<GV->getName()<<"\n";
        //OP<<"GType: "<<*GType<<"\n";

        //OP<<"GV: "<<*GV<<"\n";

        if(GPType->isArrayTy()){
            //OP<<"\nis array\n";
            //OP<<"GPType: "<<*GType<<"\n";
            Type* innerTy = GPType->getArrayElementType();
            if(innerTy->isStructTy()){
                if(innerTy->getStructName().size() == 0){
                    checkGlobalDebugInfo(GV, Tyhash);
                    targetGVSet.insert(GV);
                }
            }

            continue;
        }

        if(GPType->isStructTy()){
            //OP<<"\nis struct\n";
            //OP<<"GPType: "<<*GType<<"\n";

			if(GPType->getStructName().size() == 0){
                checkGlobalDebugInfo(GV, Tyhash);
                targetGVSet.insert(GV);
				//StringRef GTypeName = checkGlobalDebugInfo(GV);
                //OP<<"typename: "<<GTypeName<<"\n";
                //if(GTypeName.size() == 0)
                //    continue;
                
			}
            continue;
        }
	}

    //Init some global info here
    for (Function &F : *M) {

        Ctx->Global_Unique_GV_Map[F.getGUID()].insert(&F);
        //OP<<"--identifier: "<<F.getGlobalIdentifier()<<"\n";
        /*OP<<"\nF: "<<F.getName()<<"\n";
        if (F.isDeclaration())
            OP<<"F is declare\n";
        OP<<"--identifier: "<<F.getGlobalIdentifier()<<"\n";
        OP<<"my identifier: "<<funcInfoHash(&F)<<"\n";
        Ctx->Global_Unique_Func_Map[F.getGUID()].insert(&F);*/
		//if (F.empty())
		//	continue;

        //No definition for this func??
        /*if(F.getName() == "__SCT__tp_func_ext4_load_inode"){
            OP<<"F: "<<F<<"\n";
            OP<<"M: "<<M->getName()<<"\n";
            sleep(3);
        }*/

        if(F.hasAddressTaken()){
            Ctx->Global_AddressTaken_Func_Set.insert(&F);
        }

		if (F.isDeclaration())
			continue;

        // Collect global function definitions.
		if ((F.hasExternalLinkage() && !F.empty()) || F.hasAddressTaken()) {
			//OP<<"hasExternalLinkage: "<<F.getName()<<"\n";
			// External linkage always ends up with the function name.
			StringRef FName = F.getName();
			// Special case: make the names of syscalls consistent.
			//if (FName.startswith("SyS_"))
			//	FName = StringRef("sys_" + FName.str().substr(4));

			// Map functions to their names.
			//if(Ctx->GlobalFuncs.count(FName.str())){
                //OP<<"same func name: "<<FName<<"\n";
                //sleep(3);
            //}

            size_t funchash = funcInfoHash(&F);
            Ctx->GlobalFuncs[FName.str()].insert(funchash);
            Ctx->Global_Unique_Func_Map[funchash] = &F;
        
            //Check arg cast
            //if(checkArgCast(&F)){
                //OP<<"cast func: "<< F.getName()<<"\n";
                //Ctx->Global_Arg_Cast_Func_Set.insert(&F);
            //}

		}

    }

	return false;
}

static int globaltag = 0;

bool TypeBuilderPass::doFinalization(Module *M) {

	return false;
}

bool TypeBuilderPass::doModulePass(Module *M) {

    //The struct type tabel in a single module has no redundant info
    vector <StructType*> identifiedStructTys = M->getIdentifiedStructTypes();
    for(auto it = identifiedStructTys.begin(); it != identifiedStructTys.end(); it++){
        StructType* STy = *it;
        StringRef STy_name = STy->getName();
        
        if(STy_name.size() == 0)
            continue;

        string parsed_STy_name = parseIdentifiedStructName(STy_name);

        //OP<<"recorded name: "<<STy_name<<"\n";
        identifiedStructType[parsed_STy_name] = STy;
    }

    for (Module::global_iterator gi = M->global_begin(); 
			gi != M->global_end(); ++gi) {
		GlobalVariable* GV = &*gi;
    
        if (!GV->hasInitializer())
			continue;
        
        Constant *Ini = GV->getInitializer();
		if (!isa<ConstantAggregate>(Ini))
			continue;
        
#ifdef TEST_ONE_INIT_GLOBAL
		if(GV->getName() != TEST_ONE_INIT_GLOBAL)
			continue;
#endif

        //Only focus on target set
        if(targetGVSet.count(GV) == 0)
            continue;

        checkLayeredDebugInfo(GV);

    }

    identifiedStructType.clear();


    return false;
}