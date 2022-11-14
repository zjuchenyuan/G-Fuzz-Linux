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

//#define TEST_ONE_INIT_GLOBAL "aenq_handlers"
//#define DEBUG_PRINT


map<size_t, DIType*> TypeBuilderPass::structDebugInfoMap;
map<string, StructType*> TypeBuilderPass::identifiedStructType;
set<GlobalVariable*> TypeBuilderPass::targetGVSet;

StringRef getDebugStructName(DIType *DITy){

    DIDerivedType *DIDTy = dyn_cast<DIDerivedType>(DITy);
    if(DIDTy){
        DITy = DIDTy->getBaseType();
    }

    DICompositeType *DICTy = dyn_cast<DICompositeType>(DITy);
    if(!DICTy)
        return "";
    
    unsigned tag = DICTy->getTag();
    if(tag == 19){
        return DICTy->getName();
    }

    return "";
}


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

//DTy is PreLayerTyDebugInfo
void TypeBuilderPass::getLayeredDebugTypeName(DIType *DTy, int idx, size_t Tyhash){

    //OP<<"PreLayerTyDebugInfo: "<<*DTy<<"\n";
    //OP<<"idx: "<<idx<<"\n";

    DIDerivedType *DIDTy = dyn_cast<DIDerivedType>(DTy);
    if(DIDTy){
        DTy = DIDTy->getBaseType();
    }

    //OP<<"PreLayerTyDebugInfo: "<<*DTy<<"\n";

    DICompositeType *DICTy = dyn_cast<DICompositeType>(DTy);
    if(!DICTy){
        return;
    }

    unsigned tag = DICTy->getTag();
    //prelayer type is array type
    if(tag == 1){
        DIType* DIBaseTy = DICTy->getBaseType(); //usually this is struct type
        if(!DIBaseTy)
            return;
        
        //OP<<"DIBaseTy: "<<*DIBaseTy<<"\n";
        structDebugInfoMap[Tyhash] = DIBaseTy;
        StringRef typeName = getDebugStructName(DIBaseTy);
        if(typeName.size() != 0){
            //OP<<"current typeName: "<<typeName<<"\n";
            Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
        }
            
        return;
    }

    //prelayer type is union type
    if(tag == 23){
        //OP<<"here\n";
        DINodeArray DIArray = DICTy->getElements();
        for(auto it = DIArray.begin(); it != DIArray.end(); it++){
            
            DINode *targetDINode = *it;
            //OP<<"DINode: "<<*targetDINode<<"\n";

            DIDTy = dyn_cast<DIDerivedType>(targetDINode);
            if(!DIDTy)
                continue;
            
            DIType* DIBaseTy = DIDTy->getBaseType();
            if(!DIBaseTy)
                continue;

            //OP<<"DIBaseTy: "<<*DIBaseTy<<"\n";
            DICTy = dyn_cast<DICompositeType>(DIBaseTy);
            if(!DICTy){
                continue;
            }

            tag = DICTy->getTag();

            if(tag == 19){
                StringRef typeName = DICTy->getName();
                structDebugInfoMap[Tyhash] = DIBaseTy;
                if(typeName.size() != 0){
                    //OP<<"current typeName: "<<typeName<<"\n";
                    Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
                }

                continue;
            }

            if(tag == 1){
                //OP<<"is array\n";
                structDebugInfoMap[Tyhash] = DIBaseTy;
                StringRef typeName = "Generated_Array_Type";
                Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
                continue;
            }

            if(tag == 23){

                StringRef typeName = "Generated_Union_Type";

                structDebugInfoMap[Tyhash] = DIBaseTy;
                Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
                continue;
            }
        }

        return;
    }

    if(tag != 19)
        return;

    //unsigned tag = DICTy->getTag();
    //OP<<"tag: "<<tag<<"\n";

    //prelayer type is struct type, let's get its idx-th element
    DINodeArray DIArray = DICTy->getElements();
    //invalid offset
    if(idx >= DIArray.size()){
        OP<<"invalid index\n";
        return;
    }

    DINode *targetDINode = DIArray[idx];
    //OP<<"targetDINode: "<<*targetDINode<<"\n";

    DIDTy = dyn_cast<DIDerivedType>(targetDINode);
    if(!DIDTy)
        return;
    
    DIType* DIBaseTy = DIDTy->getBaseType();
    if(!DIBaseTy)
        return;

    //OP<<"DIBaseTy: "<<*DIBaseTy<<"\n";
    DICTy = dyn_cast<DICompositeType>(DIBaseTy);
    if(!DICTy){
        return;
    }

    tag = DICTy->getTag();
    //OP<<"tag: "<<tag<<"\n";

    if(tag == 19){
        StringRef typeName = DICTy->getName();
        structDebugInfoMap[Tyhash] = DIBaseTy;
        if(typeName.size() != 0){
            //OP<<"current typeName: "<<typeName<<"\n";
            Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
        }
        else{
            //This case happens when a struct has a struct field without name (struct radeon_asic)
            //For this case, there must be multilayer info, we could skip two layer analysis
            //OP<<"is struct but without name\n";

            typeName = "Generated_Struct_Type";
            Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
        }
        return ;
    }

    //a struct has an array field
    if(tag == 1){
        //OP<<"is array\n";
        structDebugInfoMap[Tyhash] = DIBaseTy;
        StringRef typeName = "Generated_Array_Type";
        Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
        return;
    }

    //a struct has a union field
    //union should not be counted as a layer, but a single field
    if(tag == 23){
        //OP<<"0000 union DICTy: "<<*DICTy<<"\n";
        //StringRef typeName = DICTy->getName();
        //some unions do not have name
        //OP<<"typeName: "<<typeName<<"\n";
        StringRef typeName = "Generated_Union_Type";

        structDebugInfoMap[Tyhash] = DIBaseTy;
        Ctx->Global_Literal_Struct_Map[Tyhash] = typeName.str();
    }

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
                continue;
            }
            
            else{
                //OP<<"no found in identifiedStructType\n";
            }
        }


        unsigned ONo_delay = 0;
        for (auto oi = U->op_begin(), oe = U->op_end(); oi != oe; ++oi) {
			Value *O = *oi;
			Type *OTy = O->getType();
            unsigned ONo = oi->getOperandNo() - ONo_delay;

#ifdef DEBUG_PRINT
            OP<<"--ONo: "<<ONo<<"\n";
            OP<<"--OTy: "<<*OTy<<"\n";
            if (Function *F = dyn_cast<Function>(O)) {
                OP<<"--O: "<<F->getName()<<"\n";
            }
            else
                OP<<"--O: "<<*O<<"\n";
            
#endif

            UndefValue *UV = dyn_cast<UndefValue>(O);
            if(UV){
                //OP<<"UndefValue!"<<"\n";
                ONo_delay++;
                continue;
            }

            if (isCompositeType(OTy)) {
				//OP<<"ONo: "<<ONo<<"\n";
				//typeConfineMap[typeIdxHash(ITy, ONo)].insert(typeHash(OTy));
				

                if(OTy->isStructTy() && OTy->getStructName().size() == 0){
                    //OP<<"empty struct\n";
                    //OP<<"\ncurrentTy: "<<*OTy<<"\n";
                    size_t CurTyhash = typeHash(OTy);
                    //Current type has a found name
                    if(structDebugInfoMap.count(CurTyhash)){
                        //OP<<"have checked before\n";
                        User *OU = dyn_cast<User>(O);
                        LU.push_back(OU);
                        continue;
                    }

                    //OP<<"resolve current layer\n";

                    //Let's find the type name through the debug info 
                    if(structDebugInfoMap.count(PreTyhash)){
                        
                        DIType * PreLayerTyDebugInfo = structDebugInfoMap[PreTyhash];
                        
                        getLayeredDebugTypeName(PreLayerTyDebugInfo, ONo, CurTyhash);

                        User *OU = dyn_cast<User>(O);
                        LU.push_back(OU);
                    }
                    
                }

                else if(OTy->isArrayTy()){
                    //OP<<"is array\n";
                    //Type* innerTy = OTy->getArrayElementType();
                    //OP<<"innerTy: "<<*innerTy<<"\n";

                    if(structDebugInfoMap.count(PreTyhash)){
                        //StringRef PreLayerTyName = Ctx->Global_Literal_Struct_Map[PreTyhash];
                        //OP<<"PreLayerTyName: "<<PreLayerTyName<<"\n";
                        
                        DIType * PreLayerTyDebugInfo = structDebugInfoMap[PreTyhash];
                        if(!PreLayerTyDebugInfo)
                            continue;
                        
                        size_t CurTyhash = typeHash(OTy);
                        getLayeredDebugTypeName(PreLayerTyDebugInfo, ONo, CurTyhash);
                        
                        //OP<<"SubTypeName: "<<SubTypeName<<"\n";
                        
                        //Ctx->Global_Literal_Struct_Map[CurTyhash] = SubTypeName;
                        User *OU = dyn_cast<User>(O);
                        LU.push_back(OU);
                    }
                

                    /*if(innerTy->isStructTy() && innerTy->getStructName().size() == 0){

                        size_t CurTyhash = typeHash(innerTy);
                        if(Ctx->Global_Literal_Struct_Map.count(CurTyhash)){
                            User *OU = dyn_cast<User>(O);
                            //LU.push_back(OU);
                            continue;
                        }
                    }*/
                }

                // recognize nested composite types
				//User *OU = dyn_cast<User>(O);
                //LU.push_back(OU);
				
            }

            else if (PointerType *POTy = dyn_cast<PointerType>(OTy)) {
                if (isa<ConstantPointerNull>(O))
					continue;
				// if the pointer points a composite type, skip it as
				// there should be another initializer for it, which
				// will be captured
				//OP<<" Case3: "<<*O<<"\n";

				Type *eleType = POTy->getElementType();
                if (isCompositeType(eleType)) {
                    
                    //OTy = eleType;
                    //goto check;

                }
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

    
	
	return false;
}

static int globaltag = 0;

bool TypeBuilderPass::doFinalization(Module *M) {

    //if(globaltag !=0)
	//	return false;

    /*for(auto it = Ctx->Global_Literal_Struct_Map.begin(); it != Ctx->Global_Literal_Struct_Map.end(); it++){
        size_t hash = it->first;
        string name = it->second;
        OP<<"\nhash: "<<hash<<"\n";
        OP<<"name: "<<name<<"\n";
    }*/
    //identifiedStructType.clear();
    
    //globaltag++;
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
        /*if(identifiedStructType.count(parsed_STy_name)){
            size_t hash = typeHash(STy);
            size_t recordedhash = typeHash(identifiedStructType[parsed_STy_name]);
            if(hash == recordedhash){
                continue;
            }
            else{
                OP<<"\nDifferent type with the same name: "<<parsed_STy_name<<"\n";
                OP<<"Pre: "<<*identifiedStructType[parsed_STy_name]<<"\n";
                OP<<"Now: "<<*STy<<"\n";
            }
        }*/
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