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

#include "CallGraph.h"
#include "../Config.h"
#include "../Common.h"

using namespace llvm;


void getLayeredDebugTypeName(User *Ini, User *Layer, vector<unsigned> &vec){
	
	list<User *>LU;
	LU.push_back(Ini);

	set<User *> PB; //Global value set to avoid loop
	PB.clear();

	while (!LU.empty()) {
		User *U = LU.front();
		LU.pop_front();

		if (PB.find(U) != PB.end()){
			continue;
		}
		PB.insert(U);

		for (auto oi = U->op_begin(), oe = U->op_end(); oi != oe; ++oi) {
			Value *O = *oi;
			Type *OTy = O->getType();

		}
	
	}
}

//Maybe we should use recursive method to do this
bool CallGraphPass::typeConfineInInitializer(User *Ini) {

	list<User *>LU;
	LU.push_back(Ini);

	//OP<<"current: "<<Ini->getNameOrAsOperand()<<"\n";

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

		//OP<<"\nCurrent U: "<<*U<<"\n\n";
		//OP<<"UTYpe: "<<*U->getType()<<"\n";
		for (auto oi = U->op_begin(), oe = U->op_end(); oi != oe; ++oi) {
			Value *O = *oi;
			Type *OTy = O->getType();
			//OP<<"--O: "<<*O<<"\n";
			// Case 1: function address is assigned to a type
			// FIXME: it seems this cannot get declared func
			if (Function *F = dyn_cast<Function>(O)) {
				OP<<"--O1: "<<F->getName()<<"\n";
				//OP<<"\ntypeConfineInInitializer: \n";
				Type *ITy = U->getType();
				// TODO: use offset?
				unsigned ONo = oi->getOperandNo();
				OP<<"Type: "<<*ITy<<" offset: "<<ONo<<"\n\n";
				
				//if(ITy->isStructTy())
				//	OP<<"\nis struct type\n";
				//OP<<"Only type hash: "<<typeHash(ITy)<<"\n";
				//OP<<"type&id hash: "<<typeIdxHash(ITy, ONo)<<"\n";
				// A struct type with index info
				// Note that ITy usually is not a pointer type
				typeFuncsMap[typeIdxHash(ITy, ONo)].insert(F);
				
				//ITy->getStructName();
				/*if(StructType * st = dyn_cast<StructType>(ITy)){
					if(ITy->getStructName().size() != 0){
						typeFuncsMap[typeNameIdxHash(ITy, ONo)].insert(F);
					}
				}*/
				Ctx->sigFuncsMap[funcHash(F, false)].insert(F); //only single type info
				/*if(F->getName() == "gv100_gr_init_419bd8"){
					//OP<<"func type hash: "<<funcHash(F, false)<<"\n";
					OP<<"Type: "<<*ITy<<" offset: "<<ONo<<"\n\n";
				}*/

				//Use the new type to store
				size_t typehash = typeHash(ITy);
				size_t typeidhash = typeIdxHash(ITy,ONo);
				hashTypeMap[typehash] = ITy;
				hashIDTypeMap[typeidhash] = make_pair(ITy,ONo);

				if(ITy->isStructTy()){
					//unsigned subnum = ITy->getNumContainedTypes();
					unsigned subnum_new = getTypeEleNum(ITy);
					subMemberNumTypeMap[subnum_new].insert(typehash);
					//OP<<"subnum_new: "<<subnum_new<<"\n";

				}

				/*if(StructType * st = dyn_cast<StructType>(ITy)){
					if(ITy->getStructName().size() == 0){
						OP<<"\nliteral struct: "<<*st<<"\n";
					}
				}*/

				updateStructInfo(F, ITy, ONo);

				//If ITy is array or union, we have to retrive the the previous layer

			}
			
			// Case 2: a composite-type object (value) is assigned to a
			// field of another composite-type object
			// A type is confined by another type
			else if (isCompositeType(OTy)) {
				//OP<<"--O2: "<<*O<<"\n";
				//OP<<" Case2: "<<*O<<"\n";
				// confine composite types
				Type *ITy = U->getType();
				unsigned ONo = oi->getOperandNo();
				//OP<<"ONo: "<<ONo<<"\n";
				typeConfineMap[typeIdxHash(ITy, ONo)].insert(typeHash(OTy));

				// recognize nested composite types
				User *OU = dyn_cast<User>(O);
				LU.push_back(OU);
			}
			// Case 3: a reference (i.e., pointer) of a composite-type
			// object is assigned to a field of another composite-type
			// object
			else if (PointerType *POTy = dyn_cast<PointerType>(OTy)) {
				//OP<<"--O3: "<<*O<<"\n";
				if (isa<ConstantPointerNull>(O))
					continue;
				// if the pointer points a composite type, skip it as
				// there should be another initializer for it, which
				// will be captured
				//OP<<" Case3: "<<*O<<"\n";

				//The following logic will greatly increase the analysis time
				//Find the root: due to loop
				Type *eleType = POTy->getElementType();
				if(isCompositeType(eleType)){
					//OP<<" Case3: "<<*O<<"\n";
					//OP<<" eleTy: "<<*OTy<<"\n";
					Type *ITy = U->getType();
					//OP<<"ITy: "<<*ITy<<"\n";
					//OP<<"eleTy: "<<*eleType<<"\n";
					unsigned ONo = oi->getOperandNo();
					//OP<<"ONo: "<<ONo<<"\n";
					//FIXME: do we need to omit pointer type info?
					typeConfineMap[typeIdxHash(ITy, ONo)].insert(typeHash(eleType));

					// recognize nested composite types
					User *OU = dyn_cast<User>(O);
					LU.push_back(OU);
				}
				

				// now consider if it is a bitcast from a function address
				// bitcast could be layered:
				// %struct.hlist_head* bitcast (i8* getelementptr (i8, 
				//i8* bitcast (%struct.security_hook_heads* @security_hook_heads to i8*), i64 1208) to %struct.hlist_head*)
				if (BitCastOperator *CO = dyn_cast<BitCastOperator>(O)) {
					// Usually in @llvm.used global array, including message like
					// module author, module description, etc
					// Also could be casr from function to a pointer
					//OP<<" Unsupported bitcast: "<<*CO<<"\n";
					Type *ToTy = CO->getDestTy(), *FromTy = CO->getSrcTy();
					Value *Operand = CO->getOperand(0);
					//Do we need typeConfineInCast?
					//typeConfineInCast(FromTy,ToTy);
					
					// TODO: ? to test if all address-taken functions
					// are captured
					//OP<<"\nFromTy: "<<*FromTy<<"\n";
					//OP<<"Operand: "<<*Operand<<"\n";
					//checktype:
					if(Function *F = dyn_cast<Function>(Operand)){
						//OP<<"from a function\n";
						Type *ITy = U->getType();
						unsigned ONo = oi->getOperandNo();
						//OP<<"Case3: \n";
						//OP<<"F: "<<*F<<"\n";
						//OP<<"ITy: "<<*ITy<<"\n";
						//OP<<"ONo: "<<ONo<<"\n";
						typeFuncsMap[typeIdxHash(ITy, ONo)].insert(F);
						/*if(StructType * st = dyn_cast<StructType>(ITy)){
							if(ITy->getStructName().size() != 0){
								typeFuncsMap[typeNameIdxHash(ITy, ONo)].insert(F);
							}
						}*/
						Ctx->sigFuncsMap[funcHash(F, false)].insert(F);

						//Use the new type to store
						size_t typehash = typeHash(ITy);
						size_t typeidhash = typeIdxHash(ITy,ONo);
						hashTypeMap[typehash] = ITy;
						hashIDTypeMap[typeidhash] = make_pair(ITy,ONo);

						if(ITy->isStructTy()){
							//unsigned subnum = ITy->getNumContainedTypes();
							unsigned subnum_new = getTypeEleNum(ITy);
							subMemberNumTypeMap[subnum_new].insert(typehash);
						}

						updateStructInfo(F, ITy, ONo);

					}
					/*else if(FromTy->isPointerTy()){
						//OP<<"from a pointer\n";
						FromTy = FromTy->getPointerElementType();

						goto checktype;
					}*/
				}
			}
			else{
				//OP<<"--O4: "<<*O<<"\n";
			}
		}
	}

	return true;
}

bool CallGraphPass::typeConfineInInitializer_rec(User *Ini, pair<size_t, size_t> &preLTY) {

    User *U = Ini;
    static set<User *> visited_U; //used to avoid deadloop
    if(visited_U.count(U))
        return true;
    
    visited_U.insert(U);

    for (auto oi = U->op_begin(), oe = U->op_end(); oi != oe; ++oi) {
        Value *O = *oi;
        Type *OTy = O->getType();
        //OP<<"--O: "<<*O<<"\n";
        // Case 1: function address is assigned to a type
        // FIXME: it seems this cannot get declared func
        if (Function *F = dyn_cast<Function>(O)) {
            //OP<<"--O1: "<<F->getName()<<"\n";
            //OP<<"\ntypeConfineInInitializer: \n";
            //OP<<"Case 1: "<<F->getName()<<"\n";
            Type *ITy = U->getType();
            // TODO: use offset?
            unsigned ONo = oi->getOperandNo();
            //OP<<"Type: "<<*ITy<<" offset: "<<ONo<<"\n";
            //OP<<"Only type hash: "<<typeHash(ITy)<<"\n";
            //OP<<"type&id hash: "<<typeIdxHash(ITy, ONo)<<"\n";
            // A struct type with index info
            // Note that ITy usually is not a pointer type
            typeFuncsMap[typeIdxHash(ITy, ONo)].insert(F);
            preLTY.first = typeIdxHash(ITy, ONo);
            //ITy->getStructName();
            if(StructType * st = dyn_cast<StructType>(ITy)){
                if(ITy->getStructName().size() != 0){
                    typeFuncsMap[typeNameIdxHash(ITy, ONo)].insert(F);
                    preLTY.second = typeNameIdxHash(ITy, ONo);
                }
            }
        }
        
        // Case 2: a composite-type object (value) is assigned to a
        // field of another composite-type object
        // A type is confined by another type
        else if (isCompositeType(OTy)) {
            //OP<<"--O2: "<<*O<<"\n";
            //OP<<" Case2: "<<*O<<"\n";
            // confine composite types
            Type *ITy = U->getType();
            unsigned ONo = oi->getOperandNo();
            typeConfineMap[typeIdxHash(ITy, ONo)].insert(typeHash(OTy));

            // recognize nested composite types
            User *OU = dyn_cast<User>(O);
            //LU.push_back(OU);

            pair<size_t, size_t> preLTY;
            preLTY.first = 0; preLTY.second = 0;
            typeConfineInInitializer_rec(OU, preLTY);
            
        }
        // Case 3: a reference (i.e., pointer) of a composite-type
        // object is assigned to a field of another composite-type
        // object
        else if (PointerType *POTy = dyn_cast<PointerType>(OTy)) {
            //OP<<"--O3: "<<*O<<"\n";
            if (isa<ConstantPointerNull>(O))
                continue;
            // if the pointer points a composite type, skip it as
            // there should be another initializer for it, which
            // will be captured
            //OP<<" Case3: "<<*O<<"\n";

            //The following logic will greatly increase the analysis time
            //Find the root: due to loop
            Type *eleType = POTy->getElementType();
            if(isCompositeType(eleType)){
                //OP<<" Case3: "<<*O<<"\n";
                //OP<<" eleTy: "<<*OTy<<"\n";
                Type *ITy = U->getType();
                //OP<<"ITy: "<<*ITy<<"\n";
                //OP<<"eleTy: "<<*eleType<<"\n";
                unsigned ONo = oi->getOperandNo();
                //FIXME: do we need to omit pointer type info?
                typeConfineMap[typeIdxHash(ITy, ONo)].insert(typeHash(eleType));

                // recognize nested composite types
                User *OU = dyn_cast<User>(O);
                //LU.push_back(OU);

                pair<size_t, size_t> preLTY;
                preLTY.first = 0; preLTY.second = 0;
                typeConfineInInitializer_rec(OU, preLTY);
            }
            

            // now consider if it is a bitcast from a function address
            if (BitCastOperator *CO = dyn_cast<BitCastOperator>(O)) {
                // Usually in @llvm.used global array, including message like
                // module author, module description, etc
                // Also could be casr from function to a pointer
                //OP<<" Unsupported bitcast: "<<*CO<<"\n";
                Type *ToTy = CO->getDestTy(), *FromTy = CO->getSrcTy();
                Value *Operand = CO->getOperand(0);
                //Do we need typeConfineInCast?
                //typeConfineInCast(FromTy,ToTy);
                
                // TODO: ? to test if all address-taken functions
                // are captured
                //OP<<"\nFromTy: "<<*FromTy<<"\n";
                //OP<<"Operand: "<<*Operand<<"\n";
                //checktype:
                if(Function *F = dyn_cast<Function>(Operand)){
                    //OP<<"from a function\n";
                    Type *ITy = U->getType();
                    unsigned ONo = oi->getOperandNo();
                    //OP<<"Case3: \n";
                    //OP<<"F: "<<*F<<"\n";
                    //OP<<"ITy: "<<*ITy<<"\n";
                    //OP<<"ONo: "<<ONo<<"\n";
                    typeFuncsMap[typeIdxHash(ITy, ONo)].insert(F);
                    if(StructType * st = dyn_cast<StructType>(ITy)){
                        if(ITy->getStructName().size() != 0){
                            typeFuncsMap[typeNameIdxHash(ITy, ONo)].insert(F);
                        }
                    }
                }
                /*else if(FromTy->isPointerTy()){
                    //OP<<"from a pointer\n";
                    FromTy = FromTy->getPointerElementType();

                    goto checktype;
                }*/
            }
        }
        else{
            //OP<<"--O4: "<<*O<<"\n";
        }
    }

    return true;
}