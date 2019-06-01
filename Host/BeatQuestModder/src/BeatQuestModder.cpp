// BeatQuestModder.cpp : Defines the entry point for the application.
//

#include "BeatQuestModder.h"
#include "bqm/capstone/Handle.h"
#include "buffer.h"
#include <iomanip>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/Reassociate.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Support/TargetSelect.h>

using namespace std;

constexpr auto code_buffer = "\x55\x48\x8b\x05\xb8\x13\x00\x00"_buffer;

int main()
{
	buffer<uint8_t> rw_buffer = code_buffer.reinterpret_as<uint8_t>();

	{
		capstone::ARMHandle handle;
		if (handle.Error() != CS_ERR_OK)
		{
			cerr << "Could not set up Capstone: " << handle.Error() << endl;
			return -1;
		}

		auto instructions = handle.Disassemble(rw_buffer, 0x1000);
		if (instructions.size() <= 0)


		{
			cerr << "Test code disassembled to nothing!" << endl;
			return -2;
		}

		for (auto instr : instructions)
		{
			cout << "0x" << hex << right << setw(8) << setfill('0') << instr.address << resetiosflags(cout.flags())
				<< ":\t" << instr.mnemonic << "\t    " << instr.op_str << endl;
		}

		rw_buffer[2] = 0x7b;

		instructions = handle.Disassemble(rw_buffer, 0x1000);
		if (instructions.size() <= 0)
		{
			cerr << "Test code disassembled to nothing!" << endl;
			return -2;
		}

		for (auto instr : instructions)
		{
			cout << "0x" << hex << right << setw(8) << setfill('0') << instr.address << resetiosflags(cout.flags())
				<< ":\t" << instr.mnemonic << "\t    " << instr.op_str << endl;
		}
	}

	{
		llvm::LLVMContext context;
		llvm::IRBuilder<> builder(context);
		auto module = llvm::make_unique<llvm::Module>("LLVM BC Module", context);

		llvm::InitializeAllTargetMCs();
		llvm::InitializeAllTargetInfos();
		llvm::InitializeAllTargets();

		auto targetTriple = llvm::Triple("armv7a-none-eabi");
		std::string error;
		const auto target = llvm::TargetRegistry::lookupTarget(targetTriple.getTriple(), error);
		
		llvm::TargetOptions opts{};
		opts.AllowFPOpFusion = llvm::FPOpFusion::Fast;
		opts.PrintMachineCode = true;

		auto machine = target->createTargetMachine(targetTriple.getTriple(), "", "", opts, llvm::None);
		module->setDataLayout(machine->createDataLayout());

		auto reg = llvm::PassRegistry::getPassRegistry();
		llvm::initializeCore(*reg);
		llvm::initializeCodeGen(*reg);
		/*llvm::initializeLoopStrengthReducePass(*reg);
		llvm::initializeLowerIntrinsicsPass(*reg);
		//llvm::initializeEntryExitInstrumenterPass(*reg);
		//llvm::initializePostInlineEntryExitInstrumenterPass(*reg);
		llvm::initializeUnreachableBlockElimLegacyPassPass(*reg);
		llvm::initializeConstantHoistingLegacyPassPass(*reg);
		llvm::initializeScalarOpts(*reg);
		llvm::initializeVectorization(*reg);
		llvm::initializeScalarizeMaskedMemIntrinPass(*reg);
		llvm::initializeExpandReductionsPass(*reg);*/

		llvm::initializeTarget(*reg);

		llvm::PassBuilder passes(machine);

		auto fpm = passes.buildFunctionSimplificationPipeline(llvm::PassBuilder::O3, llvm::PassBuilder::ThinLTOPhase::None, true);
		auto fam = llvm::FunctionAnalysisManager(true);
		passes.registerFunctionAnalyses(fam);

		auto i32 = llvm::Type::getInt32Ty(context);
		auto func = llvm::Function::Create(llvm::FunctionType::get(i32, false), llvm::Function::LinkageTypes::ExternalLinkage, "TestFunc", module.get());
		func->setDoesNotRecurse();
		auto fnBlock = llvm::BasicBlock::Create(context, "entry", func);
		builder.SetInsertPoint(fnBlock);

		auto retConst = llvm::ConstantInt::get(i32, llvm::APInt(32, 15, true));
		auto retInst = builder.CreateRet(retConst);

		llvm::verifyFunction(*func);
		fpm.run(*func, fam); // something is wrong with this setup

		module->print(llvm::outs(), nullptr);
	}

	return 0;
}
