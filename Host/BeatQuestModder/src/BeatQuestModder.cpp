// BeatQuestModder.cpp : Defines the entry point for the application.
//

#include "BeatQuestModder.h"
#include "bqm/capstone/Handle.h"
#include "buffer.h"
#include <iomanip>

using namespace std;

auto code_buffer = "\x55\x48\x8b\x05\xb8\x13\x00\x00"_buffer.reinterpret_as<uint8_t>();

int main()
{
	buffer<uint8_t> rw_buffer = code_buffer;

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

	cout << "Hello CMake." << endl;
	return 0;
}
