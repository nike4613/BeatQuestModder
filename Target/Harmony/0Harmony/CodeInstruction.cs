using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace HarmonyLib
{
    public class CodeInstruction
    {
        /// <summary>The opcode</summary>
        public OpCode opcode;
        /// <summary>The operand</summary>
        public object operand;
        /// <summary>All labels defined on this instruction</summary>
        public List<Label> labels = new List<Label>();
        /// <summary>All exception block boundaries defined on this instruction</summary>
        public List<ExceptionBlock> blocks = new List<ExceptionBlock>();

        /// <summary>Creates a new CodeInstruction with a given opcode and optional operand</summary>
        /// <param name="opcode">The code</param>
        /// <param name="operand">The operand</param>
        ///
        public CodeInstruction(OpCode opcode, object operand = null)
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>Create a full copy (including labels and exception blocks) of a CodeInstruction</summary>
        /// <param name="instruction">The instruction to copy</param>
        ///
        public CodeInstruction(CodeInstruction instruction)
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>Clones a CodeInstruction and resets its labels and exception blocks</summary>
        /// <returns>A lightweight copy of this code instruction</returns>
        ///
        public CodeInstruction Clone()
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>Clones a CodeInstruction, resets labels and exception blocks and sets its opcode</summary>
        /// <param name="opcode">The opcode</param>
        /// <returns>A copy of this CodeInstruction with a new opcode</returns>
        ///
        public CodeInstruction Clone(OpCode opcode)
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>Clones a CodeInstruction, resets labels and exception blocks and sets its operand</summary>
        /// <param name="operand">The opcode</param>
        /// <returns>A copy of this CodeInstruction with a new operand</returns>
        ///
        public CodeInstruction Clone(object operand)
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>Returns a string representation of the code instruction</summary>
        /// <returns>A string representation of the code instruction</returns>
        ///
        public override string ToString()
        {
            throw new PlatformNotSupportedException();
        }
    }
}
