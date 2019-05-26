using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace HarmonyLib
{
    /// <summary>A collection of commonly used transpilers</summary>
	public static class Transpilers
    {
        /// <summary>A transpiler that replaces all occurrences of a given method with another one</summary>
        /// <param name="instructions">The instructions to act on</param>
        /// <param name="from">Method or constructor to search for</param>
        /// <param name="to">Method or constructor to replace with</param>
        /// <returns>Modified instructions</returns>
        ///
        public static IEnumerable<CodeInstruction> MethodReplacer(this IEnumerable<CodeInstruction> instructions, MethodBase from, MethodBase to)
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>A transpiler that alters instructions that match a predicate by calling an action</summary>
        /// <param name="instructions">The instructions to act on</param>
        /// <param name="predicate">A predicate selecting the instructions to change</param>
        /// <param name="action">An action to apply to matching instructions</param>
        /// <returns>Modified instructions</returns>
        ///
        public static IEnumerable<CodeInstruction> Manipulator(this IEnumerable<CodeInstruction> instructions, Func<CodeInstruction, bool> predicate, Action<CodeInstruction> action)
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>A transpiler that logs a text at the beginning of the method</summary>
        /// <param name="instructions">The instructions to act on</param>
        /// <param name="text">The log text</param>
        /// <returns>Modified instructions</returns>
        ///
        public static IEnumerable<CodeInstruction> DebugLogger(this IEnumerable<CodeInstruction> instructions, string text)
        {
            throw new PlatformNotSupportedException();
        }

        // more added soon
    }
}
