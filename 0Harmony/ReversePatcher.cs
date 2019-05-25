using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace HarmonyLib
{
    static class ReversePatcherExtensions
    {
        /// <summary>Creates an empty reverse patcher</summary>
        /// <param name="instance">The Harmony instance</param>
        /// <param name="original">The original method</param>
        /// <param name="standin">The stand-in method</param>
        ///
        public static ReversePatcher CreateReversePatcher(this Harmony instance, MethodBase original, MethodInfo standin)
        {
            throw new PlatformNotSupportedException();
        }
    }

    /// <summary>A reverse patcher</summary>
    public class ReversePatcher
    {
        readonly Harmony instance;
        readonly MethodBase original;
        readonly MethodInfo standin;

        /// <summary>Creates an empty reverse patcher</summary>
        /// <param name="instance">The Harmony instance</param>
        /// <param name="original">The original method</param>
        /// <param name="standin">The stand-in method</param>
        ///
        public ReversePatcher(Harmony instance, MethodBase original, MethodInfo standin)
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>Applies the patch</summary>
        ///
        public void Patch(HarmonyReversePatchType type = HarmonyReversePatchType.Original)
        {
            throw new PlatformNotSupportedException();
        }

        internal MethodInfo GetTranspiler(MethodInfo method)
        {
            throw new PlatformNotSupportedException();
        }
    }

}
