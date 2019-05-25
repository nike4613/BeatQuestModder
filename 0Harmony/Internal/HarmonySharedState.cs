using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace HarmonyLib.Internal
{
    internal static class HarmonySharedState
    {
        static readonly string name = "HarmonySharedState";
        internal static readonly int internalVersion = 100;
        internal static int actualVersion = -1;

        internal static Dictionary<MethodBase, PatchInfo> state;

        internal static PatchInfo GetPatchInfo(MethodBase method)
        {
            if (state.TryGetValue(method, out var info)) return info;
            return null;
        }

        internal static IEnumerable<MethodBase> GetPatchedMethods()
        {
            return state.Keys.AsEnumerable();
        }

        internal static void UpdatePatchInfo(MethodBase method, PatchInfo patchInfo)
        {
            state[method] = patchInfo;
        }
    }

}
