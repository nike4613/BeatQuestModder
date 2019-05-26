﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace HarmonyLib.Internal
{
    /// <summary>Patch function helpers</summary>
	internal static class PatchFunctions
    {
        /// <summary>Adds a prefix</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="owner">The owner (Harmony ID)</param>
        /// <param name="info">The annotation info</param>
        ///
        internal static void AddPrefix(PatchInfo patchInfo, string owner, HarmonyMethod info)
        {
            if (info == null || info.method == null) return;

            var priority = info.priority == -1 ? Priority.Normal : info.priority;
            var before = info.before ?? new string[0];
            var after = info.after ?? new string[0];

            patchInfo.AddPrefix(info.method, owner, priority, before, after);
        }

        /// <summary>Removes a prefix</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="owner">The owner (Harmony ID)</param>
        ///
        internal static void RemovePrefix(PatchInfo patchInfo, string owner)
        {
            patchInfo.RemovePrefix(owner);
        }

        /// <summary>Adds a postfix</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="owner">The owner (Harmony ID)</param>
        /// <param name="info">The annotation info</param>
        ///
        internal static void AddPostfix(PatchInfo patchInfo, string owner, HarmonyMethod info)
        {
            if (info == null || info.method == null) return;

            var priority = info.priority == -1 ? Priority.Normal : info.priority;
            var before = info.before ?? new string[0];
            var after = info.after ?? new string[0];

            patchInfo.AddPostfix(info.method, owner, priority, before, after);
        }

        /// <summary>Removes a postfix</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="owner">The owner (Harmony ID)</param>
        ///
        internal static void RemovePostfix(PatchInfo patchInfo, string owner)
        {
            patchInfo.RemovePostfix(owner);
        }

        /// <summary>Adds a transpiler</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="owner">The owner (Harmony ID)</param>
        /// <param name="info">The annotation info</param>
        ///
        internal static void AddTranspiler(PatchInfo patchInfo, string owner, HarmonyMethod info)
        {
            if (info == null || info.method == null) return;

            var priority = info.priority == -1 ? Priority.Normal : info.priority;
            var before = info.before ?? new string[0];
            var after = info.after ?? new string[0];

            patchInfo.AddTranspiler(info.method, owner, priority, before, after);
        }

        /// <summary>Removes a transpiler</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="owner">The owner (Harmony ID)</param>
        ///
        internal static void RemoveTranspiler(PatchInfo patchInfo, string owner)
        {
            patchInfo.RemoveTranspiler(owner);
        }

        /// <summary>Adds a finalizer</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="owner">The owner (Harmony ID)</param>
        /// <param name="info">The annotation info</param>
        ///
        internal static void AddFinalizer(PatchInfo patchInfo, string owner, HarmonyMethod info)
        {
            if (info == null || info.method == null) return;

            var priority = info.priority == -1 ? Priority.Normal : info.priority;
            var before = info.before ?? new string[0];
            var after = info.after ?? new string[0];

            patchInfo.AddFinalizer(info.method, owner, priority, before, after);
        }

        /// <summary>Removes a finalizer</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="owner">The owner (Harmony ID)</param>
        ///
        internal static void RemoveFinalizer(PatchInfo patchInfo, string owner)
        {
            patchInfo.RemoveFinalizer(owner);
        }

        /// <summary>Removes a patch method</summary>
        /// <param name="patchInfo">The patch info</param>
        /// <param name="patch">The patch method</param>
        ///
        internal static void RemovePatch(PatchInfo patchInfo, MethodInfo patch)
        {
            patchInfo.RemovePatch(patch);
        }

        /// <summary>Gets sorted patch methods</summary>
        /// <param name="original">The original method</param>
        /// <param name="patches">Patches to sort</param>
        /// <returns>The sorted patch methods</returns>
        ///
        internal static List<MethodInfo> GetSortedPatchMethods(MethodBase original, Patch[] patches)
        {
            return new PatchSorter(patches).Sort(original);
        }

        /// <summary>Creates new dynamic method with the latest patches and detours the original method</summary>
        /// <param name="original">The original method</param>
        /// <param name="patchInfo">Information describing the patches</param>
        /// <param name="instanceID">Harmony ID</param>
        /// <returns>The newly created dynamic method</returns>
        ///
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal extern static DynamicMethod UpdateWrapper(MethodBase original, PatchInfo patchInfo, string instanceID);
    }
}
