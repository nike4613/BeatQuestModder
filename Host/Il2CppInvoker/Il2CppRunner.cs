using NiceIO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Unity.IL2CPP;
using Unity.IL2CPP.Common.Profiles;

namespace Il2CppInvoker
{
    class Il2CppRunner
    {
        internal static void Run(string il2cppRoot, string[] searchDirs, string[] convertDirs)
        {
            var output = Path.Combine(Environment.CurrentDirectory, "output").ToNPath();
            var data = Path.Combine(Environment.CurrentDirectory, "data").ToNPath();
            var symbols = Path.Combine(Environment.CurrentDirectory, "symbols").ToNPath();
            var execs = Path.Combine(Environment.CurrentDirectory, "execs").ToNPath();

            var mono = Path.Combine(il2cppRoot, "..", "MonoBleedingEdge");
            var etc = Path.Combine(mono, "etc").ToNPath();
            var lib = Path.Combine(mono, "lib").ToNPath();

            var monoSearch = Path.Combine(mono, "lib", "mono", "4.5").ToNPath();

            CodeGenOptions.SetToDefaults();
            CodeGenOptions.Dotnetprofile = Profile.Net45.Name;
            CodeGenOptions.EmitMethodMap = true;
            CodeGenOptions.EmitNullChecks = true;
            CodeGenOptions.EmitSourceMapping = true;
            CodeGenOptions.EnableArrayBoundsCheck = true;
            CodeGenOptions.EnableDivideByZeroCheck = true;
            CodeGenOptions.EnablePrimitiveValueTypeGenericSharing = true;
            CodeGenOptions.EnableStacktrace = true;
            CodeGenOptions.MonoRuntime = false;

            NPath[] asms;
            using (Globals.Use()) // needed for il2cpp to behave
            {
                asms = AssemblyConverter.ConvertAssemblies(convertDirs, new NPath[0], output, data, symbols, execs,
                    lib, etc, searchDirs.Select(s => s.ToNPath()).Append(monoSearch).ToArray(), null, new NPath[0]).ToArray();
            }
        }
    }
}
