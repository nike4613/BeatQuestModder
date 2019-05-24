using System;
using System.IO;
using System.Reflection;

namespace Il2CppInvoker
{
    class Program
    {
        private const string FilePathStoreFile = "il2cpp.path";
        static void Main(string[] args)
        {
            string il2cppPath;
            if (File.Exists(FilePathStoreFile))
                il2cppPath = File.ReadAllText(FilePathStoreFile);
            else
            {
                Console.WriteLine("Put the full path to your IL2CPP folder here (contains il2cpp_root an libil2cpp folder):");
                Console.Write("> ");
                il2cppPath = Console.ReadLine();
                File.WriteAllText(FilePathStoreFile, il2cppPath);
            }

            var build = Path.Combine(il2cppPath, "build");
            var buildAsDir = new DirectoryInfo(build);

            foreach(var dll in buildAsDir.EnumerateFiles("*.dll"))
                Assembly.LoadFrom(dll.FullName);

            RunnerProxy(il2cppPath, new string[0], new[] { build });
        }

        private static void RunnerProxy(string il2cppRoot, string[] searchDirs, string[] convertDirs)
        {
            Il2CppRunner.Run(il2cppRoot, searchDirs, convertDirs);
        }
    }
}
