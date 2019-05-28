using Mono.Cecil;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Unity.IL2CPP;
using Unity.IL2CPP.Common;
using Unity.IL2CPP.Debugger;

namespace Il2CppInvoker
{
    internal static class SemiUniqueStableTokenGenerator
    {
        // Token: 0x06000483 RID: 1155 RVA: 0x000206C0 File Offset: 0x0001E8C0
        private static string GenerateForString(string str)
        {
            string result;
            using (SHA1 sha = SHA1.Create())
            {
                byte[] array = sha.ComputeHash(Encoding.UTF8.GetBytes(str));
                StringBuilder stringBuilder = new StringBuilder(array.Length * 2);
                foreach (byte b in array)
                {
                    stringBuilder.Append(b.ToString("X2"));
                }
                result = stringBuilder.ToString();
            }
            return result;
        }

        // Token: 0x06000484 RID: 1156 RVA: 0x0002073C File Offset: 0x0001E93C
        internal static string GenerateFor(TypeReference type)
        {
            return GenerateForString(type.AssemblyQualifiedName(""));
        }

        // Token: 0x06000485 RID: 1157 RVA: 0x0002074E File Offset: 0x0001E94E
        internal static string GenerateFor(MethodReference method)
        {
            return GenerateForString(method.AssemblyQualifiedName());
        }

        // Token: 0x06000486 RID: 1158 RVA: 0x0002075B File Offset: 0x0001E95B
        internal static string GenerateFor(string literal)
        {
            return GenerateForString(literal);
        }

        // Token: 0x06000487 RID: 1159 RVA: 0x00020764 File Offset: 0x0001E964
        internal static uint GenerateFor(SequencePointInfo sequencePoint)
        {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append(sequencePoint.Method.Module);
            if (sequencePoint.Method.IsGenericInstance)
            {
                stringBuilder.Append(sequencePoint.Method.GetElementMethod().FullName);
            }
            else
            {
                stringBuilder.Append(sequencePoint.Method.FullName);
            }
            stringBuilder.Append(sequencePoint.IlOffset);
            stringBuilder.Append(sequencePoint.Kind);
            stringBuilder.Append(sequencePoint.SourceFile);
            stringBuilder.AppendFormat("[{0};{1}]:[{2};{3}]", new object[]
            {
                sequencePoint.StartLine,
                sequencePoint.StartColumn,
                sequencePoint.EndLine,
                sequencePoint.EndColumn
            });
            return (uint)stringBuilder.ToString().GetStableHashCode();
        }
    }
}
