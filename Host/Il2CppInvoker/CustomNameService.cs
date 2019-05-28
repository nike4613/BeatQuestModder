using System;

using Unity.IL2CPP;
using Unity.IL2CPP.IoCServices;
using Unity.IL2CPP.Common.Profiles;
using Mono.Cecil;
using System.Text;
using System.Collections.Generic;
using Unity.IL2CPP.Common;

namespace Il2CppInvoker
{
    class CustomNameService : INamingService, IDisposable
    {// Token: 0x060006A7 RID: 1703 RVA: 0x000302C4 File Offset: 0x0002E4C4
        public void Dispose()
        {
            this._cleanNamesCache.Clear();
            this._methodNameOnlyCache.Clear();
            this._typeNameOnlyCache.Clear();
            this._stringLiteralCache.Clear();
            this._typeHashCache.Clear();
            this._methodHashCache.Clear();
            this._stringLiteralHashCache.Clear();
        }

        // Token: 0x060006A8 RID: 1704 RVA: 0x00030320 File Offset: 0x0002E520
        public string ForTypeNameOnly(TypeReference type)
        {
            string text;
            if (this._typeNameOnlyCache.TryGetValue(type, out text))
            {
                return text;
            }
            text = this.ForTypeNameInternal(type);
            this._typeNameOnlyCache[type] = text;
            return text;
        }

        // Token: 0x060006A9 RID: 1705 RVA: 0x00030358 File Offset: 0x0002E558
        public string ForMethodNameOnly(MethodReference method)
        {
            string result;
            if (this._methodNameOnlyCache.TryGetValue(method, out result))
            {
                return result;
            }
            string text = this.ForMethodInternal(method);
            this._methodNameOnlyCache[method] = text;
            return text;
        }

        // Token: 0x060006AA RID: 1706 RVA: 0x00030390 File Offset: 0x0002E590
        public string Clean(string name)
        {
            if (this._cleanNamesCache.ContainsKey(name))
            {
                return this._cleanNamesCache[name];
            }
            StringBuilder stringBuilder = this._cleanStringBuilder.Clear();
            char[] array = name.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                char c = array[i];
                if (IsSafeCharacter(c) || (IsAsciiDigit(c) && i != 0))
                {
                    stringBuilder.Append(c);
                }
                else
                {
                    ushort num = Convert.ToUInt16(c);
                    if (num < 255)
                    {
                        if (num == 46 || num == 47 || num == 96 || num == 95)
                        {
                            stringBuilder.Append("_");
                        }
                        else
                        {
                            stringBuilder.AppendFormat("U{0:X2}", num);
                        }
                    }
                    else if (num < 4095)
                    {
                        stringBuilder.AppendFormat("U{0:X3}", num);
                    }
                    else
                    {
                        stringBuilder.AppendFormat("U{0:X4}", num);
                    }
                }
            }
            string text = stringBuilder.ToString();
            this._cleanNamesCache[name] = text;
            return text;
        }

        // Token: 0x060006AB RID: 1707 RVA: 0x00030498 File Offset: 0x0002E698
        public string ForStringLiteralIdentifier(string literal)
        {
            string result;
            if (this._stringLiteralCache.TryGetValue(literal, out result))
            {
                return result;
            }
            string text = "_stringLiteral" + this.GenerateUniqueStringLiteralPostFix(literal);
            this._stringLiteralCache[literal] = text;
            return text;
        }

        // Token: 0x060006AC RID: 1708 RVA: 0x000304D7 File Offset: 0x0002E6D7
        internal static bool IsSafeCharacter(char c)
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
        }

        // Token: 0x060006AD RID: 1709 RVA: 0x000304F4 File Offset: 0x0002E6F4
        internal static bool IsAsciiDigit(char c)
        {
            return c >= '0' && c <= '9';
        }

        // Token: 0x060006AE RID: 1710 RVA: 0x00030505 File Offset: 0x0002E705
        internal static string EscapeKeywords(string fieldName)
        {
            return "___" + fieldName;
        }

        internal static uint ComputeStringHash(string s)
        {
            uint num = 0;
            if (s != null)
            {
                num = 2166136261u;
                for (int i = 0; i < s.Length; i++)
                {
                    num = ((uint)s[i] ^ num) * 16777619u;
                }
            }
            return num;
        }

        // Token: 0x060006AF RID: 1711 RVA: 0x00030514 File Offset: 0x0002E714
        private static string GetWellKnownNameFor(TypeReference typeReference)
        {
            MetadataType metadataType = typeReference.MetadataType;
            if (metadataType == MetadataType.String)
            {
                return "String_t";
            }
            switch (metadataType)
            {
                case MetadataType.IntPtr:
                    return "IntPtr_t";
                case MetadataType.UIntPtr:
                    return "UIntPtr_t";
                case MetadataType.Object:
                    return "RuntimeObject";
            }
            TypeDefinition typeDefinition = typeReference.Resolve();
            if (typeDefinition != null && typeDefinition.Module != null && typeDefinition.Module.Name == "mscorlib.dll")
            {
                string fullName = typeReference.FullName;
                uint num = ComputeStringHash(fullName);
                if (num <= 1688798982u)
                {
                    if (num <= 820045441u)
                    {
                        if (num <= 600459548u)
                        {
                            if (num != 459109453u)
                            {
                                if (num == 600459548u)
                                {
                                    if (fullName == "System.Reflection.MonoGenericMethod")
                                    {
                                        return "MonoGenericMethod_t";
                                    }
                                }
                            }
                            else if (fullName == "System.Reflection.FieldInfo")
                            {
                                return "FieldInfo_t";
                            }
                        }
                        else if (num != 715069371u)
                        {
                            if (num != 797836191u)
                            {
                                if (num == 820045441u)
                                {
                                    if (fullName == "System.Delegate")
                                    {
                                        return "Delegate_t";
                                    }
                                }
                            }
                            else if (fullName == "System.Exception")
                            {
                                return "Exception_t";
                            }
                        }
                        else if (fullName == "System.Text.StringBuilder")
                        {
                            return "StringBuilder_t";
                        }
                    }
                    else if (num <= 1336056408u)
                    {
                        if (num != 1261010025u)
                        {
                            if (num == 1336056408u)
                            {
                                if (fullName == "System.Reflection.MonoField")
                                {
                                    return "MonoField_t";
                                }
                            }
                        }
                        else if (fullName == "System.Reflection.EventInfo")
                        {
                            return "EventInfo_t";
                        }
                    }
                    else if (num != 1558115797u)
                    {
                        if (num != 1577415417u)
                        {
                            if (num == 1688798982u)
                            {
                                if (fullName == "System.Type")
                                {
                                    return "Type_t";
                                }
                            }
                        }
                        else if (fullName == "System.Reflection.MemberInfo")
                        {
                            return "MemberInfo_t";
                        }
                    }
                    else if (fullName == "System.Reflection.MonoProperty")
                    {
                        return "MonoProperty_t";
                    }
                }
                else if (num <= 2856089276u)
                {
                    if (num <= 2296957535u)
                    {
                        if (num != 2046745842u)
                        {
                            if (num == 2296957535u)
                            {
                                if (fullName == "System.Reflection.Assembly")
                                {
                                    return "Assembly_t";
                                }
                            }
                        }
                        else if (fullName == "System.Reflection.PropertyInfo")
                        {
                            return "PropertyInfo_t";
                        }
                    }
                    else if (num != 2699327850u)
                    {
                        if (num != 2736390927u)
                        {
                            if (num == 2856089276u)
                            {
                                if (fullName == "System.Reflection.MonoEvent")
                                {
                                    return "MonoEvent_t";
                                }
                            }
                        }
                        else if (fullName == "System.Guid")
                        {
                            return "Guid_t";
                        }
                    }
                    else if (fullName == "System.Reflection.MethodInfo")
                    {
                        return "MethodInfo_t";
                    }
                }
                else if (num <= 4115558641u)
                {
                    if (num != 3027935821u)
                    {
                        if (num != 4110735607u)
                        {
                            if (num == 4115558641u)
                            {
                                if (fullName == "System.MonoType")
                                {
                                    return "MonoType_t";
                                }
                            }
                        }
                        else if (fullName == "System.MulticastDelegate")
                        {
                            return "MulticastDelegate_t";
                        }
                    }
                    else if (fullName == "System.Reflection.MonoMethod")
                    {
                        return "MonoMethod_t";
                    }
                }
                else if (num != 4133326831u)
                {
                    if (num != 4201364391u)
                    {
                        if (num == 4258047999u)
                        {
                            if (fullName == "System.Array")
                            {
                                return "RuntimeArray";
                            }
                        }
                    }
                    else if (fullName == "System.String")
                    {
                        return "String_t";
                    }
                }
                else if (fullName == "System.Reflection.MethodBase")
                {
                    return "MethodBase_t";
                }
            }
            if (typeReference.IsIActivationFactory())
            {
                return "Il2CppIActivationFactory";
            }
            if (typeReference.IsIl2CppComObject())
            {
                return "Il2CppComObject";
            }
            return null;
        }

        // Token: 0x060006B0 RID: 1712 RVA: 0x00030934 File Offset: 0x0002EB34
        private string ForMethodInternal(MethodReference method)
        {
            GenericInstanceMethod genericInstanceMethod = method as GenericInstanceMethod;
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append(this.Clean(method.DeclaringType.Name));
            stringBuilder.Append("_");
            stringBuilder.Append(this.Clean(method.Name));
            if (genericInstanceMethod != null)
            {
                foreach (TypeReference type in genericInstanceMethod.GenericArguments)
                {
                    stringBuilder.Append("_Tis" + this.ForTypeNameOnly(type));
                }
            }
            stringBuilder.Append("_m");
            stringBuilder.Append(this.GenerateUniqueMethodPostFix(method));
            return stringBuilder.ToString();
        }

        // Token: 0x060006B1 RID: 1713 RVA: 0x00030A00 File Offset: 0x0002EC00
        private string ForTypeNameInternal(TypeReference typeReference)
        {
            string wellKnownNameFor = GetWellKnownNameFor(typeReference);
            if (wellKnownNameFor != null)
            {
                return wellKnownNameFor;
            }
            return this.Clean(typeReference.Name) + "_t" + this.GenerateUniqueTypePostFix(typeReference);
        }

        // Token: 0x060006B2 RID: 1714 RVA: 0x00030A36 File Offset: 0x0002EC36
        private string GenerateUniqueTypePostFix(TypeReference typeReference)
        {
            return this._typeHashCache.GetUniqueHash(typeReference);
        }

        // Token: 0x060006B3 RID: 1715 RVA: 0x00030A44 File Offset: 0x0002EC44
        private string GenerateUniqueMethodPostFix(MethodReference methodReference)
        {
            return this._methodHashCache.GetUniqueHash(methodReference);
        }

        // Token: 0x060006B4 RID: 1716 RVA: 0x00030A52 File Offset: 0x0002EC52
        private string GenerateUniqueStringLiteralPostFix(string literal)
        {
            return this._stringLiteralHashCache.GetUniqueHash(literal);
        }

        // Token: 0x040001DC RID: 476
        private readonly Dictionary<string, string> _cleanNamesCache = new Dictionary<string, string>();

        // Token: 0x040001DD RID: 477
        private readonly Dictionary<MethodReference, string> _methodNameOnlyCache = new Dictionary<MethodReference, string>(new MethodReferenceComparer());

        // Token: 0x040001DE RID: 478
        private readonly Dictionary<TypeReference, string> _typeNameOnlyCache = new Dictionary<TypeReference, string>(new TypeReferenceEqualityComparer());

        // Token: 0x040001DF RID: 479
        private readonly Dictionary<string, string> _stringLiteralCache = new Dictionary<string, string>();

        // Token: 0x040001E0 RID: 480
        private readonly HashCodeCache<TypeReference> _typeHashCache = new HashCodeCache<TypeReference>(new Func<TypeReference, string>(SemiUniqueStableTokenGenerator.GenerateFor), delegate (uint notUsed)
        {
            IStatsService statsService = Globals.StatsService;
            int typeHashCollisions = statsService.TypeHashCollisions;
            statsService.TypeHashCollisions = typeHashCollisions + 1;
        }, new TypeReferenceEqualityComparer());

        // Token: 0x040001E1 RID: 481
        private readonly HashCodeCache<MethodReference> _methodHashCache = new HashCodeCache<MethodReference>(new Func<MethodReference, string>(SemiUniqueStableTokenGenerator.GenerateFor), delegate (uint notUsed)
        {
            IStatsService statsService = Globals.StatsService;
            int methodHashCollisions = statsService.MethodHashCollisions;
            statsService.MethodHashCollisions = methodHashCollisions + 1;
        }, new MethodReferenceComparer());

        // Token: 0x040001E2 RID: 482
        private readonly HashCodeCache<string> _stringLiteralHashCache = new HashCodeCache<string>(new Func<string, string>(SemiUniqueStableTokenGenerator.GenerateFor), delegate (uint notUsed)
        {
            IStatsService statsService = Globals.StatsService;
            int methodHashCollisions = statsService.MethodHashCollisions;
            statsService.MethodHashCollisions = methodHashCollisions + 1;
        });

        // Token: 0x040001E3 RID: 483
        private readonly StringBuilder _cleanStringBuilder = new StringBuilder();
    }
}