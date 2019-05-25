#pragma once

#include "il2cpp-config.h"
#include "il2cpp-object-internals.h"
#include "il2cpp-api.h"
#include "il2cpp-config-api.h"
#include "vm/Method.h"

struct MethodBase_t;
struct Harmony_HarmonyLib_PatchInfo; // this is probably wrong
struct Il2CppReflectionDynamicMethod;

namespace il2cpp {
namespace icalls {
namespace harmony {

	class LIBIL2CPP_CODEGEN_API PatchFunctions
	{
	public:
		static Il2CppReflectionDynamicMethod* UpdateWrapper(MethodBase_t*, Harmony_HarmonyLib_PatchInfo*, Il2CppString*);
	};
}
}
}
