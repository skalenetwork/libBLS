: '
This is the patch that is applied below. 
Assumes the script is run from build_em/ directory

--- a/deps/deps_inst/x86_or_x64/include/mcl/gmp_util.hpp
+++ b/deps/deps_inst/x86_or_x64/include/mcl/gmp_util.hpp
@@ -24,7 +24,11 @@
 
-#if defined(__EMSCRIPTEN__) || defined(__wasm__)
-	#define MCL_USE_VINT
-#endif
+#if (defined(__EMSCRIPTEN__) || defined(__wasm__))
+  /* On WASM, MCL defaults to Vint. Allow explicit override. */
+  #ifndef MCL_USE_GMP
+    #define MCL_USE_VINT
+  #endif
+#endif

'


sed -i '/#if defined(__EMSCRIPTEN__) || defined(__wasm__)/,/#endif/c\
#if (defined(__EMSCRIPTEN__) || defined(__wasm__))\
  /* On WASM, MCL defaults to Vint. Allow explicit override. */\
  #ifndef MCL_USE_GMP\
    #define MCL_USE_VINT\
  #endif\
#endif' ../deps/deps_inst/x86_or_x64/include/mcl/gmp_util.hpp
