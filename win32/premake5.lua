workspace "micro-web-server"
   configurations { "Release" }
   platforms { "Win32", "x64" }
   location "build"
   objdir ("build/obj")
   buildlog ("build/log/%{prj.name}.log")

   characterset ("MBCS")
   staticruntime "Off"
   exceptionhandling "Off"
   floatingpoint "Fast"
   intrinsics "On"
   rtti "Off"
   omitframepointer "On"
   flags { "NoBufferSecurityCheck", "NoIncrementalLink", "NoManifest", "NoPCH", "NoRuntimeChecks", "OmitDefaultLibrary" }
   buildoptions { "/kernel /Gs1000000" }
   linkoptions { "/SAFESEH:NO", "/EMITPOGOPHASEINFO", "/RELEASE", "/DEBUG:NONE" }

   filter "configurations:Release"
      runtime "Release"
      defines "NDEBUG"
      optimize "Speed"
      symbols "Off"

   filter "platforms:Win32"
      architecture "x86"
      libdirs { "lib/Win32" }
      targetdir "bin/Win32"

   filter "platforms:x64"
      architecture "x64"
      libdirs { "lib/x64" }
      targetdir "bin/x64"

project "micro-web-server"
   kind "ConsoleApp"
   language "C"
   targetname "server"
   targetextension ".exe"
   files { "../server.c", "../server.h", "../server_config.h" }
