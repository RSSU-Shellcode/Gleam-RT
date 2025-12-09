@echo off

echo ========== initialize Visual Studio environment ==========
if "%VisualStudio%" == "" (
    echo environment variable "VisualStudio" is not set
    exit /b 1
)
call "%VisualStudio%\VC\Auxiliary\Build\vcvars64.bat"

echo ==================== clean old files =====================
rd /S /Q "Release"
rd /S /Q "x64"
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "tool\test_dll\Release"
rd /S /Q "tool\test_dll\x64"

echo ==================== generate builder ====================
MSBuild.exe Gleam-RT.sln /t:builder /p:Configuration=Release /p:Platform=x86
MSBuild.exe Gleam-RT.sln /t:builder /p:Configuration=Release /p:Platform=x64

echo ================ extract runtime shellcode ===============
del /S /Q dist
cd builder
echo --------extract shellcode for x86--------
"..\Release\builder.exe"
echo --------extract shellcode for x64--------
"..\x64\Release\builder.exe"
cd ..

echo =================== generate test dll ====================
MSBuild.exe Gleam-RT.sln /t:test_dll /p:Configuration=Release /p:Platform=x86
MSBuild.exe Gleam-RT.sln /t:test_dll /p:Configuration=Release /p:Platform=x64
copy Release\test_dll.dll     dist\GleamRT_x86.dll
copy x64\Release\test_dll.dll dist\GleamRT_x64.dll

echo =================== clean output files ===================
rd /S /Q "Release"
rd /S /Q "x64"
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "tool\test_dll\Release"
rd /S /Q "tool\test_dll\x64"

echo ================ generate assembly module ================
go run dump.go

echo ================== test runtime package ==================
call test.bat

echo ==========================================================
echo                  build shellcode finish!
echo ==========================================================
