@echo off

echo ========== initialize Visual Studio environment ==========
if "%VisualStudio%" == "" (
    echo environment variable "VisualStudio" is not set
    exit /b 1
)
call "%VisualStudio%\VC\Auxiliary\Build\vcvars64.bat"

echo ================= clean builder old files ================
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "Release"
rd /S /Q "x64"

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

echo ================ clean builder output files ==============
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "Release"
rd /S /Q "x64"

echo ================ generate assembly module ================
go run dump.go

echo ===================== test shellcode =====================
call test.bat

echo ==========================================================
echo                  build shellcode finish!
echo ==========================================================
