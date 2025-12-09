rd  /S /Q ".vs\Gleam-RT\v17\ipch"
del /S /Q ".vs\Gleam-RT\v17\Browse.VC.db"
del /S /Q ".vs\Gleam-RT\v17\Solution.VC.db"

rd /S /Q "Debug"
rd /S /Q "Release"
rd /S /Q "x64"
rd /S /Q "x86"

rd /S /Q "builder\Debug"
rd /S /Q "builder\Release"
rd /S /Q "builder\x64"
rd /S /Q "builder\x86"

rd /S /Q "pe_loader\Debug"
rd /S /Q "pe_loader\Release"
rd /S /Q "pe_loader\x64"
rd /S /Q "pe_loader\x86"

rd /S /Q "test\Debug"
rd /S /Q "test\Release"
rd /S /Q "test\x64"
rd /S /Q "test\x86"

rd /S /Q "tool\test_dll\Debug"
rd /S /Q "tool\test_dll\Release"
rd /S /Q "tool\test_dll\x64"
rd /S /Q "tool\test_dll\x86"

rd /S /Q "tool\sc_loader\Debug"
rd /S /Q "tool\sc_loader\Release"
rd /S /Q "tool\sc_loader\x64"
rd /S /Q "tool\sc_loader\x86"