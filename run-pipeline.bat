@echo off
cd /d c:\Users\RAVE\Desktop\Ravehunts\earnproof-backend

echo Running: npm run prisma:generate
call npm run prisma:generate
if errorlevel 1 (
  echo PRISMA GENERATE FAILED with exit code %ERRORLEVEL%
  exit /b 1
)

echo.
echo Running: npm run lint
call npm run lint
if errorlevel 1 (
  echo LINT FAILED with exit code %ERRORLEVEL%
  exit /b 1
)

echo.
echo Running: npm run test -- --runInBand
call npm run test -- --runInBand
if errorlevel 1 (
  echo TEST FAILED with exit code %ERRORLEVEL%
  exit /b 1
)

echo.
echo Running: npm run build
call npm run build
if errorlevel 1 (
  echo BUILD FAILED with exit code %ERRORLEVEL%
  exit /b 1
)

echo.
echo ALL PIPELINE STEPS PASSED!
exit /b 0
