$ErrorActionPreference = "Stop"

Write-Host "=== Running prisma:generate ===" -ForegroundColor Green
npm run prisma:generate
if ($LASTEXITCODE -ne 0) {
    Write-Host "prisma:generate FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "prisma:generate PASSED" -ForegroundColor Green

Write-Host "`n=== Running lint ===" -ForegroundColor Green
npm run lint
if ($LASTEXITCODE -ne 0) {
    Write-Host "lint FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "lint PASSED" -ForegroundColor Green

Write-Host "`n=== Running tests ===" -ForegroundColor Green
npm run test -- --runInBand
if ($LASTEXITCODE -ne 0) {
    Write-Host "tests FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "tests PASSED" -ForegroundColor Green

Write-Host "`n=== Running build ===" -ForegroundColor Green
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "build FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "build PASSED" -ForegroundColor Green

Write-Host "`n=== ALL CHECKS PASSED ===" -ForegroundColor Green
