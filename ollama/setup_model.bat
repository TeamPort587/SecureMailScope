@echo off
echo ============================================================
echo   SecureMailScope - AI Copilot Model Setup
echo ============================================================
echo.

REM Step 1: Check if Ollama is running
echo [1/4] Checking if Ollama is running...
ollama list >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Ollama is not running or not installed.
    echo Please start the Ollama application and try again.
    echo.
    pause
    exit /b 1
)
echo       Ollama is running.
echo.

REM Step 2: Check if base model exists
echo [2/4] Checking for base model qwen2.5:3b...
ollama list > "%TEMP%\ollama_models.txt" 2>&1
findstr /i "qwen2.5" "%TEMP%\ollama_models.txt" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo       Base model not found. Pulling qwen2.5:3b...
    echo       This may take a few minutes depending on your connection.
    echo.
    ollama pull qwen2.5:3b
    if %ERRORLEVEL% NEQ 0 (
        echo.
        echo ERROR: Failed to pull qwen2.5:3b. Check your internet connection.
        pause
        exit /b 1
    )
) else (
    echo       Base model qwen2.5:3b already available.
)
echo.

REM Step 3: Build custom model
echo [3/4] Building mailscope-sec:3b from Modelfile...
ollama create mailscope-sec:3b -f "%~dp0Modelfile"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Failed to create custom model. Check the Modelfile.
    pause
    exit /b 1
)
echo       Custom model created successfully.
echo.

REM Step 4: Verify
echo [4/4] Verifying installation...
ollama list > "%TEMP%\ollama_models.txt" 2>&1
findstr /i "mailscope-sec" "%TEMP%\ollama_models.txt" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo WARNING: mailscope-sec:3b not found in model list.
    echo          Try running manually: ollama create mailscope-sec:3b -f Modelfile
    pause
    exit /b 1
)
echo       mailscope-sec:3b is ready!
echo.

REM Cleanup temp file
del "%TEMP%\ollama_models.txt" >nul 2>&1

echo ============================================================
echo   Setup complete! Available models:
echo ============================================================
ollama list
echo.
echo You can test it with:
echo   ollama run mailscope-sec:3b "What is STARTTLS downgrade?"
echo.
pause
