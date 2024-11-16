:: Verificar se o Controle de Conta de Usuario (UAC) esta ativado
echo Verificando o status do Controle de Conta de Usuario (UAC)...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >nul 2>&1
if %errorlevel% equ 0 (
    echo O Controle de Conta de Usuario (UAC) esta ativado.
) else (
    echo O Controle de Conta de Usuario (UAC) NAO esta ativado ou nao foi encontrado.
)
