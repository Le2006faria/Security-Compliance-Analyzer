@echo off
cls
setlocal

echo =====================================================
echo Script para Configuracoes de Seguranca - Hardening
echo =====================================================

echo.

:: Configurar expiracao de senha global para 30 dias
echo Configurando expiracao de senha para 30 dias...
net accounts /maxpwage:30
if %errorlevel% equ 0 (
    echo Expiracao de senha configurada com sucesso.
) else (
    echo Falha ao configurar expiracao de senha.
)

echo.
:: Forcar alteracao de senha no próximo login para todos os usuarios
echo Configurando forca de alteracao de senha para todos os usuarios...
for /f "skip=4 tokens=1 delims= " %%u in ('net user') do (
    if "%%u" neq "" (
        net user %%u /logonpasswordchg:yes >nul 2>&1
        if %errorlevel% equ 0 (
            echo Alteracao de senha forcada para o usuario %%u.
        ) else (
            echo Falha ao forcar alteracao de senha para o usuario %%u.
        )
    )
)

echo.
echo =====================================================

echo Iniciando configuracoes de seguranca...

:: Renomear contas chamadas "Administrator" ou "Administrador"
echo Verificando e renomeando contas "Administrator" e "Administrador"...
wmic useraccount where name="Administrator" rename "user" >nul 2>&1
if %errorlevel% neq 0 (
    echo A conta "Administrator" nao foi encontrada ou nao pode ser renomeada.
) else (
    echo Conta "Administrator" renomeada para "user".
)

wmic useraccount where name="Administrador" rename "user" >nul 2>&1
if %errorlevel% neq 0 (
    echo A conta "Administrador" nao foi encontrada ou nao pode ser renomeada.
) else (
    echo Conta "Administrador" renomeada para "user".
)

echo.
echo =====================================================

:: Exigir senhas complexas
echo Configurando exigencia de senhas complexas...
secedit /export /areas SECURITYPOLICY /cfg config.cfg >nul 2>&1
if exist config.cfg (
    echo Arquivo de configuracao exportado. Modificando politicas...
    (
        for /f "delims=" %%A in (config.cfg) do (
            echo %%A | findstr /I /C:"PasswordComplexity" >nul && (
                echo PasswordComplexity = 1
            ) || echo %%A
        )
    ) > config_temp.cfg
    move /y config_temp.cfg config.cfg >nul
    secedit /configure /db secedit.sdb /cfg config.cfg /areas SECURITYPOLICY >nul 2>&1
    if %errorlevel% equ 0 (
        echo Senhas complexas configuradas com sucesso.
    ) else (
        echo Falha ao configurar senhas complexas.
    )
    del config.cfg
) else (
    echo Falha ao exportar politicas de seguranca.
)

echo.
echo =====================================================

:: Habilitar auditoria para alteracoes de contas
echo Configurando auditoria para alteracoes de contas...

for /f "tokens=*" %%A in ('auditpol /list /subcategory:* ^| findstr /I "Account Management Gerenciamento"') do (
    set subcategory=%%A
)

auditpol /set /subcategory:"%subcategory%" /success:enable /failure:enable >nul 2>&1
if %errorlevel% equ 0 (
    echo Auditoria configurada com sucesso.
) else (
    echo Falha ao configurar auditoria para alteracoes de contas.
)


echo.
echo =====================================================

:: Configurar bloqueio de contas apos tentativas de login falhadas
echo Configurando bloqueio de contas apos tentativas de login falhadas...
net accounts /lockoutthreshold:3 /lockoutduration:30 /lockoutwindow:30 >nul 2>&1
if %errorlevel% equ 0 (
    echo Bloqueio de contas configurado com sucesso.
) else (
    echo Falha ao configurar bloqueio de contas.
)

echo.

echo ================================================

:: Listar aplicativos instalados
echo.
echo Listando aplicativos instalados...
echo.
wmic product get name, version

:: Perguntar ao usuario qual programa deseja remover
echo.
set /p program="Digite o nome do programa que deseja remover (ou aperte ENTER para pular): "
if not "%program%"=="" (
    echo Tentando remover o programa: %program%
    wmic product where "name='%program%'" call uninstall
    if %errorlevel% equ 0 (
        echo Programa removido com sucesso.
    ) else (
        echo Falha ao remover o programa.
    )
)

:: Verificar itens de inicializacao no Registro
echo.
echo Verificando itens de inicializacao no Registro...
echo.
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

:: Perguntar ao usuario se deseja remover algum item de inicializacao
echo.
set /p regitem="Digite o nome do item de inicializacao que deseja remover (ou aperte ENTER para pular): "
if not "%regitem%"=="" (
    echo Tentando remover o item de inicializacao: %regitem%
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%regitem%" /f
    if %errorlevel% equ 0 (
        echo Item de inicializacao removido com sucesso.
    ) else (
        echo Falha ao remover o item de inicializacao.
    )
)

:: Listar todos os servicos
echo.
echo Listando todos os servicos...
echo.
sc query

:: Perguntar ao usuario qual servico deseja parar e excluir
echo.
set /p service="Digite o nome do servico que deseja parar e excluir (ou aperte ENTER para pular): "
if not "%service%"=="" (
    echo Tentando parar o servico: %service%
    sc stop "%service%"
    if %errorlevel% equ 0 (
        echo Servico parado com sucesso.
    ) else (
        echo Falha ao parar o servico.
    )

    echo Tentando excluir o servico: %service%
    sc delete "%service%"
    if %errorlevel% equ 0 (
        echo Servico excluido com sucesso.
    ) else (
        echo Falha ao excluir o servico.
    )
)

:: Limpeza de disco
echo.
echo =====================================================

echo Limpando a memoria do PC...
cleanmgr /sagerun:1
if %errorlevel% equ 0 (
    echo Limpeza realizada com sucesso.
) else (
    echo Falha na limpeza.
)

echo.
echo =====================================================

:: Verificar e corrigir arquivos do sistema
echo Verificando arquivos do sistema com o sfc /scannow...
sfc /scannow
if %errorlevel% equ 0 (
    echo A verificacao do sfc foi concluida com sucesso.
) else (
    echo A verificacao do sfc encontrou problemas.
)

echo.
echo =====================================================

:: Verificar e reparar a imagem do sistema
echo Verificando e reparando a imagem do sistema com o DISM...
DISM /Online /Cleanup-Image /RestoreHealth
if %errorlevel% equ 0 (
    echo A reparacao da imagem do sistema foi concluida com sucesso.
) else (
    echo A reparacao da imagem do sistema encontrou problemas.
)

echo.
echo =====================================================

echo Listando Grupos Locais...
net localgroup
echo.

:: Solicita ao usuario para escolher um grupo local para listar membros e permissoes
set /p grupo="Digite o nome do grupo local para listar os membros: "
echo.

:: Lista os membros do grupo local escolhido
echo Membros do grupo %grupo%:
net localgroup "%grupo%"
echo.

:: Pergunta se o usuario deseja excluir um membro ou remover permissoes
set /p acao="Deseja excluir um membro? (S/N): "
if /i "%acao%"=="S" (
    set /p membro="Digite o nome do membro a ser excluido ou ter permissao removida: "
    echo.
    :: Excluir membro do grupo
    net localgroup "%grupo%" "%membro%" /delete
    if %errorlevel% equ 0 (
        echo Membro %membro% removido com sucesso do grupo %grupo%.
    ) else (
        echo Erro ao remover o membro %membro%.
    )
) else (
    echo Nenhuma alteracao foi feita.
)

echo.
echo ============================================

echo Verificando o status do servico Windows Defender...
sc query windefend >nul 2>&1
if %errorlevel% equ 0 (
    echo O servico Windows Defender esta ativado.
) else (
    echo O servico Windows Defender NAO esta ativado ou nao foi encontrado.
)

echo.
echo ============================================

:: Verificar se o Windows Update esta ativado
echo Verificando o status do servico Windows Update...
sc query wuauserv >nul 2>&1
if %errorlevel% equ 0 (
    echo O servico Windows Update esta ativado.
) else (
    echo O servico Windows Update NAO esta ativado ou nao foi encontrado.
)

echo.
echo ============================================

:: Verificar configuracao do Windows Defender Antivirus
echo Verificando configuracao do Windows Defender Antivirus...
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" >nul 2>&1
if %errorlevel% equ 0 (
    echo O Windows Defender Antivirus esta habilitado.
) else (
    echo O Windows Defender Antivirus esta desabilitado ou nao foi encontrado.
)

echo.
echo ============================================

:: Verificar se o Controle de Conta de Usuario (UAC) esta ativado
echo Verificando o status do Controle de Conta de Usuario (UAC)...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >nul 2>&1
if %errorlevel% equ 0 (
    echo O Controle de Conta de Usuario (UAC) esta ativado.
) else (
    echo O Controle de Conta de Usuario (UAC) NAO esta ativado ou nao foi encontrado.
)

echo.

echo =====================================================
echo Configuracoes de seguranca aplicadas.
echo =====================================================

echo .
