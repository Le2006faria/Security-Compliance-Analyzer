@echo off
cls
setlocal

echo =====================================================
echo Script para Configuracoes de Seguranca - Hardening
echo =====================================================

echo.

:: Verifica se o script esta sendo executado com privilegios de administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Este script precisa ser executado como administrador.
    pause
    exit /b
)

echo.
echo =====================================================
:: Configurar expiracao de senha global para 30 dias
echo Configurando expiracao de senha para 30 dias...
net accounts /maxpwage:30
if %errorlevel% equ 0 (
    echo Expiracao de senha configurada com sucesso.
) else (
    echo Falha ao configurar expiracao de senha.
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

echo.
echo ================================================
:: Listar aplicativos instalados a partir do Registro
echo.
echo Listando aplicativos instalados a partir do Registro...
echo.

:: Lista os programas instalados no registro e exibe no terminal
for /f "tokens=*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "" /k') do (
    echo %%i
)

:: Lista programas de 32 bits em sistemas de 64 bits
for /f "tokens=*" %%i in ('reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "" /k') do (
    echo %%i
)

echo.
:: Perguntar ao usuario qual programa deseja remover
set /p program="Digite o nome do programa que deseja remover (ou aperte ENTER para pular): "

:: Se o nome do programa nao for vazio
if not "%program%"=="" (
    echo Tentando remover o programa: %program%

    :: Verifica no Registro e tenta desinstalar
    for /f "tokens=2,*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "%program%" /k ^| findstr /i "UninstallString"') do (
        set uninstall_cmd=%%j
    )

    :: Verifica no Registro para programas de 32 bits
    for /f "tokens=2,*" %%i in ('reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "%program%" /k ^| findstr /i "UninstallString"') do (
        set uninstall_cmd=%%j
    )

    :: Verifica se a string de desinstalacao foi encontrada
    if not "!uninstall_cmd!"=="" (
        echo Comando para desinstalar: !uninstall_cmd!
        :: Executa a desinstalacao
        call "!uninstall_cmd!"
        if %errorlevel% equ 0 (
            echo Programa removido com sucesso.
        ) else (
            echo Falha ao remover o programa.
        )
    ) else (
        echo Nao foi possivel encontrar o comando de desinstalacao.
    )
) else (
    echo Nenhum programa foi removido.
)

:: Verificar itens de inicializacao no Registro
echo.
echo ================================================
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
echo ================================================
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

:: Listar grupos locais
echo Listando Grupos Locais...
net localgroup
echo.

:: Solicita ao usuario para escolher um grupo local
set /p grupo="Digite o nome do grupo local para listar os membros: "
echo.

:: Lista os membros do grupo local escolhido
echo Membros do grupo %grupo%:
net localgroup "%grupo%"
echo.

:: Pergunta se o usuario deseja realizar alguma acao
echo Escolha uma opcao:
echo [1] Excluir um membro do grupo (remover do grupo, mas manter no sistema).
echo [2] Excluir um usuario completamente do sistema.
echo [3] Sair sem fazer alteracoes.
set /p opcao="Digite o numero da opcao desejada: "

if "%opcao%"=="1" (
    :: Remover membro do grupo
    set /p membro="Digite o nome do membro a ser removido do grupo: "
    echo.
    net localgroup "%grupo%" "%membro%" /delete
    if %errorlevel% equ 0 (
        echo Membro %membro% removido com sucesso do grupo %grupo%.
    ) else (
        echo Erro ao remover o membro %membro% do grupo %grupo%.
    )
) else if "%opcao%"=="2" (
    :: Excluir usuario completamente do sistema
    set /p usuario="Digite o nome do usuario a ser excluido: "
    echo.
    net user "%usuario%" /delete
    if %errorlevel% equ 0 (
        echo Usuario %usuario% excluido com sucesso do sistema.
    ) else (
        echo Erro ao excluir o usuario %usuario%.
    )
) else if "%opcao%"=="3" (
    echo Nenhuma alteracao foi feita. Saindo...
) else (
    echo Opcao invalida. Saindo...
)

echo.
echo ============================================

echo Verificando o status do servico Windows Defender...
sc query windefend >nul 2>&1
if %errorlevel% equ 0 (
    echo O servico Windows Defender esta ativado.
    
    :: Pergunta se o usuario deseja desativar o Windows Defender
    set /p action="Deseja desativar o Windows Defender? (S/N): "
    if /i "%action%"=="S" (
        echo Desativando o servico Windows Defender...
        sc stop windefend
        sc config windefend start= disabled
        echo Windows Defender desativado com sucesso.
    ) else (
        echo Nenhuma alteracao foi feita.
    )
) else (
    echo O servico Windows Defender NAO esta ativado ou nao foi encontrado.
    
    :: Pergunta se o usuario deseja ativar o Windows Defender
    set /p action="Deseja ativar o Windows Defender? (S/N): "
    if /i "%action%"=="S" (
        echo Ativando o servico Windows Defender...
        sc config windefend start= auto
        sc start windefend
        echo Windows Defender ativado com sucesso.
    ) else (
        echo Nenhuma alteracao foi feita.
    )
)

echo.
echo ============================================

echo Verificando o status do servico Windows Update...

sc query wuauserv >nul 2>&1
if %errorlevel% equ 0 (
    echo O servico Windows Update esta ativado.
    
    :: Pergunta se o usuario deseja desativar o Windows Update
    set /p action="Deseja desativar o Windows Update? (S/N): "
    if /i "%action%"=="S" (
        echo Desativando o servico Windows Update...
        sc stop wuauserv
        sc config wuauserv start= disabled
        echo Windows Update desativado com sucesso.
    ) else (
        echo Nenhuma alteracao foi feita.
    )
) else (
    echo O servico Windows Update NAO esta ativado ou nao foi encontrado.
    
    :: Pergunta se o usuario deseja ativar o Windows Update
    set /p action="Deseja ativar o Windows Update? (S/N): "
    if /i "%action%"=="S" (
        echo Ativando o servico Windows Update...
        sc config wuauserv start= auto
        sc start wuauserv
        echo Windows Update ativado com sucesso.
    ) else (
        echo Nenhuma alteracao foi feita.
    )
)

echo.
echo ============================================

echo Verificando configuracao do Windows Defender Antivirus...

:: Verificar a configuracao do Windows Defender
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" >nul 2>&1
if %errorlevel% equ 0 (
    echo O Windows Defender Antivirus esta habilitado.

    :: Perguntar ao usuario se deseja desabilitar o Windows Defender
    set /p action="Deseja desabilitar o Windows Defender Antivirus? (S/N): "
    if /i "%action%"=="S" (
        echo Desabilitando o Windows Defender Antivirus...
        reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
        echo Windows Defender Antivirus desabilitado com sucesso.
    ) else (
        echo Nenhuma alteracao foi feita.
    )
) else (
    echo O Windows Defender Antivirus esta desabilitado ou nao foi encontrado.

    :: Perguntar ao usuario se deseja habilitar o Windows Defender
    set /p action="Deseja habilitar o Windows Defender Antivirus? (S/N): "
    if /i "%action%"=="S" (
        echo Habilitando o Windows Defender Antivirus...
        reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
        echo Windows Defender Antivirus habilitado com sucesso.
    ) else (
        echo Nenhuma alteracao foi feita.
    )
)

echo.
echo ============================================

:: Exibir conexoes de rede ativas
echo === Conexoes de Rede Ativas ===
netstat -an
echo.
echo Deseja desativar alguma conexao especifica? (S/N)
set /p resposta=

if /i "%resposta%"=="S" (
    echo Digite o PID ou a porta da conexao que deseja desativar:
    set /p pid_port=
    echo Desativando conexao com PID ou porta: %pid_port%
    for /f "tokens=5" %%a in ('netstat -ano ^| find "%pid_port%"') do taskkill /PID %%a /F
    if %errorlevel% equ 0 (
        echo Conexao desativada com sucesso!
    ) else (
        echo Falha ao desativar a conexao. Verifique se o PID ou porta esta correto.
    )
) else (
    echo Nenhuma conexao foi desativada.
)

echo.
echo ============================================
:: Exibe as configuracoes de protocolos TLS/SSL
echo === Configuracoes atuais de TLS e SSL ===
echo.

:: Verifica as configuracoes de TLS no registro
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" /s
echo.

:: Pergunta ao usuario se deseja modificar as configuracoes
set /p "action=Voce deseja modificar as configuracoes de TLS/SSL? (S/N): "
if /i "%action%"=="S" (
    echo Escolha uma opcao para alterar a configuracao de TLS/SSL:
    echo 1. Habilitar/Desabilitar TLS 1.2
    echo 2. Habilitar/Desabilitar TLS 1.1
    echo 3. Habilitar/Desabilitar TLS 1.0
    echo 4. Habilitar/Desabilitar SSL 3.0
    echo 5. Habilitar/Desabilitar SSL 2.0
    echo 6. Habilitar TLS 1.3 (se disponivel)
    set /p "choice=Escolha o número da opcao (1-6): "
    
    if "%choice%"=="1" (
        set /p "enable=Habilitar (1) ou Desabilitar (0) TLS 1.2? "
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v "Enabled" /t REG_DWORD /d %enable% /f
        echo Configuracao de TLS 1.2 alterada.
    ) else if "%choice%"=="2" (
        set /p "enable=Habilitar (1) ou Desabilitar (0) TLS 1.1? "
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v "Enabled" /t REG_DWORD /d %enable% /f
        echo Configuracao de TLS 1.1 alterada.
    ) else if "%choice%"=="3" (
        set /p "enable=Habilitar (1) ou Desabilitar (0) TLS 1.0? "
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v "Enabled" /t REG_DWORD /d %enable% /f
        echo Configuracao de TLS 1.0 alterada.
    ) else if "%choice%"=="4" (
        set /p "enable=Habilitar (1) ou Desabilitar (0) SSL 3.0? "
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v "Enabled" /t REG_DWORD /d %enable% /f
        echo Configuracao de SSL 3.0 alterada.
    ) else if "%choice%"=="5" (
        set /p "enable=Habilitar (1) ou Desabilitar (0) SSL 2.0? "
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v "Enabled" /t REG_DWORD /d %enable% /f
        echo Configuracao de SSL 2.0 alterada.
    ) else if "%choice%"=="6" (
        echo TLS 1.3 esta disponivel apenas em versoes mais recentes do Windows. Se o seu Windows nao for compativel, essa opcao pode nao funcionar.
        set /p "enable=Habilitar (1) ou Desabilitar (0) TLS 1.3? "
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /v "Enabled" /t REG_DWORD /d %enable% /f
        echo Configuracao de TLS 1.3 alterada.
    ) else (
        echo Opcao invalida.
    )
) else (
    echo Nenhuma alteracao realizada.
)

echo.
echo ============================================
:: Listar servicos e protocolos associados
echo === Servicos e Protocolos Associados ===
netsh interface show interface
echo.
echo Deseja desativar algum servico listado? (S/N)
set /p resposta=

if /i "%resposta%"=="S" (
    echo Digite o nome do servico que deseja desativar:
    set /p servico=
    echo Desativando servico: %servico%
    sc stop "%servico%" >nul 2>&1
    sc config "%servico%" start= disabled >nul 2>&1
    if %errorlevel% equ 0 (
        echo Servico %servico% desativado com sucesso!
    ) else (
        echo Falha ao desativar o servico %servico%. Verifique o nome e tente novamente.
    )
) else (
    echo Nenhum servico foi desativado.
)

echo.
echo =====================================================
:: Verificar se o Controle de Conta de Usuario (UAC) esta ativado
echo Verificando o status do Controle de Conta de Usuario (UAC)...
:: Definir o caminho da chave de registro
set regKey="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
set regValue="EnableLUA"

:: Buscar e exibir o valor da chave
for /f "tokens=2*" %%A in ('reg query %regKey% /v %regValue% 2^>nul') do (
    echo O valor de %regValue% e: %%B
)
echo 0x1: Significa que o Controle de Conta de Usuario (UAC) esta ativado, porem, 
echo se 0x0: Significa que o Controle de Conta de Usuario (UAC) esta desativado.

echo.
echo ======================================================
echo Configurando o log de eventos de seguranca...

:: Define o tamanho maximo do log para 10 MB
wevtutil sl Security /ms:10485760

:: Ativa o arquivamento automatico
wevtutil sl Security /ca:true


echo .
echo ===========================================
echo Configurando o Windows Update...

:: Define o servico para iniciar automaticamente
sc config wuauserv start= auto
if %errorlevel% equ 0 (
    echo O servico Windows Update foi configurado para iniciar automaticamente.
) else (
    echo Falha ao configurar o servico para iniciar automaticamente.
)

:: Inicia o servico
net start wuauserv
if %errorlevel% equ 0 (
    echo O servico Windows Update foi iniciado com sucesso.
) else (
    echo Falha ao iniciar o servico Windows Update. Verifique as configuracoes ou permissoes.
)

echo .
echo ===========================================

:: Verificar se a unidade D: esta disponivel
if not exist D:\ (
    echo A unidade D: nao foi encontrada. O backup nao pode ser realizado.
    pause
    exit /b
)

:: Iniciar o backup
echo Iniciando backup de C: para D:\Backup...
wbadmin start backup -backupTarget:D:\Backup -include:C: -allCritical -quiet

:: Verificar o resultado do comando
if %errorlevel% equ 0 (
    echo Backup realizado com sucesso!
) else (
    echo Ocorreu um erro durante o backup.
)

echo .
echo ===========================================

:: Desativa a conta de convidado (Guest)
echo Desativando a conta Guest...
net user guest /active:no
if %errorlevel% equ 0 (
    echo Conta Guest desativada com sucesso.
) else (
    echo Falha ao desativar a conta Guest. Verifique as permissoes do usuario atual.
)

echo.

:: Desativa compartilhamentos administrativos automaticos
echo Desativando compartilhamentos administrativos automaticos...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f
if %errorlevel% equ 0 (
    echo Compartilhamentos administrativos desativados com sucesso.
) else (
    echo Falha ao desativar compartilhamentos administrativos. Verifique as permissoes do usuario atual.
)

echo.
echo ===========================================
echo Aplicando atualizacoes do Windows...

echo Executando o comando PowerShell para instalar e aplicar atualizacoes...
echo Este processo pode reiniciar o computador se necessario. Deseja continuar? (S/N)
set /p choice=
if /i not "%choice%"=="S" (
    echo Operacao cancelada pelo usuario.
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "Install-Module PSWindowsUpdate -Force; Import-Module PSWindowsUpdate; Get-WindowsUpdate -Install -AcceptAll -AutoReboot"

echo.
echo =====================================================
echo Configuracoes de seguranca aplicadas.
echo =====================================================

echo .
