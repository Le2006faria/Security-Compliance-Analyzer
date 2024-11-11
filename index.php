<!DOCTYPE html>
<html lang="pt-br">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Página de Análise de Segurança</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>

    <div class="container">
        <div class="header">Análise completa da Segurança da Infraestrutura de Backup</div>
        <button onclick="startProgress()">Fazer análise</button>
    </div>

    <!-- Barra de progresso -->
    <div class="progress" id="progress-container" style="display: none;">
        <div class="progress-bar" id="myBar" role="progressbar" style="width: 0%" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
    </div>

    <script>
        // Função para iniciar o progresso e redirecionar enquanto a barra é preenchida
        function startProgress() {
            var elem = document.getElementById("myBar");
            var progressContainer = document.getElementById("progress-container");
            var width = 0;

            // Exibe a barra de progresso
            progressContainer.style.display = "block";

            // Função que simula o preenchimento da barra de progresso
            var id = setInterval(function() {
                if (width >= 100) {
                    clearInterval(id);
                    // A barra atingiu 100%, redireciona para a página de análise
                    window.location.href = './analise/analise.php';
                } else {
                    width++; // Aumenta o progresso
                    elem.style.width = width + '%';
                    elem.innerHTML = width + '%'; // Atualiza o texto da barra
                }
            }, 50); // Ajuste o valor aqui para controlar a velocidade do progresso

            // Redireciona imediatamente após o clique, permitindo que o carregamento da página ocorra ao mesmo tempo
            setTimeout(function() {
                window.location.href = './analise/analise.php';
            }, 50); // Inicia o redirecionamento de forma quase simultânea ao progresso
        }
    </script>

</body>

</html>