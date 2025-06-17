
        async function verificarMensagem() {
            const mensagemInput = document.getElementById('mensagemInput');
            const mensagem = mensagemInput.value.trim(); 
            const resultadosDiv = document.getElementById('resultados');
            const statusMensagem = document.getElementById('statusMensagem');
            const listaPalavras = document.getElementById('listaPalavrasSuspeitas');
            const listaDominios = document.getElementById('listaDominiosSuspeitos');
            const spinner = document.getElementById('spinner');

            if (!mensagem) {
                statusMensagem.textContent = 'Por favor, digite ou cole uma mensagem para verificar.';
                resultadosDiv.className = 'alerta';
                resultadosDiv.querySelector('h2').style.color = 'var(--cor-alerta)';
                listaPalavras.innerHTML = '';
                listaDominios.innerHTML = '';
                return;
            }

            listaPalavras.innerHTML = '';
            listaDominios.innerHTML = '';
            resultadosDiv.className = ''; 
            statusMensagem.textContent = 'A analisar...';
            spinner.style.display = 'block'; 

            try {
                const response = await fetch('http://127.0.0.1:5000/verificar', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ mensagem: mensagem })
                });

                const data = await response.json();

                spinner.style.display = 'none'; 

                if (data.erro) {
                    statusMensagem.textContent = `Erro do servidor: ${data.erro}`;
                    resultadosDiv.classList.add('alerta');
                    resultadosDiv.querySelector('h2').style.color = 'var(--cor-alerta)';
                    console.error("Erro na resposta da API:", data.erro);
                    return;
                }

                if (data.e_golpe) {
                    statusMensagem.textContent = '❗ ALERTA: Possível golpe detetado!';
                    resultadosDiv.classList.add('alerta');
                    resultadosDiv.querySelector('h2').style.color = 'var(--cor-alerta)';
                } else {
                    statusMensagem.textContent = '✅ Nenhum indício forte de golpe encontrado. Mantenha-se atento!';
                    resultadosDiv.classList.add('seguro');
                    resultadosDiv.querySelector('h2').style.color = 'var(--cor-seguro)';
                }

                if (data.palavras_suspeitas && data.palavras_suspeitas.length > 0) {
                    const liTitulo = document.createElement('li');
                    liTitulo.innerHTML = '<span class="bold">Palavras suspeitas encontradas:</span>';
                    listaPalavras.appendChild(liTitulo);
                    data.palavras_suspeitas.forEach(palavra => {
                        const li = document.createElement('li');
                        li.textContent = `- ${palavra}`;
                        listaPalavras.appendChild(li);
                    });
                }

                if (data.dominios_suspeitos && data.dominios_suspeitos.length > 0) {
                    const liTitulo = document.createElement('li');
                    liTitulo.innerHTML = '<span class="bold">Domínios suspeitos encontrados:</span>';
                    listaDominios.appendChild(liTitulo);
                    data.dominios_suspeitos.forEach(dominio => {
                        const li = document.createElement('li');
                        li.textContent = `- ${dominio}`;
                        listaDominios.appendChild(li);
                    });
                }

                if (data.palavras_suspeitas.length === 0 && data.dominios_suspeitos.length === 0 && !data.e_golpe) {
                     statusMensagem.textContent = '✅ Nenhum indício forte de golpe encontrado. Mantenha-se atento!';
                }

            } catch (error) {
                spinner.style.display = 'none'; 
                statusMensagem.textContent = `Erro ao comunicar com o servidor: ${error.message}. Verifique se o backend está a funcionar (python app.py).`;
                resultadosDiv.classList.add('alerta');
                resultadosDiv.querySelector('h2').style.color = 'var(--cor-alerta)';
                console.error("Erro na requisição fetch:", error);
            }
        }