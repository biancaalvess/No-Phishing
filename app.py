from flask import Flask, render_template, request, jsonify
import logging
from datetime import datetime
import os
import re
from urllib.parse import urlparse

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'sua-chave-secreta-aqui'

# Lista de domínios conhecidamente seguros
DOMINIOS_SEGUROS = {
    'nubank.com.br', 'itau.com.br', 'bradesco.com.br', 'bancodobrasil.com.br',
    'bb.com.br', 'caixa.gov.br', 'santander.com.br', 'paypal.com',
    'google.com', 'microsoft.com', 'amazon.com', 'gov.br', 'mercadopago.com.br',
    'picpay.com', 'inter.co', 'original.com.br', 'c6bank.com.br',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'youtube.com',
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com'
}

# Lista de domínios maliciosos conhecidos (atualizada manualmente)
DOMINIOS_MALICIOSOS = {
    'banco-seguro-verificacao.tk', 'itau-verificacao.ml', 'nubank-update.ga',
    'bradesco-secure.cf', 'caixa-verificar.tk', 'santander-login.ml',
    'paypal-secure.ga', 'mercadopago-verify.cf', 'picpay-update.tk',
    'bb-verificacao.ml', 'inter-secure.ga', 'original-verify.cf'
}

# MARCAS CRÍTICAS - Qualquer imitação é EXTREMAMENTE perigosa
MARCAS_CRITICAS = {
    'nubank': {
        'oficial': 'nubank.com.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['nubbank', 'nuubank', 'nubanck', 'nubankk', 'nubank2024', 'nubankapp', 'nubankbr', 'nubanksecure', 'securenubank', 'nu-bank', 'nubank-br']
    },
    'itau': {
        'oficial': 'itau.com.br', 
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['itauu', 'itaau', 'itaubank', 'itausecure', 'itauoficial', 'itaubr', 'secureitau', 'itau-unibanco', 'itaucard']
    },
    'bradesco': {
        'oficial': 'bradesco.com.br',
        'categoria': 'banco', 
        'risco_imitacao': 95,
        'variacoes': ['bradescobank', 'bradescoo', 'braadesco', 'bradescosecure', 'bradescooficial', 'bradescobr', 'bradesco-bank']
    },
    'bancodobrasil': {
        'oficial': 'bancodobrasil.com.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['bb', 'bancobrasil', 'bancobrasiloficial', 'bancodobrasilsecure', 'bbbank', 'banco-brasil', 'bb-bank']
    },
    'caixa': {
        'oficial': 'caixa.gov.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['caiixa', 'caixaa', 'caixabank', 'caixasecure', 'caixaoficial', 'caixabr', 'caixaeconomica', 'caixa-economica']
    },
    'santander': {
        'oficial': 'santander.com.br',
        'categoria': 'banco',
        'risco_imitacao': 95,
        'variacoes': ['santanderr', 'santanderbank', 'santandersecure', 'santanderoficial', 'santanderbr', 'santander-bank']
    },
    'paypal': {
        'oficial': 'paypal.com',
        'categoria': 'pagamento',
        'risco_imitacao': 90,
        'variacoes': ['paypall', 'paypaall', 'paypalsecure', 'paypaloficial', 'paypalbr', 'pay-pal']
    },
    'mercadopago': {
        'oficial': 'mercadopago.com.br',
        'categoria': 'pagamento',
        'risco_imitacao': 90,
        'variacoes': ['mercadopagoo', 'mercadopaago', 'mercadopagosecure', 'mercadopagooficial', 'mercado-pago']
    },
    'picpay': {
        'oficial': 'picpay.com',
        'categoria': 'pagamento',
        'risco_imitacao': 90,
        'variacoes': ['picpayy', 'piicpay', 'picpaysecure', 'picpayoficial', 'picpaybr', 'pic-pay']
    },
    'inter': {
        'oficial': 'inter.co',
        'categoria': 'banco',
        'risco_imitacao': 90,
        'variacoes': ['interbank', 'intersecure', 'interoficial', 'interbr', 'banco-inter']
    }
}

# TLDs EXTREMAMENTE SUSPEITOS
TLDS_PERIGOSOS = {
    '.tk': 95, '.ml': 95, '.ga': 95, '.cf': 95,
    '.click': 80, '.download': 85, '.zip': 90,
    '.review': 75, '.country': 70, '.kim': 70,
    '.cricket': 75, '.science': 70, '.top': 65,
    '.work': 60, '.date': 70, '.stream': 75
}

# Palavras suspeitas categorizadas
PALAVRAS_URGENCIA = [
    'urgente', 'imediatamente', 'agora', 'expire', 'último', 'prazo',
    'suspenso', 'bloqueado', 'cancelado', 'removido', 'desativado',
    'último aviso', 'ação necessária', 'conta bloqueada', 'acesso negado',
    'tempo limitado', 'oferta expira', 'válido até', 'apenas hoje'
]

PALAVRAS_ENGENHARIA_SOCIAL = [
    'parabéns', 'ganhou', 'prêmio', 'sorteio', 'grátis', 'oferta especial',
    'desconto', 'promoção', 'limitado', 'exclusivo', 'selecionado',
    'aprovado', 'contemplado', 'beneficiado', 'escolhido', 'vencedor'
]

PALAVRAS_CREDENCIAIS = [
    'senha', 'login', 'usuário', 'cpf', 'rg', 'cartão', 'conta',
    'dados pessoais', 'informações', 'confirme', 'verifique', 'atualize',
    'validar', 'autenticar', 'token', 'código', 'pin', 'chave'
]

PALAVRAS_ACAO = [
    'clique aqui', 'acesse agora', 'baixe', 'instale', 'cadastre-se',
    'registre-se', 'faça login', 'entre', 'confirme', 'verifique',
    'atualize', 'renove', 'ative', 'desbloqueie'
]

# GOLPES DE ENGENHARIA SOCIAL E PROPOSTAS FRAUDULENTAS
PALAVRAS_GOLPES_COLABORACAO = [
    'colaboração', 'parceria', 'freelancer', 'upwork', 'fiverr', 'freelance',
    'conta suspensa', 'conta bloqueada', 'mudança de endereço', 'verificação de identidade',
    'criar uma conta', 'compartilhe comigo', 'usar sua conta', 'empresas de ponta',
    'dividir lucro', 'ganhar dinheiro', 'receita', 'colaboração de longo prazo',
    'trabalhar juntos', 'gerar receita', 'lucrar', 'ganhos', 'projetos de desenvolvimento'
]

PALAVRAS_PROMESSAS_FINANCEIRAS = [
    'ganhar pelo menos', 'mil por semana', 'muito bem', 'ótimos ganhos',
    'dinheiro fácil', 'renda extra', 'trabalho em casa', 'sem experiência',
    'apenas algumas horas', 'pouco tempo', 'máximo 2 a 3 horas',
    'geralmente menos', 'sem esforço', 'garantido'
]

PALAVRAS_SOLICITACOES_SUSPEITAS = [
    'criar uma conta', 'compartilhar conta', 'usar minha conta', 'emprestar conta',
    'preciso da sua ajuda', 'você pode me ajudar', 'sua função é',
    'permitir usar', 'participar das videoconferências', 'se preparar com respostas',
    'só me candidatarei', 'conversarei com os clientes', 'usar seu nome',
    'fingir ser você', 'representar você'
]

PALAVRAS_MANIPULACAO_PSICOLOGICA = [
    'vi você no github', 'procurando alguém', 'desenvolvedor experiente',
    'anos de experiência', 'infelizmente', 'repentinamente', 'permanentemente',
    'espero que', 'aguardo resposta positiva', 'o que você acha',
    'aberto a negociações', 'se nossa colaboração', 'bem-sucedida',
    'atenciosamente', 'respeitosamente'
]

PADROES_GOLPES_TECNICOS = [
    r'\b\d+\s*anos?\s*de\s*experiência\b',  # "10 anos de experiência"
    r'\b\d+\s*mil\s*por\s*semana\b',        # "2 mil por semana"
    r'\b\d+%\s*da\s*receita\b',             # "10% da receita"
    r'\b\d+\s*a\s*\d+\s*horas?\s*por\s*semana\b',  # "2 a 3 horas por semana"
    r'\bR?\$?\s*\d+[.,]?\d*\s*(mil|k|reais?|dólares?)\b',  # valores monetários
]

def criar_estrutura_arquivos():
    """Cria a estrutura de pastas e arquivos necessários"""
    # Cria diretórios
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Cria index.html se não existir
    index_path = 'index.html'
    if not os.path.exists(index_path):
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write('''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detector de Phishing - Proteção contra Golpes</title>
    <meta name="description" content="Ferramenta inteligente para detectar emails e URLs de phishing, protegendo você contra golpes online.">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <header class="header">
        <h1>
            <i class="fas fa-shield-alt icon" aria-hidden="true"></i>
            Detector de Phishing
        </h1>
        <p>Ferramenta inteligente para identificar emails e URLs suspeitos, protegendo você contra golpes online</p>
    </header>

    <main class="container">
        <div class="card">
            <form id="analysisForm" novalidate>
                <div class="input-group">
                    <label for="messageInput" class="input-label">
                        <i class="fas fa-envelope" aria-hidden="true"></i>
                        Cole aqui o texto do email, mensagem ou URL para análise
                    </label>
                    <div class="textarea-container">
                        <textarea 
                            id="messageInput" 
                            class="input-textarea"
                            placeholder="Exemplo: 'Parabéns! Você ganhou um prêmio de R$ 10.000! Clique em https://site-suspeito.com para resgatar seu prêmio agora mesmo!'"
                            maxlength="5000"
                            required
                            aria-describedby="char-counter"
                        ></textarea>
                        <div id="char-counter" class="char-counter">0 / 5000</div>
                    </div>
                </div>

                <button type="submit" class="analyze-btn" id="analyzeBtn">
                    <span class="btn-text">
                        <i class="fas fa-search" aria-hidden="true"></i>
                        Analisar Mensagem
                    </span>
                    <div class="spinner" id="spinner" aria-hidden="true"></div>
                </button>
            </form>
        </div>

        <div class="card results" id="results" role="region" aria-label="Resultados da análise">
            <div id="riskIndicator" class="risk-indicator" role="alert">
                <div class="risk-score">
                    <i class="fas fa-exclamation-triangle" aria-hidden="true"></i>
                    <span id="riskText">Analisando...</span>
                </div>
            </div>

            <div class="results-section">
                <h2 class="results-title">
                    <i class="fas fa-exclamation-circle" aria-hidden="true"></i>
                    Palavras Suspeitas Encontradas
                </h2>
                <div class="results-list">
                    <ul id="suspiciousWordsList" aria-label="Lista de palavras suspeitas">
                        <li class="empty-state">Nenhuma palavra suspeita encontrada</li>
                    </ul>
                </div>
            </div>

            <div class="results-section">
                <h2 class="results-title">
                    <i class="fas fa-globe" aria-hidden="true"></i>
                    Domínios Suspeitos Encontrados
                </h2>
                <div class="results-list">
                    <ul id="suspiciousDomainsList" aria-label="Lista de domínios suspeitos">
                        <li class="empty-state">Nenhum domínio suspeito encontrado</li>
                    </ul>
                </div>
            </div>

            <div class="results-section" id="recommendationsSection" style="display: none;">
                <h2 class="results-title">
                    <i class="fas fa-lightbulb" aria-hidden="true"></i>
                    Recomendações de Segurança
                </h2>
                <div class="results-list">
                    <ul id="recommendationsList" aria-label="Lista de recomendações">
                    </ul>
                </div>
            </div>
        </div>
    </main>

    <footer class="footer">
        <p>
            Desenvolvido com <i class="fas fa-heart" style="color: #ef4444;" aria-hidden="true"></i> por 
            <a href="#" target="_blank" rel="noopener">Bianca Alves</a> - 2025
        </p>
        <p style="margin-top: 0.5rem; font-size: 0.8rem;">
            <i class="fas fa-info-circle" aria-hidden="true"></i>
            Esta ferramenta é apenas indicativa. Sempre mantenha cuidado com mensagens suspeitas.
        </p>
    </footer>

    <script src="{{ url_for('static', filename='script.js') }}"></script>
</body>
</html>''')
    
    # Cria style.css se não existir
    css_path = 'static/style.css'
    if not os.path.exists(css_path):
        with open(css_path, 'w', encoding='utf-8') as f:
            f.write(''':root {
  --primary-color: #8b5cf6;
  --primary-dark: #7c3aed;
  --primary-light: #a78bfa;
  --secondary-color: #6366f1;
  --background-dark: #0f0f23;
  --background-card: #1a1a2e;
  --background-input: #16213e;
  --text-primary: #f8fafc;
  --text-secondary: #cbd5e1;
  --text-muted: #94a3b8;
  --border-color: #334155;
  --success-color: #10b981;
  --success-bg: #064e3b;
  --warning-color: #f59e0b;
  --warning-bg: #451a03;
  --danger-color: #ef4444;
  --danger-bg: #450a0a;
  --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2);
  --shadow-xl: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  --gradient-primary: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
  --gradient-danger: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
  --gradient-success: linear-gradient(135deg, #10b981 0%, #059669 100%);
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--background-dark);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  padding: 1rem;
}

.header {
  text-align: center;
  margin-bottom: 2rem;
  padding: 2rem 0;
}

.header h1 {
  font-size: clamp(2rem, 5vw, 3rem);
  font-weight: 700;
  background: var(--gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
}

.header .icon {
  font-size: 0.8em;
  color: var(--primary-color);
}

.header p {
  color: var(--text-secondary);
  font-size: 1.1rem;
  max-width: 600px;
  margin: 0 auto;
  font-weight: 500;
}

.container {
  max-width: 800px;
  margin: 0 auto;
  flex: 1;
  display: flex;
  flex-direction: column;
}

.card {
  background: var(--background-card);
  border-radius: 1rem;
  padding: 2rem;
  box-shadow: var(--shadow-xl);
  border: 1px solid var(--border-color);
  backdrop-filter: blur(10px);
  margin-bottom: 2rem;
}

.input-group {
  margin-bottom: 1.5rem;
}

.input-label {
  display: block;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 0.5rem;
  font-size: 0.95rem;
}

.textarea-container {
  position: relative;
}

.input-textarea {
  width: 100%;
  min-height: 200px;
  padding: 1rem;
  background: var(--background-input);
  border: 2px solid var(--border-color);
  border-radius: 0.75rem;
  color: var(--text-primary);
  font-size: 1rem;
  font-family: inherit;
  resize: vertical;
  transition: all 0.3s ease;
  line-height: 1.5;
}

.input-textarea::placeholder {
  color: var(--text-muted);
  font-style: italic;
}

.input-textarea:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.1);
  background: var(--background-card);
}

.char-counter {
  position: absolute;
  bottom: 0.5rem;
  right: 0.75rem;
  font-size: 0.8rem;
  color: var(--text-muted);
  background: var(--background-dark);
  padding: 0.25rem 0.5rem;
  border-radius: 0.25rem;
}

.analyze-btn {
  width: 100%;
  padding: 1rem 2rem;
  background: var(--gradient-primary);
  color: white;
  border: none;
  border-radius: 0.75rem;
  font-size: 1.1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
}

.analyze-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.analyze-btn:active {
  transform: translateY(0);
}

.analyze-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
}

.spinner {
  width: 20px;
  height: 20px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top: 2px solid white;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  display: none;
}

.spinner.active {
  display: block;
}

@keyframes spin {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}

.results {
  display: none;
  animation: fadeInUp 0.5s ease;
}

.results.show {
  display: block;
}

@keyframes fadeInUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.risk-indicator {
  padding: 1.5rem;
  border-radius: 0.75rem;
  margin-bottom: 2rem;
  text-align: center;
  font-weight: 600;
  font-size: 1.2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  border: 2px solid;
}

.risk-indicator.safe {
  background: var(--success-bg);
  border-color: var(--success-color);
  color: var(--success-color);
}

.risk-indicator.warning {
  background: var(--warning-bg);
  border-color: var(--warning-color);
  color: var(--warning-color);
}

.risk-indicator.danger {
  background: var(--danger-bg);
  border-color: var(--danger-color);
  color: var(--danger-color);
}

.risk-score {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1.5rem;
  font-weight: 700;
}

.results-section {
  margin-bottom: 2rem;
}

.results-title {
  font-size: 1.3rem;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.results-list {
  background: var(--background-input);
  border-radius: 0.5rem;
  padding: 1rem;
  border: 1px solid var(--border-color);
}

.results-list ul {
  list-style: none;
  padding: 0;
}

.results-list li {
  padding: 0.75rem;
  margin-bottom: 0.5rem;
  background: var(--background-card);
  border-radius: 0.5rem;
  border-left: 4px solid var(--primary-color);
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-weight: 500;
}

.results-list li:last-child {
  margin-bottom: 0;
}

.results-list .icon {
  color: var(--primary-color);
  font-size: 1.1rem;
}

.empty-state {
  text-align: center;
  padding: 2rem;
  color: var(--text-muted);
  font-style: italic;
}

.footer {
  text-align: center;
  padding: 2rem 0;
  margin-top: auto;
  border-top: 1px solid var(--border-color);
  color: var(--text-muted);
  font-size: 0.9rem;
}

.footer a {
  color: var(--primary-color);
  text-decoration: none;
  font-weight: 500;
}

.footer a:hover {
  text-decoration: underline;
}

/* Responsividade */
@media (max-width: 768px) {
  body {
    padding: 0.5rem;
  }

  .card {
    padding: 1.5rem;
    border-radius: 0.75rem;
  }

  .header {
    padding: 1rem 0;
    margin-bottom: 1.5rem;
  }

  .input-textarea {
    min-height: 150px;
    padding: 0.75rem;
  }

  .analyze-btn {
    padding: 0.875rem 1.5rem;
    font-size: 1rem;
  }

  .risk-indicator {
    padding: 1rem;
    font-size: 1.1rem;
  }
}

@media (max-width: 480px) {
  .header h1 {
    flex-direction: column;
    gap: 0.5rem;
  }

  .results-list li {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
}

/* Melhorias de acessibilidade */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}

/* Estados de foco melhorados */
.analyze-btn:focus-visible,
.input-textarea:focus-visible {
  outline: 2px solid var(--primary-color);
  outline-offset: 2px;
}''')
    
    # Cria script.js se não existir
    js_path = 'static/script.js'
    if not os.path.exists(js_path):
        with open(js_path, 'w', encoding='utf-8') as f:
            f.write('''// Contador de caracteres
const messageInput = document.getElementById("messageInput")
const charCounter = document.getElementById("char-counter")

messageInput.addEventListener("input", function () {
  const currentLength = this.value.length
  const maxLength = this.getAttribute("maxlength")
  charCounter.textContent = `${currentLength} / ${maxLength}`

  if (currentLength > maxLength * 0.9) {
    charCounter.style.color = "var(--warning-color)"
  } else {
    charCounter.style.color = "var(--text-muted)"
  }
})

// Função principal de análise
async function verificarMensagem() {
  const messageInput = document.getElementById("messageInput")
  const analyzeBtn = document.getElementById("analyzeBtn")
  const spinner = document.getElementById("spinner")
  const results = document.getElementById("results")
  const btnText = document.querySelector(".btn-text")

  const message = messageInput.value.trim()

  if (!message) {
    showNotification("Por favor, insira uma mensagem para análise.", "warning")
    messageInput.focus()
    return
  }

  // Estado de carregamento
  analyzeBtn.disabled = true
  spinner.classList.add("active")
  btnText.style.opacity = "0.7"

  try {
    // Chama a API do backend
    const response = await fetch("/verificar", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        mensagem: message,
      }),
    })

    if (!response.ok) {
      const errorData = await response.json()
      throw new Error(errorData.erro || "Erro na análise")
    }

    const data = await response.json()

    // Atualiza interface com resultados
    updateResults(data)

    // Mostra resultados
    results.classList.add("show")
    results.scrollIntoView({ behavior: "smooth", block: "start" })
  } catch (error) {
    console.error("Erro na análise:", error)
    showError(error.message || "Erro ao analisar a mensagem. Tente novamente.")
  } finally {
    // Remove estado de carregamento
    analyzeBtn.disabled = false
    spinner.classList.remove("active")
    btnText.style.opacity = "1"
  }
}

// Atualiza interface com resultados
function updateResults(data) {
  const riskIndicator = document.getElementById("riskIndicator")
  const riskText = document.getElementById("riskText")
  const suspiciousWordsList = document.getElementById("suspiciousWordsList")
  const suspiciousDomainsList = document.getElementById("suspiciousDomainsList")
  const recommendationsSection = document.getElementById("recommendationsSection")
  const recommendationsList = document.getElementById("recommendationsList")

  // Garante que o score seja um número válido
  let riskScore = data.score_risco || 0
  if (isNaN(riskScore)) {
    riskScore = 0
  }
  riskScore = Math.round(riskScore)

  // Atualiza indicador de risco
  riskIndicator.className = `risk-indicator ${data.nivel_risco}`

  let riskMessage = ""
  let riskIcon = ""

  switch (data.nivel_risco) {
    case "danger":
      riskMessage = `ALTO RISCO (${riskScore}/100) - Possível Golpe!`
      riskIcon = "fas fa-exclamation-triangle"
      break
    case "warning":
      riskMessage = `RISCO MODERADO (${riskScore}/100) - Seja Cauteloso`
      riskIcon = "fas fa-exclamation-circle"
      break
    default:
      riskMessage = `BAIXO RISCO (${riskScore}/100) - Aparenta ser Seguro`
      riskIcon = "fas fa-check-circle"
  }

  riskText.innerHTML = `<i class="${riskIcon}" aria-hidden="true"></i> ${riskMessage}`

  // Atualiza lista de palavras suspeitas
  updateList(suspiciousWordsList, data.palavras_suspeitas, "fas fa-exclamation-circle")

  // Atualiza lista de domínios suspeitos
  updateList(suspiciousDomainsList, data.dominios_suspeitos, "fas fa-globe")

  // Atualiza recomendações
  if (data.recomendacoes && data.recomendacoes.length > 0) {
    updateList(recommendationsList, data.recomendacoes, "fas fa-lightbulb")
    recommendationsSection.style.display = "block"
  } else {
    recommendationsSection.style.display = "none"
  }

  // Log para debug
  console.log("Dados recebidos:", data)
}

// Atualiza listas de resultados
function updateList(listElement, items, iconClass) {
  listElement.innerHTML = ""

  if (!items || items.length === 0) {
    listElement.innerHTML = '<li class="empty-state">Nenhum item suspeito encontrado</li>'
  } else {
    items.forEach((item) => {
      const li = document.createElement("li")
      li.innerHTML = `<i class="${iconClass} icon" aria-hidden="true"></i> ${item}`
      listElement.appendChild(li)
    })
  }
}

// Mostra erro
function showError(message) {
  const riskIndicator = document.getElementById("riskIndicator")
  const riskText = document.getElementById("riskText")

  riskIndicator.className = "risk-indicator danger"
  riskText.innerHTML = `<i class="fas fa-exclamation-triangle" aria-hidden="true"></i> ${message}`

  document.getElementById("results").classList.add("show")
}

// Sistema de notificações
function showNotification(message, type = "info") {
  // Cria elemento de notificação
  const notification = document.createElement("div")
  notification.className = `notification ${type}`
  notification.innerHTML = `
        <i class="fas fa-info-circle" aria-hidden="true"></i>
        <span>${message}</span>
    `

  // Adiciona estilos inline (você pode mover para CSS)
  notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--background-card);
        color: var(--text-primary);
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        border-left: 4px solid var(--primary-color);
        box-shadow: var(--shadow-lg);
        z-index: 1000;
        animation: slideInRight 0.3s ease;
    `

  if (type === "warning") {
    notification.style.borderLeftColor = "var(--warning-color)"
  } else if (type === "error") {
    notification.style.borderLeftColor = "var(--danger-color)"
  }

  document.body.appendChild(notification)

  // Remove após 3 segundos
  setTimeout(() => {
    notification.style.animation = "slideOutRight 0.3s ease"
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification)
      }
    }, 300)
  }, 3000)
}

// Event listeners
document.getElementById("analysisForm").addEventListener("submit", (e) => {
  e.preventDefault()
  verificarMensagem()
})

// Atalho de teclado
messageInput.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key === "Enter") {
    e.preventDefault()
    verificarMensagem()
  }
})

// Adiciona animações CSS para notificações
const style = document.createElement("style")
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`
document.head.appendChild(style)'''
)

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/verificar', methods=['POST'])
def verificar_mensagem():
    """Endpoint para verificar mensagens/URLs - SISTEMA 100% LOCAL"""
    try:
        data = request.get_json()
        
        if not data or 'mensagem' not in data:
            return jsonify({'erro': 'Mensagem não fornecida'}), 400
        
        mensagem = data['mensagem'].strip()
        
        if not mensagem:
            return jsonify({'erro': 'Mensagem vazia'}), 400
        
        logger.info(f"🔍 ANÁLISE LOCAL: {mensagem[:100]}...")
        
        # ANÁLISE COMPLETA LOCAL
        resultado = analisar_local(mensagem)
        
        logger.warning(f"🚨 RESULTADO: {resultado['nivel_risco_texto']} - Score: {resultado['score_risco']}")
        
        return jsonify(resultado)
        
    except Exception as e:
        logger.error(f"❌ ERRO na análise: {str(e)}")
        return jsonify({
            'score_risco': 90,
            'nivel_risco': 'danger',
            'nivel_risco_texto': 'ERRO',
            'palavras_suspeitas': [],
            'dominios_suspeitos': [f"ERRO NA ANÁLISE: {str(e)}"],
            'recomendacoes': [
                "🚨 ERRO NO SISTEMA - Seja cauteloso",
                "🛡️ Não insira dados pessoais até verificar manualmente"
            ]
        }), 200

def extrair_urls(texto):
    """Extrai todas as URLs do texto"""
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*'
    urls = re.findall(url_pattern, texto)
    
    # Limpa e normaliza URLs
    urls_limpas = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                url = 'http://' + url
            else:
                url = 'http://' + url
        urls_limpas.append(url)
    
    return urls_limpas

def extrair_dominio(url):
    """Extrai domínio de uma URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return url.lower()

def detectar_imitacao_marca(dominio):
    """Detecta imitações de marcas críticas"""
    dominio_limpo = dominio.lower()
    nome_base = dominio_limpo.split('.')[0]
    
    imitacoes_encontradas = []
    score_total = 0
    
    for marca, info in MARCAS_CRITICAS.items():
        marca_lower = marca.lower()
        
        # Verificação exata da marca no domínio
        if marca_lower in nome_base and dominio_limpo != info['oficial']:
            score_total = info['risco_imitacao']
            imitacoes_encontradas.append({
                'tipo': 'IMITAÇÃO DETECTADA',
                'marca_imitada': marca.upper(),
                'dominio_oficial': info['oficial'],
                'dominio_suspeito': dominio_limpo,
                'categoria': info['categoria'],
                'risco': info['risco_imitacao']
            })
        
        # Verificação de variações conhecidas
        if nome_base in info['variacoes']:
            score_total = max(score_total, info['risco_imitacao'])
            imitacoes_encontradas.append({
                'tipo': 'VARIAÇÃO PERIGOSA',
                'marca_imitada': marca.upper(),
                'dominio_oficial': info['oficial'],
                'dominio_suspeito': dominio_limpo,
                'categoria': info['categoria'],
                'risco': info['risco_imitacao']
            })
    
    return {
        'score': score_total,
        'imitacoes': imitacoes_encontradas,
        'is_imitacao': len(imitacoes_encontradas) > 0
    }

def verificar_tld_perigoso(dominio):
    """Verifica TLDs perigosos"""
    dominio_limpo = dominio.lower()
    
    for tld, risco in TLDS_PERIGOSOS.items():
        if dominio_limpo.endswith(tld):
            return {
                'is_perigoso': True,
                'tld': tld,
                'risco': risco,
                'motivo': f"TLD {tld} frequentemente usado para phishing"
            }
    
    return {'is_perigoso': False, 'risco': 0}

def analisar_palavras_suspeitas(texto):
    """Analisa palavras suspeitas no texto incluindo golpes de engenharia social"""
    texto_lower = texto.lower()
    palavras_encontradas = []
    score_total = 0
    
    # Verifica palavras de urgência
    for palavra in PALAVRAS_URGENCIA:
        if palavra in texto_lower:
            palavras_encontradas.append(f"URGÊNCIA: {palavra}")
            score_total += 15
    
    # Verifica engenharia social tradicional
    for palavra in PALAVRAS_ENGENHARIA_SOCIAL:
        if palavra in texto_lower:
            palavras_encontradas.append(f"ENG. SOCIAL: {palavra}")
            score_total += 10
    
    # Verifica solicitação de credenciais
    for palavra in PALAVRAS_CREDENCIAIS:
        if palavra in texto_lower:
            palavras_encontradas.append(f"CREDENCIAIS: {palavra}")
            score_total += 20
    
    # Verifica chamadas para ação
    for palavra in PALAVRAS_ACAO:
        if palavra in texto_lower:
            palavras_encontradas.append(f"AÇÃO: {palavra}")
            score_total += 8
    
    # NOVA: Verifica golpes de colaboração/freelancer
    for palavra in PALAVRAS_GOLPES_COLABORACAO:
        if palavra in texto_lower:
            palavras_encontradas.append(f"GOLPE COLABORAÇÃO: {palavra}")
            score_total += 25  # Score alto para este tipo de golpe
    
    # NOVA: Verifica promessas financeiras suspeitas
    for palavra in PALAVRAS_PROMESSAS_FINANCEIRAS:
        if palavra in texto_lower:
            palavras_encontradas.append(f"PROMESSA FINANCEIRA: {palavra}")
            score_total += 20
    
    # NOVA: Verifica solicitações suspeitas
    for palavra in PALAVRAS_SOLICITACOES_SUSPEITAS:
        if palavra in texto_lower:
            palavras_encontradas.append(f"SOLICITAÇÃO SUSPEITA: {palavra}")
            score_total += 30  # Score muito alto
    
    # NOVA: Verifica manipulação psicológica
    for palavra in PALAVRAS_MANIPULACAO_PSICOLOGICA:
        if palavra in texto_lower:
            palavras_encontradas.append(f"MANIPULAÇÃO: {palavra}")
            score_total += 12
    
    # NOVA: Verifica padrões técnicos suspeitos
    for padrao in PADROES_GOLPES_TECNICOS:
        matches = re.findall(padrao, texto_lower)
        for match in matches:
            if isinstance(match, tuple):
                match = ' '.join(match)
            palavras_encontradas.append(f"PADRÃO SUSPEITO: {match}")
            score_total += 15
    
    return {
        'palavras': palavras_encontradas,
        'score': min(score_total, 90)  # Aumentei o máximo para 90
    }

def detectar_golpe_colaboracao(texto):
    """Detecta especificamente golpes de colaboração/freelancer"""
    texto_lower = texto.lower()
    
    # Indicadores específicos de golpes de colaboração
    indicadores_criticos = [
        'criar uma conta',
        'compartilhar conta',
        'usar sua conta',
        'conta suspensa',
        'preciso da sua ajuda',
        'dividir lucro',
        'usar seu nome',
        'participar das videoconferências'
    ]
    
    indicadores_encontrados = []
    score_golpe = 0
    
    for indicador in indicadores_criticos:
        if indicador in texto_lower:
            indicadores_encontrados.append(indicador)
            score_golpe += 35  # Score muito alto para cada indicador
    
    # Padrões específicos
    padroes_criticos = [
        r'conta.*suspensa.*devido.*mudança',
        r'criar.*conta.*seu.*nome',
        r'compartilh.*conta.*comigo',
        r'dividir.*lucro.*colaboração',
        r'ganhar.*mil.*semana',
        r'apenas.*horas.*semana'
    ]
    
    for padrao in padroes_criticos:
        if re.search(padrao, texto_lower):
            indicadores_encontrados.append(f"PADRÃO CRÍTICO: {padrao}")
            score_golpe += 40
    
    return {
        'is_golpe_colaboracao': len(indicadores_encontrados) >= 2,
        'score': min(score_golpe, 95),
        'indicadores': indicadores_encontrados
    }

def analisar_local(mensagem):
    """ANÁLISE COMPLETA 100% LOCAL"""
    
    # Extrai URLs da mensagem
    urls = extrair_urls(mensagem)
    
    score_risco = 0
    dominios_suspeitos = []
    palavras_suspeitas = []
    
    # ANÁLISE DE PALAVRAS SUSPEITAS
    analise_palavras = analisar_palavras_suspeitas(mensagem)
    palavras_suspeitas = analise_palavras['palavras']
    score_risco += analise_palavras['score']

    # NOVA: DETECÇÃO ESPECÍFICA DE GOLPES DE COLABORAÇÃO
    golpe_colaboracao = detectar_golpe_colaboracao(mensagem)
    if golpe_colaboracao['is_golpe_colaboracao']:
        score_risco += golpe_colaboracao['score']
        dominios_suspeitos.append("🚨 GOLPE DE COLABORAÇÃO/FREELANCER DETECTADO")
        for indicador in golpe_colaboracao['indicadores']:
            dominios_suspeitos.append(f"⚠️ INDICADOR: {indicador}")
    
    # ANÁLISE DE DOMÍNIOS
    for url in urls:
        dominio = extrair_dominio(url)
        
        # Verifica se é domínio seguro conhecido
        if dominio in DOMINIOS_SEGUROS:
            continue  # Domínio seguro, não adiciona risco
        
        # Verifica se é domínio malicioso conhecido
        if dominio in DOMINIOS_MALICIOSOS:
            score_risco += 95
            dominios_suspeitos.append(f"🚨 DOMÍNIO MALICIOSO CONHECIDO: {dominio}")
            continue
        
        # Verifica imitação de marcas
        imitacao_result = detectar_imitacao_marca(dominio)
        if imitacao_result['is_imitacao']:
            score_risco += imitacao_result['score']
            for imitacao in imitacao_result['imitacoes']:
                dominios_suspeitos.append(
                    f"🚨 {imitacao['tipo']}: {imitacao['dominio_suspeito']} "
                    f"imita {imitacao['marca_imitada']} (oficial: {imitacao['dominio_oficial']})"
                )
        
        # Verifica TLD perigoso
        tld_result = verificar_tld_perigoso(dominio)
        if tld_result['is_perigoso']:
            score_risco += tld_result['risco']
            dominios_suspeitos.append(f"🚩 TLD PERIGOSO: {dominio} - {tld_result['motivo']}")
        
        # Verifica padrões suspeitos
        if re.search(r'\d+\.\d+\.\d+\.\d+', dominio):
            score_risco += 40
            dominios_suspeitos.append(f"🚨 USA IP: {dominio} (em vez de nome de domínio)")
        
        if len(dominio.split('.')) > 4:
            score_risco += 20
            dominios_suspeitos.append(f"⚠️ MUITOS SUBDOMÍNIOS: {dominio}")
        
        # Se não é conhecido como seguro, adiciona risco base
        if not any([imitacao_result['is_imitacao'], tld_result['is_perigoso'], 
                   re.search(r'\d+\.\d+\.\d+\.\d+', dominio)]):
            score_risco += 15
            dominios_suspeitos.append(f"⚠️ DOMÍNIO DESCONHECIDO: {dominio}")
    
    # ANÁLISE DE PADRÕES GERAIS
    mensagem_lower = mensagem.lower()
    
    # Excesso de maiúsculas
    caps_ratio = sum(1 for c in mensagem if c.isupper()) / max(len(mensagem), 1)
    if caps_ratio > 0.3:
        score_risco += 15
        palavras_suspeitas.append("EXCESSO DE MAIÚSCULAS")
    
    # Excesso de pontuação
    punct_count = sum(1 for c in mensagem if c in '!?.,;:')
    if punct_count > len(mensagem) * 0.1:
        score_risco += 10
        palavras_suspeitas.append("EXCESSO DE PONTUAÇÃO")
    
    # Números de telefone ou códigos suspeitos
    if re.search(r'\b\d{10,11}\b', mensagem):
        score_risco += 10
        palavras_suspeitas.append("NÚMERO DE TELEFONE")
    
    # Limita score máximo
    score_risco = min(score_risco, 100)
    
    # DETERMINA NÍVEL DE RISCO
    if score_risco >= 80 or golpe_colaboracao['is_golpe_colaboracao']:
        nivel_risco = 'danger'
        nivel_risco_texto = 'CRÍTICO'
        recomendacoes = [
            "🚨 GOLPE DETECTADO - NÃO RESPONDA A ESTA MENSAGEM",
            "❌ NUNCA compartilhe contas ou dados pessoais",
            "🛡️ NUNCA crie contas para terceiros usarem",
            "💰 Desconfie de promessas de dinheiro fácil",
            "📞 Golpes de 'colaboração' são muito comuns",
            "🚔 Reporte este golpe às autoridades se necessário"
        ]
    elif score_risco >= 60:
        nivel_risco = 'danger'
        nivel_risco_texto = 'ALTO'
        recomendacoes = [
            "⚠️ ALTO RISCO - Seja extremamente cauteloso",
            "🔍 Verifique se é realmente da empresa oficial",
            "❌ NÃO clique em links ou baixe arquivos",
            "📞 Entre em contato com a empresa por canais oficiais"
        ]
    elif score_risco >= 40:
        nivel_risco = 'warning'
        nivel_risco_texto = 'MÉDIO'
        recomendacoes = [
            "⚠️ CUIDADO - Esta mensagem tem elementos suspeitos",
            "🔍 Confirme a legitimidade antes de prosseguir",
            "🛡️ Evite inserir dados sensíveis",
            "📞 Em caso de dúvida, contate a empresa diretamente"
        ]
    elif score_risco >= 20:
        nivel_risco = 'warning'
        nivel_risco_texto = 'BAIXO'
        recomendacoes = [
            "⚠️ ATENÇÃO - Alguns elementos podem ser suspeitos",
            "🔍 Sempre verifique a legitimidade de mensagens",
            "🛡️ Mantenha cuidado com dados pessoais"
        ]
    else:
        nivel_risco = 'safe'
        nivel_risco_texto = 'SEGURO'
        recomendacoes = [
            "✅ Mensagem aparenta ser segura",
            "🛡️ Mesmo assim, sempre mantenha cuidado com dados pessoais",
            "🔍 Verifique sempre a legitimidade de sites antes de inserir dados"
        ]
    
    return {
        'score_risco': score_risco,
        'nivel_risco': nivel_risco,
        'nivel_risco_texto': nivel_risco_texto,
        'palavras_suspeitas': palavras_suspeitas,
        'dominios_suspeitos': dominios_suspeitos,
        'recomendacoes': recomendacoes,
        'detalhes': {
            'tipo_analise': 'local_completa',
            'timestamp': datetime.now().isoformat(),
            'urls_encontradas': len(urls),
            'dominios_analisados': [extrair_dominio(url) for url in urls]
        }
    }

@app.route('/health')
def health_check():
    """Health check do sistema"""
    return jsonify({
        'status': 'ok',
        'modo': 'LOCAL_COMPLETO',
        'dominios_seguros': len(DOMINIOS_SEGUROS),
        'dominios_maliciosos': len(DOMINIOS_MALICIOSOS),
        'marcas_protegidas': len(MARCAS_CRITICAS),
        'tlds_perigosos': len(TLDS_PERIGOSOS),
        'timestamp': datetime.now().isoformat()
    })

@app.errorhandler(404)
def not_found(error):
    logger.warning(f"Página não encontrada: {request.path}")
    return jsonify({'erro': 'Página não encontrada'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Erro interno: {str(error)}")
    return jsonify({'erro': 'Erro interno do servidor'}), 500

if __name__ == '__main__':
    # Cria estrutura de arquivos automaticamente
    criar_estrutura_arquivos()
    
    logger.warning("🚨 SISTEMA INICIADO EM MODO 100% LOCAL")
    logger.warning("🛡️ PRIORIDADE MÁXIMA: PROTEÇÃO DO USUÁRIO")
    logger.info("📊 Sistema completamente independente - SEM APIs externas")
    logger.info("📁 Estrutura de arquivos criada automaticamente")
    logger.info(f"🔍 Protegendo contra {len(MARCAS_CRITICAS)} marcas críticas")
    logger.info(f"⚠️ Detectando {len(TLDS_PERIGOSOS)} TLDs perigosos")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
