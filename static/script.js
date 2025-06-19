// Contador de caracteres
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
const toggleBtn = document.getElementById('toggle-theme');
const body = document.body;

if (localStorage.getItem('tema') === 'dark') {
    body.classList.add('dark');
    toggleBtn.textContent = '☀️ Modo Claro';
}

toggleBtn.addEventListener('click', () => {
    body.classList.toggle('dark');
    if (body.classList.contains('dark')) {
        toggleBtn.textContent = '☀️';
        localStorage.setItem('tema', 'dark');
    } else {
        toggleBtn.textContent = '🌙';
        localStorage.setItem('tema', 'light');
    }
});

document.head.appendChild(style)
