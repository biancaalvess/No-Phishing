// Contador de caracteres
const messageInput = document.getElementById("messageInput")
const charCounter = document.getElementById("char-counter")

messageInput.addEventListener("input", function () {
  const currentLength = this.value.length
  const maxLength = this.getAttribute("maxlength")
  charCounter.textContent = `${currentLength} / ${maxLength}`

  charCounter.classList.remove("char-warning", "char-muted")
  if (currentLength > maxLength * 0.9) {
    charCounter.classList.add("char-warning")
  } else {
    charCounter.classList.add("char-muted")
  }
})

// Função principal de análise
async function verificarMensagem() {
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

  analyzeBtn.disabled = true
  spinner.classList.add("active")
  btnText.classList.add("btn-loading")

  try {
    const response = await fetch("http://localhost:5000/verificar", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ mensagem: message }),
    })

    if (!response.ok) {
      let errorMessage = "Erro na análise"
      try {
        const errorData = await response.json()
        errorMessage = errorData.erro || errorMessage
      } catch (jsonError) {
        console.warn("Erro ao parsear resposta de erro:", jsonError)
        errorMessage = `Erro ${response.status}: ${response.statusText}`
      }
      throw new Error(errorMessage)
    }

    let data
    try {
      data = await response.json()
    } catch (jsonError) {
      console.error("Erro ao parsear resposta JSON:", jsonError)
      throw new Error("Resposta inválida do servidor")
    }

    if (!data || typeof data !== 'object') {
      throw new Error("Dados de resposta inválidos")
    }

    updateResults(data)
    results.classList.add("show")
    results.scrollIntoView({ behavior: "smooth", block: "start" })
  } catch (error) {
    console.error("Erro na análise:", error)
    showError(error.message || "Erro ao analisar a mensagem. Tente novamente.")
  } finally {
    analyzeBtn.disabled = false
    spinner.classList.remove("active")
    btnText.classList.remove("btn-loading")
  }
}

// Atualiza interface com resultados
function updateResults(data) {
  const riskIndicator = document.getElementById("riskIndicator")
  const riskText = document.getElementById("riskText")
  const meterFill = document.getElementById("meterFill")
  const riskCategory = document.getElementById("riskCategory")
  const analysisTimestamp = document.getElementById("analysisTimestamp")
  const suspiciousWordsList = document.getElementById("suspiciousWordsList")
  const suspiciousDomainsList = document.getElementById("suspiciousDomainsList")
  const recommendationsSection = document.getElementById("recommendationsSection")
  const recommendationsList = document.getElementById("recommendationsList")
  const threatDetailsSection = document.getElementById("threatDetailsSection")
  const threatDetailsList = document.getElementById("threatDetailsList")

  let riskScore = data.score_risco || 0
  if (isNaN(riskScore)) riskScore = 0
  riskScore = Math.round(riskScore)

  // Atualiza timestamp
  const now = new Date()
  analysisTimestamp.textContent = `Análise realizada em ${now.toLocaleString('pt-BR')}`

  // Atualiza indicador de risco
  riskIndicator.className = `risk-indicator ${data.nivel_risco}`

  let riskMessage = ""
  let riskIcon = ""
  let categoryText = ""

  switch (data.nivel_risco) {
    case "danger":
      riskMessage = `ALTO RISCO (${riskScore}/100) - Possível Golpe!`
      riskIcon = "fas fa-exclamation-triangle"
      categoryText = "CRÍTICO - AÇÃO IMEDIATA NECESSÁRIA"
      break
    case "warning":
      riskMessage = `RISCO MODERADO (${riskScore}/100) - Seja Cauteloso`
      riskIcon = "fas fa-exclamation-circle"
      categoryText = "ATENÇÃO - VERIFICAÇÃO RECOMENDADA"
      break
    default:
      riskMessage = `BAIXO RISCO (${riskScore}/100) - Aparenta ser Seguro`
      riskIcon = "fas fa-check-circle"
      categoryText = "SEGURO - SEM AMEAÇAS DETECTADAS"
  }

  riskText.innerHTML = `<i class="${riskIcon}" aria-hidden="true"></i> ${riskMessage}`
  riskCategory.textContent = categoryText

  // Atualiza medidor de risco
  meterFill.style.width = `${riskScore}%`

  // Atualiza badges
  document.getElementById("wordsBadge").textContent = data.palavras_suspeitas ? data.palavras_suspeitas.length : 0
  document.getElementById("domainsBadge").textContent = data.dominios_suspeitos ? data.dominios_suspeitos.length : 0
  document.getElementById("recommendationsBadge").textContent = data.recomendacoes ? data.recomendacoes.length : 0

  // Atualiza listas
  updateList(suspiciousWordsList, data.palavras_suspeitas, "fas fa-exclamation-circle")
  updateList(suspiciousDomainsList, data.dominios_suspeitos, "fas fa-globe")

  if (data.recomendacoes && data.recomendacoes.length > 0) {
    updateList(recommendationsList, data.recomendacoes, "fas fa-lightbulb")
    recommendationsSection.style.display = "block"
  } else {
    recommendationsSection.style.display = "none"
  }

  // Detalhes da ameaça
  const threatDetails = []
  if (data.detalhes) {
    if (data.detalhes.tipo_analise) {
      threatDetails.push(`Tipo de Análise: ${data.detalhes.tipo_analise}`)
    }
    if (data.detalhes.urls_encontradas) {
      threatDetails.push(`URLs Encontradas: ${data.detalhes.urls_encontradas}`)
    }
    if (data.detalhes.dominios_analisados && data.detalhes.dominios_analisados.length > 0) {
      threatDetails.push(`Domínios Analisados: ${data.detalhes.dominios_analisados.join(', ')}`)
    }
  }

  if (threatDetails.length > 0) {
    updateList(threatDetailsList, threatDetails, "fas fa-bug")
    threatDetailsSection.style.display = "block"
    document.getElementById("threatsBadge").textContent = threatDetails.length
  } else {
    threatDetailsSection.style.display = "none"
  }

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
  const meterFill = document.getElementById("meterFill")
  const riskCategory = document.getElementById("riskCategory")

  riskIndicator.className = "risk-indicator danger"
  riskText.innerHTML = `<i class="fas fa-exclamation-triangle" aria-hidden="true"></i> ${message}`
  riskCategory.textContent = "ERRO - PROBLEMA TÉCNICO"
  meterFill.style.width = "100%"

  // Limpa badges
  document.getElementById("wordsBadge").textContent = "0"
  document.getElementById("domainsBadge").textContent = "0"
  document.getElementById("recommendationsBadge").textContent = "0"

  // Limpa listas
  document.getElementById("suspiciousWordsList").innerHTML = '<li class="empty-state">Erro na análise</li>'
  document.getElementById("suspiciousDomainsList").innerHTML = '<li class="empty-state">Erro na análise</li>'
  
  // Esconde seções opcionais
  document.getElementById("recommendationsSection").style.display = "none"
  document.getElementById("threatDetailsSection").style.display = "none"

  document.getElementById("results").classList.add("show")
}

// Sistema de notificações (sem inline)
function showNotification(message, type = "info") {
  const notification = document.createElement("div")
  notification.className = `notification ${type}`
  notification.innerHTML = `
    <i class="fas fa-info-circle" aria-hidden="true"></i>
    <span>${message}</span>
  `

  document.body.appendChild(notification)

  setTimeout(() => {
    notification.classList.add("fade-out")
    setTimeout(() => {
      notification.remove()
    }, 300)
  }, 3000)
}

// Submissão do formulário
document.getElementById("analysisForm").addEventListener("submit", (e) => {
  e.preventDefault()
  verificarMensagem()
})

// Atalho de teclado: Ctrl + Enter
messageInput.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key === "Enter") {
    e.preventDefault()
    verificarMensagem()
  }
})

// Tema escuro
const toggleBtn = document.getElementById("toggle-theme")
const body = document.body

if (localStorage.getItem("tema") === "dark") {
  body.classList.add("dark")
  toggleBtn.textContent = "☀️"
}

toggleBtn.addEventListener("click", () => {
  body.classList.toggle("dark")
  if (body.classList.contains("dark")) {
    toggleBtn.textContent = "☀️"
    localStorage.setItem("tema", "dark")
  } else {
    toggleBtn.textContent = "🌙"
    localStorage.setItem("tema", "light")
  }
})
