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
    const response = await fetch("/verificar", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ mensagem: message }),
    })

    if (!response.ok) {
      const errorData = await response.json()
      throw new Error(errorData.erro || "Erro na análise")
    }

    const data = await response.json()

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
  const suspiciousWordsList = document.getElementById("suspiciousWordsList")
  const suspiciousDomainsList = document.getElementById("suspiciousDomainsList")
  const recommendationsSection = document.getElementById("recommendationsSection")
  const recommendationsList = document.getElementById("recommendationsList")

  let riskScore = data.score_risco || 0
  if (isNaN(riskScore)) riskScore = 0
  riskScore = Math.round(riskScore)

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

  updateList(suspiciousWordsList, data.palavras_suspeitas, "fas fa-exclamation-circle")
  updateList(suspiciousDomainsList, data.dominios_suspeitos, "fas fa-globe")

  if (data.recomendacoes && data.recomendacoes.length > 0) {
    updateList(recommendationsList, data.recomendacoes, "fas fa-lightbulb")
    recommendationsSection.style.display = "block"
  } else {
    recommendationsSection.style.display = "none"
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

  riskIndicator.className = "risk-indicator danger"
  riskText.innerHTML = `<i class="fas fa-exclamation-triangle" aria-hidden="true"></i> ${message}`

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
