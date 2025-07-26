# Exemplos de Demonstração - No-Phishing v2.0

## 🧪 Testes de Funcionalidade

### 1. Golpe de Colaboração/Freelancer (Score: 95+)

**Exemplo de mensagem suspeita:**
```
Olá! Vi seu perfil no GitHub e estou procurando alguém para uma colaboração de longo prazo. Sou um desenvolvedor web experiente com 10 anos de experiência.

Infelizmente, quando me mudei para Singapura, minha conta foi suspensa repentinamente devido a uma mudança de endereço. Mesmo após enviar documentos, a conta foi suspensa permanentemente.

Sua função é criar uma conta com seu nome e me permitir usá-la. Podemos ganhar pelo menos 2 mil por semana. Você ficará com 10% da receita.

Preciso da sua ajuda para participar das videoconferências e se preparar com respostas para perguntas técnicas.

O que você acha? Estou aberto a negociações.
```

**Indicadores detectados:**
- ✅ Golpe de colaboração detectado
- ✅ Solicitação de compartilhamento de conta
- ✅ Promessas financeiras suspeitas
- ✅ Manipulação psicológica
- ✅ Padrões de urgência

### 2. Golpe de Criptomoedas (Score: 90+)

**Exemplo de mensagem suspeita:**
```
🚀 OPORTUNIDADE ÚNICA! 🚀

Ganhe 500% de retorno garantido em apenas 24 horas!

Nosso sistema de trading com inteligência artificial garante lucros diários de 25% a 50%. 

✅ Bitcoin, Ethereum, NFT
✅ Yield farming com 80% de rentabilidade
✅ Staking com 120% de retorno anual
✅ Liquidity pools com 200% de ROI

Tempo limitado! Última chance de se juntar ao grupo VIP.

Clique aqui: https://bitcoin-profit-guaranteed.tk

⚠️ Garantido 100% seguro! ⚠️
```

**Indicadores detectados:**
- ✅ Golpe de criptomoedas detectado
- ✅ Promessas de retorno irreais
- ✅ Urgência e pressão
- ✅ TLD perigoso (.tk)
- ✅ Terminologia técnica fraudulenta

### 3. Phishing Bancário (Score: 85+)

**Exemplo de mensagem suspeita:**
```
ATENÇÃO: Sua conta Nubank foi SUSPENSA!

🔴 URGENTE: Ação necessária imediatamente!

Sua conta foi bloqueada devido a atividades suspeitas. Para desbloquear, clique no link abaixo e confirme seus dados:

https://nubank-seguro-verificacao.tk/confirmar-dados

⚠️ Você tem apenas 2 horas para resolver!
⚠️ Após esse prazo, sua conta será PERMANENTEMENTE SUSPENSA!

Confirme agora:
- Número do cartão
- CVV
- Data de validade
- Senha de 6 dígitos
- Token de segurança

Nubank - Segurança em primeiro lugar
```

**Indicadores detectados:**
- ✅ Imitação de marca (Nubank)
- ✅ TLD perigoso (.tk)
- ✅ Solicitação de credenciais
- ✅ Urgência extrema
- ✅ Ameaças de suspensão

### 4. Engenharia Social Tradicional (Score: 70+)

**Exemplo de mensagem suspeita:**
```
🎉 PARABÉNS! 🎉

Você foi SELECIONADO para receber um prêmio de R$ 50.000!

Você é um dos 10 sortudos escolhidos entre 1 milhão de pessoas!

Para resgatar seu prêmio, clique aqui:
https://premio-gratis-ganhe.ml

⚠️ OFERTA VÁLIDA APENAS HOJE!
⚠️ Não perca esta oportunidade única!

Clique AGORA para receber seu dinheiro!
```

**Indicadores detectados:**
- ✅ Engenharia social detectada
- ✅ Promessas de prêmios
- ✅ Urgência e pressão
- ✅ TLD perigoso (.ml)
- ✅ Chamadas para ação

### 5. Mensagem Segura (Score: 0-20)

**Exemplo de mensagem legítima:**
```
Olá João,

Gostaria de agendar uma reunião para discutir o projeto de desenvolvimento web que mencionamos.

Disponibilidade:
- Segunda-feira, 14h
- Terça-feira, 10h
- Quarta-feira, 16h

Por favor, confirme qual horário prefere.

Atenciosamente,
Maria Silva
Desenvolvedora Senior
maria.silva@empresa.com.br
```

**Resultado esperado:**
- ✅ Baixo risco (0-20 pontos)
- ✅ Sem indicadores suspeitos
- ✅ Domínio legítimo
- ✅ Linguagem profissional

## 🎯 Como Testar

### 1. Teste Básico
1. Acesse `http://localhost:5000`
2. Cole um dos exemplos acima
3. Clique em "Iniciar Análise de Segurança"
4. Observe os resultados detalhados

### 2. Teste de Performance
```bash
# Teste de carga simples
for i in {1..10}; do
  curl -X POST http://localhost:5000/verificar \
    -H "Content-Type: application/json" \
    -d '{"mensagem":"Teste de performance número '$i'"}'
done
```

### 3. Teste de Endpoints
```bash
# Health check
curl http://localhost:5000/health

# Test endpoint
curl http://localhost:5000/test

# Análise de exemplo
curl -X POST http://localhost:5000/verificar \
  -H "Content-Type: application/json" \
  -d '{"mensagem":"Parabéns! Você ganhou R$ 10.000!"}'
```

## 📊 Métricas de Teste

### Taxa de Detecção Esperada
- **Golpes de Colaboração:** 95%+
- **Golpes de Criptomoedas:** 90%+
- **Phishing Bancário:** 95%+
- **Engenharia Social:** 85%+
- **Falsos Positivos:** <5%

### Performance Esperada
- **Tempo de Análise:** <1 segundo
- **Memória:** <50MB
- **CPU:** <10% (pico)
- **Concorrência:** 10 análises simultâneas

## 🔧 Configurações de Teste

### Modo Debug
```python
# Em app.py
app.run(debug=True, host='127.0.0.1', port=5000)
```

### Logs Detalhados
```python
# Configuração de logging
logging.basicConfig(level=logging.DEBUG)
```

### Teste de Erros
```python
# Teste de entrada inválida
curl -X POST http://localhost:5000/verificar \
  -H "Content-Type: application/json" \
  -d '{"mensagem":""}'

# Teste de JSON inválido
curl -X POST http://localhost:5000/verificar \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'
```

## 🎨 Interface de Teste

### Elementos Visuais
- **Medidor de Risco:** Barra progressiva colorida
- **Badges:** Contadores de itens encontrados
- **Ícones:** Indicadores visuais por categoria
- **Cores:** Sistema de cores por nível de risco

### Responsividade
- **Desktop:** Layout em grid completo
- **Tablet:** Layout adaptativo
- **Mobile:** Layout em coluna única

### Tema
- **Claro:** Cores suaves e profissionais
- **Escuro:** Modo noturno para conforto visual
- **Auto:** Detecção automática de preferência

## 🚀 Próximos Passos

### Melhorias Planejadas
1. **Machine Learning:** Detecção baseada em IA
2. **API REST:** Endpoints para integração
3. **Dashboard:** Interface administrativa
4. **Relatórios:** Análises detalhadas
5. **Integração:** Plugins para navegadores

### Testes Futuros
- **Testes de Penetração:** Validação de segurança
- **Testes de Carga:** Performance sob pressão
- **Testes de Usabilidade:** Experiência do usuário
- **Testes de Acessibilidade:** Inclusão universal

---

**Use estes exemplos para testar e validar o sistema No-Phishing v2.0!** 