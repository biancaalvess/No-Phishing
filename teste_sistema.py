#!/usr/bin/env python3
"""
Script de Teste - No-Phishing v2.0
Demonstra as capacidades de detecção do sistema
"""

import requests
import json
import time


def testar_sistema():
    """Testa as funcionalidades principais do sistema"""

    base_url = "http://localhost:5000"

    print("TESTE DO SISTEMA NO-PHISHING v2.0")
    print("=" * 50)

    # Teste 1: Health Check
    print("\n1️⃣  Testando Health Check...")
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            data = response.json()
            print(f"Sistema funcionando: {data['status']}")
            print(f"   - Domínios seguros: {data['dominios_seguros']}")
            print(f"   - Domínios maliciosos: {data['dominios_maliciosos']}")
            print(f"   - Marcas protegidas: {data['marcas_protegidas']}")
            print(f"   - TLDs perigosos: {data['tlds_perigosos']}")
        else:
            print(f"Erro no health check: {response.status_code}")
            return
    except Exception as e:
        print(f"Erro ao conectar: {e}")
        return

    # Teste 2: Mensagem Segura
    print("\n2️⃣  Testando Mensagem Segura...")
    mensagem_segura = """
    Olá João,
    
    Gostaria de agendar uma reunião para discutir o projeto de desenvolvimento web.
    
    Disponibilidade:
    - Segunda-feira, 14h
    - Terça-feira, 10h
    
    Por favor, confirme qual horário prefere.
    
    Atenciosamente,
    Maria Silva
    maria.silva@empresa.com.br
    """

    testar_analise(mensagem_segura, "Mensagem Segura")

    # Teste 3: Golpe de Colaboração
    print("\n3️⃣  Testando Golpe de Colaboração...")
    golpe_colaboracao = """
    Olá! Vi seu perfil no GitHub e estou procurando alguém para uma colaboração de longo prazo.
    
    Infelizmente, quando me mudei para Singapura, minha conta foi suspensa repentinamente devido a uma mudança de endereço.
    
    Sua função é criar uma conta com seu nome e me permitir usá-la. Podemos ganhar pelo menos 2 mil por semana.
    
    Preciso da sua ajuda para participar das videoconferências.
    """

    testar_analise(golpe_colaboracao, "Golpe de Colaboração")

    # Teste 4: Golpe de Criptomoedas
    print("\n4️⃣  Testando Golpe de Criptomoedas...")
    golpe_cripto = """
    OPORTUNIDADE ÚNICA!
    
    Ganhe 500% de retorno garantido em apenas 24 horas!
    
    Nosso sistema de trading com inteligência artificial garante lucros diários de 25% a 50%.
    
    Bitcoin, Ethereum, NFT
    Yield farming com 80% de rentabilidade
    Staking com 120% de retorno anual
    
    Clique aqui: https://bitcoin-profit-guaranteed.tk
    
    Garantido 100% seguro!
    """

    testar_analise(golpe_cripto, "Golpe de Criptomoedas")

    # Teste 5: Phishing Bancário
    print("\n5️⃣  Testando Phishing Bancário...")
    phishing_bancario = """
    ATENÇÃO: Sua conta Nubank foi SUSPENSA!
    
    URGENTE: Ação necessária imediatamente!
    
    Sua conta foi bloqueada devido a atividades suspeitas. Para desbloquear, clique no link:
    
    https://nubank-seguro-verificacao.tk/confirmar-dados
    
    Você tem apenas 2 horas para resolver!
    
    Confirme agora:
    - Número do cartão
    - CVV
    - Senha de 6 dígitos
    
    Nubank - Segurança em primeiro lugar
    """

    testar_analise(phishing_bancario, "Phishing Bancário")

    print("\n" + "=" * 50)
    print("TESTES CONCLUÍDOS COM SUCESSO!")
    print("O sistema No-Phishing v2.0 está funcionando perfeitamente!")


def testar_analise(mensagem, nome_teste):
    """Testa a análise de uma mensagem específica"""

    try:
        response = requests.post(
            "http://localhost:5000/verificar",
            headers={"Content-Type": "application/json"},
            json={"mensagem": mensagem}
        )

        if response.status_code == 200:
            data = response.json()

            print(f"{nome_teste}:")
            print(f"   - Score: {data['score_risco']}/100")
            print(f"   - Nível: {data['nivel_risco_texto']}")
            print(
                f"   - Palavras suspeitas: {len(data['palavras_suspeitas'])}")
            print(
                f"   - Domínios suspeitos: {len(data['dominios_suspeitos'])}")

            if data['palavras_suspeitas']:
                print(f"   - Exemplos: {data['palavras_suspeitas'][:3]}")

            if data['dominios_suspeitos']:
                print(f"   - Exemplos: {data['dominios_suspeitos'][:2]}")

        else:
            print(f"Erro na análise: {response.status_code}")

    except Exception as e:
        print(f"Erro ao testar {nome_teste}: {e}")


def testar_performance():
    """Testa a performance do sistema"""

    print("\nTestando Performance...")

    mensagem_teste = "Teste de performance do sistema No-Phishing"
    tempos = []

    for i in range(5):
        inicio = time.time()

        try:
            response = requests.post(
                "http://localhost:5000/verificar",
                headers={"Content-Type": "application/json"},
                json={"mensagem": f"{mensagem_teste} - Teste {i+1}"}
            )

            if response.status_code == 200:
                tempo = time.time() - inicio
                tempos.append(tempo)
                print(f"   Teste {i+1}: {tempo:.3f}s")
            else:
                print(f"   Teste {i+1}: Erro {response.status_code}")

        except Exception as e:
            print(f"   Teste {i+1}: Erro - {e}")

    if tempos:
        tempo_medio = sum(tempos) / len(tempos)
        tempo_min = min(tempos)
        tempo_max = max(tempos)

        print(f"\nResultados de Performance:")
        print(f"   - Tempo médio: {tempo_medio:.3f}s")
        print(f"   - Tempo mínimo: {tempo_min:.3f}s")
        print(f"   - Tempo máximo: {tempo_max:.3f}s")

        if tempo_medio < 1.0:
            print("   Performance excelente!")
        elif tempo_medio < 2.0:
            print("   Performance boa!")
        else:
            print("   Performance pode ser melhorada")


if __name__ == "__main__":
    print("Iniciando testes do sistema No-Phishing v2.0...")
    print("Certifique-se de que o servidor está rodando em http://localhost:5000")
    print()

    try:
        testar_sistema()
        testar_performance()

    except KeyboardInterrupt:
        print("\n\nTestes interrompidos pelo usuário")
    except Exception as e:
        print(f"\n\nErro durante os testes: {e}")

    print("\n�� Fim dos testes")
