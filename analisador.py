import re
import tldextract

def carregar_lista_arquivo(nome_arquivo):
    """
    Carrega uma lista de palavras ou domínios de um arquivo de texto,
    retornando uma lista com cada linha como item.
    """
    with open(nome_arquivo, 'r', encoding='utf-8') as f:
        return f.read().splitlines()

def detectar_palavras_suspeitas(mensagem, lista_palavras):
    """
    Verifica se a mensagem contém alguma palavra da lista de palavras suspeitas.
    Retorna uma lista com as palavras encontradas.
    """
    mensagem = mensagem.lower()
    encontradas = [palavra for palavra in lista_palavras if palavra in mensagem]
    return encontradas

def detectar_links(mensagem):
    """
    Usa regex para extrair links que comecem com http ou https.
    Retorna uma lista de URLs encontradas.
    """
    padrao_url = r'https?://[^\s]+'
    return re.findall(padrao_url, mensagem)

def extrair_dominio(url):
    """
    Extrai o domínio principal de uma URL (ex: itau.com.br) usando tldextract.
    """
    extraido = tldextract.extract(url)
    return f"{extraido.domain}.{extraido.suffix}"

def detectar_urls_suspeitas(mensagem, lista_dominios_suspeitos):
    """
    Detecta se existem URLs suspeitas na mensagem.
    Retorna uma lista dos domínios suspeitos encontrados.
    """
    links = detectar_links(mensagem)
    suspeitos = []
    for link in links:
        dominio = extrair_dominio(link)
        if dominio in lista_dominios_suspeitos:
            suspeitos.append(dominio)
    return suspeitos
