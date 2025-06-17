-----

## Detector de Phishing: Uma Ferramenta Contra Golpes Online

Este **Detector de Phishing** foi criado para o ajudar a identificar e proteger-se de mensagens e links maliciosos. A ideia para esta ferramenta surgiu de uma experiência pessoal, quando uma tentativa de **golpe de engenharia social** foi feita através de um e-mail.

-----

### A Inspiração: Um E-mail de Engenharia Social (Experienência Pessoal)

Imagine receber um e-mail com uma proposta aparentemente vantajosa. Ele começa de forma amigável, como "Olá, tudo bem?". O remetente descreve-se como um "desenvolvedor web experiente" que notou o seu perfil numa plataforma. A proposta é de uma "colaboração a longo prazo" com "lucros juntos", trabalhando poucas horas por semana numa conhecida plataforma de *freelancing*.

A história continua com um problema: o desenvolvedor mudou-se para um novo país (Singapura, no exemplo), e a sua conta na plataforma foi suspensa devido à alteração de localização. Mesmo após tentar reativá-la com documentos, a conta foi "permanentemente suspensa".

É aqui que entra a **engenharia social**: o golpista pede a sua ajuda. Sugere que crie uma nova conta na plataforma em seu nome e a partilhe com ele. Você teria que "participar em reuniões de vídeo se os clientes assim o quisessem", mas ele "ajudaria a preparar as respostas". A promessa é de um "lucro suficiente" e que, se a colaboração for bem-sucedida, poderiam "fazer pelo menos 2 mil por semana" em poucos meses, com você a receber "10% da receita", negociável.

Este tipo de e-mail é um exemplo clássico de **phishing**, que não procura apenas roubar credenciais, mas sim explorar a confiança e a ganância. O objetivo é levá-lo a criar uma conta sob seu nome que o golpista possa usar para atividades ilícitas, ou para enganar outros.

-----

### Como o Detector Ajuda

Inspirada por este tipo de ameaça, este detector foi desenvolvido para identificar automaticamente padrões e características comuns em golpes como o descrito:

  * **Verificação de Palavras-Chave**: Ele analisa o texto da mensagem em busca de palavras e frases frequentemente usadas em phishing (como "urgente", "verificar conta", "clique aqui", "lucro", "colaboração"). No caso do e-mail de exemplo, termos como "lucro", "colaboração", "ajuda", "criar uma conta" poderiam ser detetados.
  * **Análise de Links Suspeitos**: Embora o e-mail de exemplo não contivesse links diretos e óbvios, muitos golpes de engenharia social eventualmente direcionam para sites falsos. O detector é capaz de:
      * **Comparar com Listas Conhecidas**: Verifica se quaisquer URLs presentes na mensagem correspondem a bases de dados de sites de phishing conhecidos (seja através de uma API externa, como o URLhaus, ou de um ficheiro local como `urls_suspeitas.txt`).
      * **Detecção de Sites "Fora do Padrão" (Typosquatting)**: Esta é uma funcionalidade crucial. Mesmo que um site não esteja numa lista conhecida, o detector usa lógica avançada para identificar URLs que tentam imitar domínios legítimos, mas com pequenas alterações. Por exemplo:
          * **Erros de digitação**: Como "faceboook.com" em vez de "facebook.com".
          * **Adição de termos**: Como "itau-premios.com.br" em vez de "https://www.google.com/search?q=itau.com.br".
          * **Subdomínios estranhos**: Que podem ter palavras como "login", "segurança" ou "verify", mesmo que o domínio principal seja aparentemente legítimo.

Ao combinar a verificação de palavras-chave com uma análise inteligente de URLs, este detector oferece uma camada de segurança que o ajuda a identificar potenciais ameaças de phishing antes que se torne uma vítima.

----------------------------------------------------------------

Sites de phishing conhecidos: Se estiverem nas suas listas ou na API (se funcionar).
Sites "falsos": Que parecem, mas não são os sites verdadeiros (ex: faceboook.com.br, itau-premios.com.br).
Nota sobre a API: Ele tenta buscar uma lista de sites de phishing online (do URLhaus). Se vir erros como Erro de requisição..., significa que a ligação à API pode estar com problemas. Nesses casos, ele usa o seu ficheiro urls_suspeitas.txt.


-----

## Phishing Detector: A Tool Against Online Scams

This **Phishing Detector** was created to help you identify and protect yourself from malicious messages and links. The idea for this tool came from a personal experience, when an attempted **social engineering scam** was made via email.

-----

### The Inspiration: A Social Engineering Email (Personal Experience)

Imagine receiving an email with a seemingly advantageous proposal. It starts in a friendly way, like "Hello, how are you?". The sender describes himself as an "experienced web developer" who noticed your profile on a platform. The proposal is for a "long-term collaboration" with "joint profits", working a few hours a week on a well-known *freelancing* platform.

The story continues with a problem: the developer has moved to a new country (Singapore, in the example), and his account on the platform has been suspended due to the change of location. Even after trying to reactivate it with documents, the account was “permanently suspended”.

This is where the **social engineering** comes in: the scammer asks for your help. He suggests that you create a new account on the platform in your name and share it with him. You would have to “participate in video meetings if the clients wanted”, but he would “help prepare the answers”. He promises a “sufficient profit” and that, if the collaboration is successful, they could “make at least 2k per week” in a few months, with you receiving “10% of the revenue”, negotiable.

This type of email is a classic example of **phishing**, which seeks not only to steal credentials, but also to exploit trust and greed. The goal is to trick you into creating an account under your name that the scammer can use for illicit activities, or to deceive others.

-----

### How the Detector Helps

Inspired by this type of threat, this detector was developed to automatically identify common patterns and characteristics in scams like the one described:

* **Keyword Check**: It analyzes the message text for words and phrases frequently used in phishing (such as "urgent", "verify account", "click here", "profit", "collaboration"). In the case of the example email, terms such as "profit", "collaboration", "help", "create an account" could be detected.
* **Suspicious Link Analysis**: Although the example email did not contain any direct and obvious links, many social engineering scams eventually direct to fake websites. The detector is capable of:
* **Comparison with Known Lists**: Checks if any URLs present in the message match databases of known phishing sites (either through an external API, such as URLhaus, or from a local file such as `urls_suspicious.txt`).
* **Detection of "Non-Standard" Sites (Typosquatting)**: This is a crucial feature. Even if a site is not on a known list, the detector uses advanced logic to identify URLs that try to imitate legitimate domains, but with small changes. For example:
* **Typos**: Such as "faceboook.com" instead of "facebook.com".
* **Adding terms**: Such as "itau-premios.com.br" instead of "https://www.google.com/search?q=itau.com.br". * **Strange subdomains**: These may contain words like "login", "security" or "verify", even if the main domain seems legitimate.

By combining keyword checking with intelligent URL analysis, this detector provides a layer of security that helps you identify potential phishing threats before you become a victim.

----------------------------------------------------------------

Known phishing sites: If they are on your lists or in the API (if it works).
"Fake" sites: Which look like, but are not, the real sites (e.g. faceboook.com.br, itau-premios.com.br).
Note about the API: It tries to fetch a list of phishing sites online (from URLhaus). If you see errors like Request error..., it means that the connection to the API may be having problems. In such cases, it uses your urls_suspicious.txt file.