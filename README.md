# Valider

Valider é uma CLI Python para diagnóstico técnico de URLs em domínios que você
controla ou tem autorização explícita para testar. Ela informa status HTTP,
redirecionamentos, DNS, dados básicos de TLS e título/descrição neutros de HTML.
Os resultados **não determinam se um perfil ou uma conta existe**; essa conclusão
é sempre apresentada como **INCONCLUSIVO**.

Valider não procura perfis, não classifica pessoas ou contas e não contorna
autenticação, CAPTCHA ou proteções. A allowlist explícita é obrigatória. Antes de
cada conexão, o destino é resolvido novamente e todos os endereços retornados
precisam ser globais; a conexão é fixada ao IP validado. Redirecionamentos passam
pelas mesmas verificações, evitando acesso a loopback, redes privadas,
link-local e destinos não globais. Somente HTTP/HTTPS nas portas padrão são
aceitos. Há intervalo mínimo de um segundo entre requisições e timeout máximo de
30 segundos.

## Instalação no Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv
git clone <URL_DO_REPOSITORIO>
cd Valider
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install .
```

O ambiente virtual evita alterações na instalação Python gerenciada pelo Kali.

## Uso autorizado

Autorize somente domínios próprios ou para os quais você tenha autorização
explícita. `--allow-domain` pode ser repetido; cada entrada autoriza o domínio
exato e seus subdomínios. Sem uma allowlist, a ferramenta não executa.

```bash
valider --allow-domain exemplo.com https://exemplo.com/
valider --allow-domain exemplo.com --allow-domain exemplo.net \
  https://www.exemplo.com/ https://exemplo.net/status
```

Para processar um arquivo UTF-8 com uma URL por linha (linhas vazias e linhas
iniciadas por `#` são ignoradas):

```bash
valider --allow-domain exemplo.com --input urls.txt
```

Limite o timeout entre 1 e 30 segundos. O intervalo mínimo é fixo em um segundo
por requisição e são aceitas no máximo 1.000 URLs por execução:

```bash
valider --allow-domain exemplo.com --timeout 8 --max-redirects 3 https://exemplo.com/
```

Exportação para JSON, TXT ou CSV:

```bash
valider --allow-domain exemplo.com --input urls.txt --format json --output resultados.json
valider --allow-domain exemplo.com --input urls.txt --format csv --output resultados.csv
valider --allow-domain exemplo.com https://exemplo.com/ --format txt --output resultados.txt
```

Sem `--output`, os resultados são exibidos no terminal usando Rich. URLs fora da
allowlist, malformadas, com portas não padrão ou que resolvam para endereços não
globais são rejeitadas sem conexão. Respostas HTTP e metadados HTML são dados
técnicos e não devem ser interpretados como confirmação de existência de contas.

## Desenvolvimento e testes

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```
