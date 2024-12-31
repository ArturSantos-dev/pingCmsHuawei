import requests
import datetime
import hashlib
import hmac
import urllib.parse
import string

##############################
# Configurações de ambiente #
##############################

HOST = "10.22.26.181:28080"    # IP:Port
URL_BASE = f"https://{HOST}"
ACCESS_KEY = "globalaktest"   # Seu AK
SECRET_KEY = "1q************20"  # Seu SK

##############################
# Funções utilitárias       #
##############################

def utc_timestamp_iso8601():
    """
    Gera a data/hora em formato UTC no padrão yyyy-MM-dd'T'HH:mm:ss.SSS'Z'.
    Exemplo: 2024-10-31T14:06:52.123Z
    """
    now = datetime.datetime.utcnow()
    # Pega milissegundos
    millis = int(now.microsecond / 1000)
    return now.strftime(f"%Y-%m-%dT%H:%M:%S.{millis:03d}Z")

def sha256_hex(key, msg):
    """
    Calcula HMAC-SHA256 em hexa, equivalente ao SignerUtils.sha256Hex do Java.
    """
    return hmac.new(
        key.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

def path_normalize(value):
    """
    Faz a normalização estilo 'PathUtils.normalize' do Java:
      - Faz percent-encode de caracteres fora do conjunto unreserved
    """
    # urllib.parse.quote já faz esse “percent-encode”.
    # Mas precisamos garantir que ~, -, ., _, 0-9, A-Z, a-z não sejam codificados.
    # Então setamos `safe=string.ascii_letters + string.digits + "-._~"`
    # Se quiser reproduzir idêntico, pode refinar mais.
    return urllib.parse.quote(value, safe="-._~")

def build_signed_headers(headers):
    """
    Converte as chaves de cabeçalho para lowercase e retorna em novo dicionário.
    Importante: a key 'authorization' não entra no cálculo, e host é obrigatório.
    """
    if not headers or "host" not in {k.lower() for k in headers.keys()}:
        raise ValueError("Cabeçalho 'host' é obrigatório no signedHeaders.")
    new_headers = {}
    for k, v in headers.items():
        new_headers[k.lower()] = v.strip()
    return new_headers

def build_canonical_headers(signed_headers):
    """
    Monta a string CanonicalHeaders:
      - Cada linha: "<lowercase_header_name>:<normalized_header_value>"
      - Ordenado alfabeticamente por header_name
      - Separado por \n (mas não adiciona \n no final)
    """
    # Ordena por nome de header
    sorted_header_names = sorted(signed_headers.keys())
    lines = []
    for name in sorted_header_names:
        normalized_name = path_normalize(name)
        normalized_value = path_normalize(signed_headers[name])
        lines.append(f"{normalized_name}:{normalized_value}")
    # Junta com '\n'
    return "\n".join(lines)

def build_signed_headers_string(signed_headers):
    """
    Monta a string 'content-length;content-type;host' etc.
    Ordenada alfabeticamente por nome do header.
    """
    sorted_header_names = sorted(signed_headers.keys())
    return ";".join([name.lower() for name in sorted_header_names])

def build_canonical_request(method, uri, query_params, signed_headers, body):
    """
    Monta o CanonicalRequest no formato:
      HttpMethod \n
      HttpURI \n
      (HttpParameters?) \n
      SignedHeaders(...) \n
      CanonicalHeaders(...) \n
      Normalize(body)
    """
    # Garantir que o uri comece com '/'
    if not uri.startswith("/"):
        uri = "/" + uri

    # Monta query string
    canonical_query = ""
    if query_params:
        # Normaliza e junta com '&'
        kvs = []
        for k, v in query_params.items():
            k_enc = path_normalize(k)
            v_enc = path_normalize(v) if v else ""
            kvs.append(f"{k_enc}={v_enc}")
        kvs.sort()
        canonical_query = "&".join(kvs)

    # SignedHeaders string, ex: "content-length;content-type;host"
    signed_headers_str = build_signed_headers_string(signed_headers)

    # CanonicalHeaders string
    canonical_headers_str = build_canonical_headers(signed_headers)

    # Normaliza o body
    normalized_body = path_normalize(body) if body else ""

    # Monta:
    # method \n
    # uri \n
    # querystring \n
    # signed_headers_str \n
    # canonical_headers_str \n
    # normalized_body
    parts = [
        method.upper(),
        uri,
    ]
    # Se tiver query, adicionamos, senão adicionamos uma linha vazia
    parts.append(canonical_query)
    parts.append(signed_headers_str)
    parts.append(canonical_headers_str)
    parts.append(normalized_body)

    # Juntamos com \n
    return "\n".join(parts)

def build_authorization_header(access_key, secret_key,
                              method, uri,
                              query_params, payload,
                              signed_headers):
    """
    Gera o header "Authorization" usando a regra:
      1) authStringPrefix = "auth-v2/AK/timestamp/signedHeaders"
      2) signingKey = sha256Hex(secretKey, authStringPrefix)
      3) signature = sha256Hex(signingKey, canonicalRequest)
      4) authorization = authStringPrefix + "/" + signature
    """
    # Gera timestamp
    ts = utc_timestamp_iso8601()

    # 1) authStringPrefix
    auth_version = "auth-v2"
    signed_headers_str = build_signed_headers_string(signed_headers)
    auth_string_prefix = f"{auth_version}/{access_key}/{ts}/{signed_headers_str}"

    # 2) signingKey
    signing_key = sha256_hex(secret_key, auth_string_prefix)

    # 3) canonicalRequest
    canonical_request = build_canonical_request(
        method, uri, query_params, signed_headers, payload
    )

    # 4) signature
    signature = sha256_hex(signing_key, canonical_request)

    authorization = f"{auth_string_prefix}/{signature}"
    return authorization, ts

##############################
# Exemplo de uso (POST)     #
##############################

def cms_ping_test():
    """
    Exemplo simples de envio POST para o CMS com autenticação.
    """
    # Definir endpoint
    http_uri = "/rest/cmsapp/v1/ping"
    full_url = f"{URL_BASE}{http_uri}"

    # Montar body da requisição
    body = '{"say": "Hello world!"}'
    # Calcula content-length
    content_length = str(len(body.encode("utf-8")))

    # Cabeçalhos básicos obrigatórios
    headers_inicial = {
        "Host": HOST,  
        "Content-Length": content_length,
        "Content-Type": "application/json;charset=UTF-8",
    }
    # Converte para lowercase e limpa
    signed_headers = build_signed_headers(headers_inicial)

    # Gera o header Authorization
    auth_header, timestamp = build_authorization_header(
        ACCESS_KEY,
        SECRET_KEY,
        method="POST",
        uri=http_uri,
        query_params=None,
        payload=body,
        signed_headers=signed_headers
    )

    # Insere o Authorization no dicionário final de headers
    # (precisamos mandar no formato exato e sem lowercase automático aqui)
    final_headers = {
        **headers_inicial,
        "Authorization": auth_header
    }

    print("---- HEADERS QUE SERÃO ENVIADOS ----")
    for k, v in final_headers.items():
        print(f"{k}: {v}")
    print("------------------------------------")

    # Envia a requisição
    # Caso o certificado não seja confiável, você pode usar verify=False
    response = requests.post(full_url, data=body, headers=final_headers, verify=False)

    print("Status Code:", response.status_code)
    print("Response Body:", response.text)

##############################
# Se quiser testar diretamente
##############################

if __name__ == "__main__":
    cms_ping_test()
