import requests
import datetime
import hashlib
import hmac
import urllib.parse
import string
import sys

##############################
# Configurações de ambiente #
##############################

HOST = "URL"  # Exemplo
URL_BASE = f"https://{HOST}"

# Ajuste com seu AK e SK reais:
ACCESS_KEY = "AK"
SECRET_KEY = "SK"

# Ajuste o path do endpoint conforme a doc/ambiente real:
HTTP_URI = "/rest/cmsapp/v1/ping"  # Exemplo: "/rest/cmsapp/v1/ping"


##############################
# Funções utilitárias
##############################

def utc_timestamp_iso8601():
    """
    Gera a data/hora em formato UTC no padrão yyyy-MM-dd'T'HH:mm:ss.SSS'Z'.
    Exemplo: 2024-10-31T14:06:52.123Z
    """
    now = datetime.datetime.utcnow()
    millis = int(now.microsecond / 1000)
    return now.strftime(f"%Y-%m-%dT%H:%M:%S.{millis:03d}Z")


def sha256_hex(key, msg):
    """
    Calcula HMAC-SHA256 em hexa, equivalente ao SignerUtils.sha256Hex do Java.
    """
    return hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def path_normalize(value):
    """
    Faz a normalização estilo 'PathUtils.normalize' do Java:
      - Faz percent-encode de caracteres fora do conjunto unreserved
    """
    # urllib.parse.quote com safe="-._~" impede que esses caracteres sejam codificados
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
      - Ordenado alfabeticamente
      - Separado por \n
    """
    sorted_header_names = sorted(signed_headers.keys())
    lines = []
    for name in sorted_header_names:
        normalized_name = path_normalize(name)
        normalized_value = path_normalize(signed_headers[name])
        lines.append(f"{normalized_name}:{normalized_value}")
    return "\n".join(lines)


def build_signed_headers_string(signed_headers):
    """
    Monta a string 'content-length;content-type;host'
    ordenada alfabeticamente por nome do header.
    """
    sorted_header_names = sorted(signed_headers.keys())
    return ";".join([name.lower() for name in sorted_header_names])


def build_canonical_request(method, uri, query_params, signed_headers, body):
    """
    Monta o CanonicalRequest no formato:
      HttpMethod \n
      HttpURI \n
      (HttpParameters) \n
      SignedHeaders(...) \n
      CanonicalHeaders(...) \n
      Normalize(body)
    """
    # Garante que o uri comece com '/'
    if not uri.startswith("/"):
        uri = "/" + uri

    # Monta query string
    canonical_query = ""
    if query_params:
        kvs = []
        for k, v in query_params.items():
            k_enc = path_normalize(k)
            v_enc = path_normalize(v) if v else ""
            kvs.append(f"{k_enc}={v_enc}")
        kvs.sort()
        canonical_query = "&".join(kvs)

    # SignedHeaders string
    signed_headers_str = build_signed_headers_string(signed_headers)
    # CanonicalHeaders string
    canonical_headers_str = build_canonical_headers(signed_headers)
    # Normaliza o body
    normalized_body = path_normalize(body) if body else ""

    parts = [
        method.upper(),
        uri,
        canonical_query,  # se vazio, fica ""
        signed_headers_str,
        canonical_headers_str,
        normalized_body,
    ]

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
    ts = utc_timestamp_iso8601()

    auth_version = "auth-v2"
    signed_headers_str = build_signed_headers_string(signed_headers)
    auth_string_prefix = f"{auth_version}/{access_key}/{ts}/{signed_headers_str}"

    print("DEBUG >> authStringPrefix =", auth_string_prefix)

    signing_key = sha256_hex(secret_key, auth_string_prefix)
    print("DEBUG >> signingKey =", signing_key)

    canonical_request = build_canonical_request(
        method, uri, query_params, signed_headers, payload
    )
    print("DEBUG >> CanonicalRequest:\n", canonical_request)

    signature = sha256_hex(signing_key, canonical_request)
    print("DEBUG >> Signature =", signature)

    authorization = f"{auth_string_prefix}/{signature}"
    return authorization, ts


##############################
# Exemplo de uso (POST)
##############################

def cms_ping_test():
    """
    Tenta enviar POST para o CMS (ou API) no endpoint HTTP_URI.
    Se der erro, printa status code e response pra ajudar no debug.
    """
    # Montar URL final
    full_url = f"{URL_BASE}{HTTP_URI}"
    print(f"DEBUG >> Full URL = {full_url}")

    # Montar body
    body = '{"say": "Hello world!"}'
    content_length = str(len(body.encode("utf-8")))

    # Cabeçalhos obrigatórios
    headers_inicial = {
        "Host": HOST,
        "Content-Length": content_length,
        "Content-Type": "application/json;charset=UTF-8",
    }

    # Transformar pra signed_headers
    signed_headers = build_signed_headers(headers_inicial)

    print("\n==== [DEBUG] HEADERS INICIAIS ====")
    for k, v in headers_inicial.items():
        print(f"{k}: {v}")
    print("==================================")

    print("\n==== [DEBUG] ACCESS_KEY / SECRET_KEY ====")
    print("ACCESS_KEY:", ACCESS_KEY)
    print("SECRET_KEY:", SECRET_KEY)
    print("=========================================\n")

    # Gera o Authorization
    auth_header, timestamp = build_authorization_header(
        ACCESS_KEY,
        SECRET_KEY,
        method="POST",
        uri=HTTP_URI,
        query_params=None,  # se houver params, passe em dict
        payload=body,
        signed_headers=signed_headers
    )

    final_headers = {
        **headers_inicial,
        "Authorization": auth_header
    }

    print("\n==== [DEBUG] HEADERS FINAIS ENVIADOS ====")
    for k, v in final_headers.items():
        print(f"{k}: {v}")
    print("=========================================")

    # Envia a requisição
    try:
        # Caso tenha problema de certificado SSL, `verify=False` ignora.
        resp = requests.post(full_url, data=body, headers=final_headers, verify=False)
    except requests.RequestException as e:
        print("ERRO >> Falha na requisição HTTP:", e)
        sys.exit(1)

    print("\n==== [DEBUG] RESPOSTA ====")
    print("HTTP Status Code:", resp.status_code)
    print("Response Body:", resp.text)
    print("Response Headers:", resp.headers)
    print("==========================")

    # Dicas de troubleshooting
    if resp.status_code == 404:
        print("DICA: 404 significa que o endpoint provavelmente não existe.")
        print(f"      Verifique se {HTTP_URI} está correto.")
    elif resp.status_code == 401:
        print("DICA: 401 significa que as credenciais ou a assinatura podem estar incorretas.")
        print("      Verifique seu AccessKey / SecretKey ou compare a doc da API.")
    elif resp.status_code == 403:
        print("DICA: 403 normalmente é 'Forbidden'. Pode ser permissão ou assinatura incorreta.")
    elif 400 <= resp.status_code < 500:
        print("DICA: Algum problema do lado do cliente. Consulte a doc para ver se falta algo.")
    elif resp.status_code >= 500:
        print("DICA: Erro do lado do servidor (5xx). O serviço pode estar indisponível ou com bug.")


def main():
    cms_ping_test()


if __name__ == "__main__":
    main()
