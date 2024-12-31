package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/tls"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "sort"
    "strings"
    "time"
)

// Configurações de ambiente
const (
    Host      = "10.22.26.181:28080"      // IP:Port
    AccessKey = "globalaktest"           // Seu AK
    SecretKey = "1q************20"       // Seu SK
    Scheme    = "https"
)

// Gera timestamp em UTC no formato yyyy-MM-dd'T'HH:mm:ss.SSS'Z'
func utcTimestampISO8601() string {
    now := time.Now().UTC()
    millis := now.Nanosecond() / 1_000_000
    return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        now.Year(), now.Month(), now.Day(),
        now.Hour(), now.Minute(), now.Second(), millis)
}

// Implementação estilo sha256Hex(secret, message)
func sha256Hex(key, data string) string {
    mac := hmac.New(sha256.New, []byte(key))
    mac.Write([]byte(data))
    return hex.EncodeToString(mac.Sum(nil))
}

// Faz o “percent-encode” estilo PathUtils.normalize()
func pathNormalize(value string) string {
    // url.QueryEscape codifica demais (por exemplo, `~` e outros).
    // Para ficar mais parecido com a doc, podemos usar url.PathEscape, 
    // mas esse também difere um pouco. Então vamos manualmente:
    return customPercentEncode(value)
}

// Precisamos de um encode mais customizado (similar ao Java), 
// mas pra simplificar vou fazer algo “próximo” usando substituição manual.
func customPercentEncode(value string) string {
    // Vou fazer um strings.Builder e “escapar” apenas o que não está em [A-Za-z0-9-_.~].
    // É um encode básico. Em produção, você pode refinar caso precise ficar idêntico.
    var sb strings.Builder
    for _, c := range value {
        // Verifica se é caractere “unreserved”
        if (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~' {
            sb.WriteRune(c)
        } else {
            // Percent-encode
            sb.WriteString(fmt.Sprintf("%%%02X", c))
        }
    }
    return sb.String()
}

// Monta a lista “header1;header2;header3” com nomes em minúsculo ordenados
func buildSignedHeadersString(signedHeaders map[string]string) string {
    var keys []string
    for k := range signedHeaders {
        keys = append(keys, strings.ToLower(k))
    }
    sort.Strings(keys)
    return strings.Join(keys, ";")
}

// Monta o CanonicalHeaders:
//  headerName:headerValue\n ...
//  ordenados alfabeticamente
//  com name e value normalizados
func buildCanonicalHeaders(signedHeaders map[string]string) string {
    var lines []string
    // Ordena pelas chaves
    var keys []string
    for k := range signedHeaders {
        keys = append(keys, strings.ToLower(k))
    }
    sort.Strings(keys)

    for _, k := range keys {
        // Normaliza a key e o value
        normKey := pathNormalize(k)
        normVal := pathNormalize(signedHeaders[k])
        lines = append(lines, fmt.Sprintf("%s:%s", normKey, normVal))
    }
    // Junta com \n
    return strings.Join(lines, "\n")
}

// Monta a query canonical (key=value&key2=value2...), ordenada
func buildCanonicalQueryString(queryParams map[string]string) string {
    if len(queryParams) == 0 {
        return ""
    }
    var kvs []string
    for k, v := range queryParams {
        normK := pathNormalize(k)
        normV := pathNormalize(v)
        kvs = append(kvs, fmt.Sprintf("%s=%s", normK, normV))
    }
    sort.Strings(kvs)
    return strings.Join(kvs, "&")
}

// Monta o canonical request:
//  HttpMethod \n
//  HttpURI \n
//  (HttpParameters?) \n
//  SignedHeaders(...) \n
//  CanonicalHeaders(...) \n
//  Normalize(body)
func buildCanonicalRequest(method, uri string, queryParams map[string]string, signedHeaders map[string]string, body string) string {
    // Garante que uri comece com /
    if !strings.HasPrefix(uri, "/") {
        uri = "/" + uri
    }

    canonicalQuery := buildCanonicalQueryString(queryParams)
    signedHeadersStr := buildSignedHeadersString(signedHeaders)
    canonicalHeadersStr := buildCanonicalHeaders(signedHeaders)
    normalizedBody := ""
    if body != "" {
        normalizedBody = pathNormalize(body)
    }

    // Monta as linhas
    // Se queryParams existir, canonicalQuery. Se não, string vazia
    // Observação: a doc coloca a queryParams + "\n" mesmo se estiver vazia (outra linha)
    parts := []string{
        strings.ToUpper(method),
        uri,
        canonicalQuery,       // se for vazio, fica string vazia
        signedHeadersStr,
        canonicalHeadersStr,
        normalizedBody,
    }

    return strings.Join(parts, "\n")
}

func buildAuthorizationHeader(accessKey, secretKey, method, uri string,
    queryParams map[string]string,
    body string,
    signedHeaders map[string]string) (string, string) {

    timestamp := utcTimestampISO8601()
    // authStringPrefix = "auth-v2/AK/timestamp/signedHeaders"
    authVersion := "auth-v2"
    shStr := buildSignedHeadersString(signedHeaders)
    authStringPrefix := fmt.Sprintf("%s/%s/%s/%s", authVersion, accessKey, timestamp, shStr)

    // signingKey = sha256Hex(secretKey, authStringPrefix)
    signingKey := sha256Hex(secretKey, authStringPrefix)

    // canonicalRequest
    canonicalRequest := buildCanonicalRequest(method, uri, queryParams, signedHeaders, body)

    // signature = sha256Hex(signingKey, canonicalRequest)
    signature := sha256Hex(signingKey, canonicalRequest)

    // Authorization = authStringPrefix + "/" + signature
    authorization := fmt.Sprintf("%s/%s", authStringPrefix, signature)
    return authorization, timestamp
}

// Exemplo de teste do CMS / ping
func cmsPingTest() error {
    // Endpoint
    httpURI := "/rest/cmsapp/v1/ping" // ex: "/rest/cmsapp/v1/ping"
    fullURL := fmt.Sprintf("%s://%s%s", Scheme, Host, httpURI)

    // Body
    body := `{"say":"Hello world!"}`
    contentLength := fmt.Sprintf("%d", len([]byte(body)))

    // Cabeçalhos iniciais
    headers := map[string]string{
        "Host":           Host,
        "Content-Length": contentLength,
        "Content-Type":   "application/json;charset=UTF-8",
    }

    // Gera Authorization
    authHeader, timestamp := buildAuthorizationHeader(
        AccessKey, SecretKey,
        "POST", httpURI,
        nil, // sem query params nesse ping
        body,
        headers,
    )

    // Monta a requisição
    req, err := http.NewRequest("POST", fullURL, strings.NewReader(body))
    if err != nil {
        return err
    }

    // Seta cabeçalhos
    for k, v := range headers {
        req.Header.Set(k, v)
    }
    // Adiciona o Authorization
    req.Header.Set("Authorization", authHeader)

    // Se precisar ignorar certificado SSL “inseguro”, crie um *http.Client custom:
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}

    // Executa
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    // Lê resposta
    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return err
    }

    fmt.Println("Status:", resp.StatusCode)
    fmt.Println("Timestamp que enviamos:", timestamp)
    fmt.Println("Authorization que enviamos:", authHeader)
    fmt.Println("Resposta do servidor:", string(bodyBytes))
    return nil
}

func main() {
    err := cmsPingTest()
    if err != nil {
        fmt.Println("Erro ao chamar cmsPingTest:", err)
    }
}
