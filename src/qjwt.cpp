#include "qjwt.h"

#include <QDateTime>
#include <QDebug>
#include <QJsonArray>
#include <utility>

bool ssl_initialized = false;

QJWT::QJWT()
{
    setAlgorithm("HS256");
    m_baPayload = "{}";

    init_SSL();
}

QJWT::QJWT(QString token, QString secret, QVariantMap options)
{
    m_vmOptions = std::move(options);
    setToken(token);
    setSecret(secret);

    init_SSL();
}

QJWT::QJWT(const QJsonDocument& payload, QString secret, QVariantMap options)
{
    m_vmOptions = std::move(options);
    setPayload(payload);
    setSecret(std::move(secret));

    init_SSL();
}

QJsonDocument QJWT::header()
{
    return QJsonDocument::fromJson(m_baHeader);
}

QJsonDocument QJWT::payload()
{
    return QJsonDocument::fromJson(m_baPayload);
}

bool QJWT::setPayload(const QJsonDocument& payload)
{
    if (payload.isEmpty() || payload.isNull() || !payload.isObject()) {
        return false;
    }

    m_baPayload = payload.toJson(QJsonDocument::Compact);

    return true;
}

QString QJWT::lastError()
{
    return m_strLastError;
}

bool QJWT::setSecret(const QString& secret)
{
    if (secret.isEmpty() || secret.isNull()) {
        return false;
    }

    m_baSecret = secret.toUtf8();

    return true;
}

bool QJWT::setAlgorithm(const QString& algorithm)
{
    if (!supportedAlgorithms().contains(algorithm)) {
        return false;
    }

    m_baAlgorithm = algorithm.toUtf8();
    m_baHeader = R"({"typ": "JWT", "alg" : ")" + m_baAlgorithm + "\"}";

    return true;
}

QString QJWT::token()
{
    return signToken();
}

bool QJWT::setToken(const QString& token)
{
    QStringList parts = token.split(".");

    if (parts.length() >= 2 && parts.length() <= 3) {
        m_baHeader = QByteArray::fromBase64(parts[0].toUtf8(), QByteArray::OmitTrailingEquals | QByteArray::Base64UrlEncoding);
        m_baPayload = QByteArray::fromBase64(parts[1].toUtf8(), QByteArray::OmitTrailingEquals | QByteArray::Base64UrlEncoding);
        m_baSignature = parts[2].toUtf8();
        return true;
    }

    m_baHeader = "{}";
    m_baPayload = "{}";
    m_baSignature = "";

    return false;
}

bool QJWT::isValid()
{
    return !verifySignature(m_baHeader.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals) + "." + m_baPayload.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals) + "." + m_baSignature).isEmpty();
}

QString QJWT::signToken()
{
    QByteArray signature;
    QString alg = m_vmOptions.value("alg", "HS256").toString().left(2);
    QJsonObject header;
    header["alg"] = m_vmOptions.value("alg", "HS256").toString();
    header["typ"] = "JWT";

    if ((m_vmOptions.contains("alg") && m_vmOptions.keys().length() > 1) || (!m_vmOptions.contains("alg") && m_vmOptions.keys().length() > 0)) {
        QJsonObject pl = QJsonDocument::fromJson(m_baPayload).object();
        QVariantMap opCopy = m_vmOptions;
        opCopy.remove("alg");
        foreach (QString key, opCopy.keys()) {
            pl[key] = opCopy[key].toJsonValue();
        }
        m_baPayload = QJsonDocument(pl).toJson(QJsonDocument::Compact);
    }

    QByteArray message;
    message += QJsonDocument(header).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    message += ".";
    message += m_baPayload.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    int bits = m_vmOptions.value("alg", "HS256").toString().rightRef(3).toInt();
    QCryptographicHash::Algorithm method;

    switch (bits) {
    case 384:
        method = QCryptographicHash::Sha384;
        break;
    case 512:
        method = QCryptographicHash::Sha512;
        break;
    case 256:
    default:
        method = QCryptographicHash::Sha256;
        break;
    }

    if (alg == "HS") { // HMAC-SHAxxx
        signature = QMessageAuthenticationCode::hash(message, m_baSecret, method);
    }
#ifndef NO_OPENSSL
    else if (alg == "RS") { // RSA-SHAxxx
        signature = getAsymmetricSignature(message, m_baSecret, method);
    } else if (alg == "ES") { // ECDSA-SHAxxx
        signature = getAsymmetricSignature(message, m_baSecret, method);
        signature = derToJose(signature, method);
    }
#endif

    QString token;

    token += message;
    token += ".";
    token += signature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    return token;
}

QJsonDocument QJWT::verify(QString token, QString secret, QVariantMap options)
{
    QJWT jwt(std::move(token), std::move(secret), std::move(options));

    if (jwt.isValid()) {
        return jwt.payload();
    }

    return QJsonDocument();
}

QJsonDocument QJWT::verifySignature(const QString& token)
{
    QStringList parts = token.split('.');
    QByteArray message = parts[0].toUtf8() + '.' + parts[1].toUtf8();
    QJsonObject header;
    QJsonDocument payload;
    QByteArray signature = QByteArray::fromBase64(parts[2].toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    bool isValidToken = false;

    if (parts.size() < 2 && parts.size() > 3) {
        m_strLastError = QString("invalid number of parts: %1").arg(parts.size());
        return payload;
    }

    header = QJsonDocument::fromJson(QByteArray::fromBase64(parts[0].toUtf8())).object();

    if (header["alg"].toString() != "none") {
        QString alg = header["alg"].toString().left(2);
        int bits = header["alg"].toString().rightRef(3).toInt();

        QCryptographicHash::Algorithm method;

        switch (bits) {
        case 384:
            method = QCryptographicHash::Sha384;
            break;
        case 512:
            method = QCryptographicHash::Sha512;
            break;
        case 256:
        default:
            method = QCryptographicHash::Sha256;
            break;
        }

        if (alg == "HS") { // HMAC-SHAxxx
            isValidToken = signature == QMessageAuthenticationCode::hash(message, m_baSecret, method);
        }
#ifndef NO_OPENSSL
        else if (alg == "RS") { // RSA-SHAxxx
            isValidToken = verifyAsymmetricSignature(message, signature, m_baSecret, method);
        } else if (alg == "ES") { // ECDSA-SHAxxx
            isValidToken = verifyAsymmetricSignature(message, joseToDer(signature, method), m_baSecret, method);
        }
#endif
    } else {
        isValidToken = true;
    }

    if (!isValidToken)
        m_strLastError = "token signature invalid";

    payload = QJsonDocument::fromJson(QByteArray::fromBase64(parts[1].toUtf8(), QByteArray::OmitTrailingEquals | QByteArray::Base64UrlEncoding));
    QJsonObject plO = payload.object();

    //iss, sub, aud, exp, nbf, iat, jti

    // iss == QString case sensitive       issuer
    if (isValidToken && m_vmOptions.contains("iss")) {
        if (m_vmOptions["iss"].type() == QVariant::String) {
            isValidToken = m_vmOptions["iss"].toString() == plO["iss"].toString();
        } else if (m_vmOptions["iss"].type() == QVariant::StringList) {
            isValidToken = m_vmOptions["iss"].toStringList().contains(plO["iss"].toString());
        }
        if (!isValidToken)
            m_strLastError = "iss invalid";
    }

    // sub == QString case sensitive       subject
    if (isValidToken && m_vmOptions.contains("sub")) {
        isValidToken = m_vmOptions["sub"].toString() == plO["sub"].toString();
        if (!isValidToken)
            m_strLastError = "sub invalid";
    }

    // aud == QString / QStringList        audience
    if (isValidToken && m_vmOptions.contains("aud")) {
        QStringList plAud;
        if (plO["aud"].isString()) {
            plAud << plO["aud"].toString();
        } else {
            foreach (QJsonValue i, plO["aud"].toArray()) {
                plAud << i.toString();
            }
        }
        QStringList opAud;
        if (m_vmOptions["aud"].type() == QVariant::String) {
            opAud << m_vmOptions["aud"].toString();
        } else {
            opAud << m_vmOptions["aud"].toStringList();
        }
        plAud += opAud;
        isValidToken = plAud.removeDuplicates() > 0;
        if (!isValidToken)
            m_strLastError = "aud invalid";
    }

    // exp == unix timestamp => QDateTime  expiration
    if (isValidToken && plO.contains("exp") && !(!m_vmOptions.contains("ignoreExpiration") || m_vmOptions["ignoreExpiration"].toBool())) {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 8, 0))
        qint64 currentTime = QDateTime::currentDateTime().toSecsSinceEpoch() + m_vmOptions.value("clockTolerance", 0).toLongLong();
#else
        qint64 currentTime = QDateTime::currentDateTime().toTime_t() + m_vmOptions.value("clockTolerance", 0).toLongLong();
#endif
        isValidToken = QJsonValue(plO["exp"]).toVariant().toLongLong() >= currentTime;
        if (!isValidToken)
            m_strLastError = "token expired";
    }

    // nbf == unix timestamp => QDateTime  not before
    if (isValidToken && plO.contains("nbf") && !(m_vmOptions.contains("ignoreNotBefore") && !m_vmOptions["ignoreNotBefore"].toBool())) {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 8, 0))
        qint64 currentTime = QDateTime::currentDateTime().toSecsSinceEpoch() + m_vmOptions.value("clockTolerance", 0).toLongLong();
#else
        qint64 currentTime = QDateTime::currentDateTime().toTime_t() + m_vmOptions.value("clockTolerance", 0).toLongLong();
#endif
        isValidToken = QJsonValue(plO["nbf"]).toVariant().toLongLong() <= currentTime;
        if (!isValidToken)
            m_strLastError = "token not active anymore";
    }

    // iat == unix timestamp => QDateTime  issued at
    if (isValidToken && m_vmOptions.contains("maxAge")) {
        qint64 maxAge = m_vmOptions["maxAge"].toLongLong() + m_vmOptions.value("clockTolerance", 0).toLongLong();
        isValidToken = plO.contains("iat") && QJsonValue(plO["iat"]).toVariant().toLongLong() < maxAge;
        if (!isValidToken)
            m_strLastError = "max age exceeded";
    }

    // jti == QString case sensitive       JWT ID
    if (isValidToken && m_vmOptions.contains("jti")) {
        isValidToken = plO.contains("jti") && m_vmOptions["jti"].toString() == plO["jti"].toString();
        if (!isValidToken)
            m_strLastError = "jti invalid";
    }

    return isValidToken ? payload : QJsonDocument();
}

#ifndef NO_OPENSSL
void QJWT::init_SSL()
{
    ssl_initialized = true;
    SSL_load_error_strings();
    OPENSSL_no_config();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
    OpenSSL_add_all_algorithms();

    sk_SSL_COMP_zero(SSL_COMP_get_compression_methods());

#ifndef OPENSSL_NO_ENGINE
    ERR_load_ENGINE_strings();
    ENGINE_load_builtin_engines();
#endif // !OPENSSL_NO_ENGINE
    ERR_load_crypto_strings();
    SSL_load_error_strings();
}

bool QJWT::verifyAsymmetricSignature(const QByteArray& message, const QByteArray& signature, const QByteArray& key, QCryptographicHash::Algorithm method)
{
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
    EVP_MD_CTX* mdctx_ = EVP_MD_CTX_new();
#else
    EVP_MD_CTX* mdctx_ = EVP_MD_CTX_create();
#endif
    QByteArray sign_type;
    QByteArray pubkey_prefix = "-----BEGIN PUBLIC KEY-----";
    QByteArray pubrsa_prefix = "-----BEGIN RSA PUBLIC KEY-----";

    init_SSL();

    switch (method) {
    case QCryptographicHash::Sha256:
        sign_type = "sha256";
        break;
    case QCryptographicHash::Sha384:
        sign_type = "sha384";
        break;
    case QCryptographicHash::Sha512:
        sign_type = "sha512";
        break;
    default:
        m_strLastError = QString("%1 not implemented").arg(method);
        return false;
    }

    const EVP_MD* md = EVP_get_digestbyname(sign_type.constData());
    if (md == nullptr) {
        m_strLastError = "digest not found";
        return false;
    }

    EVP_MD_CTX_init(mdctx_);
    if (!EVP_VerifyInit_ex(mdctx_, md, nullptr)) {
        m_strLastError = "init error";
        return false;
    }

    if (!EVP_VerifyUpdate(mdctx_, message.constData(), static_cast<size_t>(message.length()))) {
        m_strLastError = "update error";
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    BIO* bp = nullptr;
    X509* x509 = nullptr;
    bool fatal = true;
    int r = 0;

    bp = BIO_new_mem_buf((char*)key.data(), key.length());
    if (bp == nullptr)
        goto exit;

    if (qstrncmp(key.constData(), pubkey_prefix.constData(), pubkey_prefix.length() /*-1*/) == 0) {
        pkey = PEM_read_bio_PUBKEY(bp, nullptr, nullptr, nullptr);
        if (pkey == nullptr)
            goto exit;
    } else if (qstrncmp(key.constData(), pubrsa_prefix.constData(), pubrsa_prefix.length() /*-1*/) == 0) {
        RSA* rsa = PEM_read_bio_RSAPublicKey(bp, nullptr, nullptr, nullptr);
        if (rsa) {
            pkey = EVP_PKEY_new();
            if (pkey)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        }
        if (pkey == nullptr)
            goto exit;
    } else {
        // X.509 fallback
        x509 = PEM_read_bio_X509(bp, nullptr, nullptr, nullptr);
        if (x509 == nullptr)
            goto exit;

        pkey = X509_get_pubkey(x509);
        if (pkey == nullptr)
            goto exit;
    }

    fatal = false;
    r = EVP_VerifyFinal(mdctx_, reinterpret_cast<const unsigned char*>(signature.constData()), static_cast<uint>(signature.length()), pkey);

    if (r < 0) {
        m_strLastError = ERR_error_string(ERR_get_error(), nullptr);
    } else if (r == 0) {
        m_strLastError = "signature invalid";
    }

exit:
    if (pkey != nullptr)
        EVP_PKEY_free(pkey);
    if (bp != nullptr)
        BIO_free_all(bp);
    if (x509 != nullptr)
        X509_free(x509);

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
    EVP_MD_CTX_free(mdctx_);
#else
    EVP_MD_CTX_destroy(mdctx_);
#endif

    if (fatal) {
        m_strLastError = "public key error";
        return false;
    }

    return r == 1;
}

QByteArray QJWT::getAsymmetricSignature(const QByteArray& message, const QByteArray& key, QCryptographicHash::Algorithm method)
{
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
    EVP_MD_CTX* mdctx_ = EVP_MD_CTX_new();
#else
    EVP_MD_CTX* mdctx_ = EVP_MD_CTX_create();
#endif
    QByteArray sign_type;
    unsigned int sig_len = 8192;
    //unsigned char sig[sig_len];
    unsigned char sig[8192];

    init_SSL();

    switch (method) {
    case QCryptographicHash::Sha256:
        sign_type = "sha256";
        break;
    case QCryptographicHash::Sha384:
        sign_type = "sha384";
        break;
    case QCryptographicHash::Sha512:
        sign_type = "sha512";
        break;
    default:
        m_strLastError = QString("%1 not implemented").arg(method);
        return QByteArray();
        break;
    }

    const EVP_MD* md = EVP_get_digestbyname(sign_type.constData());
    if (md == nullptr) {
        m_strLastError = "digest not found";
        return QByteArray();
    }

    EVP_MD_CTX_init(mdctx_);
    if (!EVP_SignInit_ex(mdctx_, md, nullptr)) {
        m_strLastError = "init error";
        return QByteArray();
    }

    if (!EVP_SignUpdate(mdctx_, message.constData(), message.length())) {
        m_strLastError = "update error";
        return QByteArray();
    }

    BIO* bp = nullptr;
    EVP_PKEY* pkey = nullptr;
    bool fatal = true;

    bp = BIO_new_mem_buf(const_cast<char*>(key.data()), key.length());
    if (bp == nullptr)
        goto exit;

    pkey = PEM_read_bio_PrivateKey(bp, nullptr, nullptr, nullptr);

    if (pkey == nullptr || 0 != ERR_peek_error())
        goto exit;

    if (EVP_SignFinal(mdctx_, sig, &sig_len, pkey))
        fatal = false;

exit:
    if (pkey != nullptr)
        EVP_PKEY_free(pkey);
    if (bp != nullptr)
        BIO_free_all(bp);

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
    EVP_MD_CTX_free(mdctx_);
#else
    EVP_MD_CTX_destroy(mdctx_);
#endif

    if (fatal) {
        m_strLastError = "private key error";
        return QByteArray();
    }

    return QByteArray(reinterpret_cast<char*>(sig), static_cast<int>(sig_len));
}

QByteArray QJWT::derToJose(QByteArray& signature, QCryptographicHash::Algorithm method)
{
    int paramBytes;

    switch (method) {
    case QCryptographicHash::Sha256:
        paramBytes = 32;
        break;
    case QCryptographicHash::Sha384:
        paramBytes = 48;
        break;
    case QCryptographicHash::Sha512:
        paramBytes = 64;
        break;
    default:
        m_strLastError = "hash algo not implemented";
        return QByteArray();
        break;
    }

    int maxParamLength = paramBytes + 1;
    int pos = 0;
    QByteArray baJOSE;

    if (signature[pos] != (char)0x30) {
        m_strLastError = "tag seq missing";
        return QByteArray();
    }

    int seqLength = signature[++pos];
    if (seqLength == (0x80 | 1)) {
        seqLength = signature[++pos] + (1 << 8);
    }

    if (signature[++pos] != (char)0x2) {
        m_strLastError = "tag int missing";
        return QByteArray();
    }

    int rLength = signature[++pos];

    if (maxParamLength < rLength) {
        m_strLastError = "param to short";
        return QByteArray();
    }

    pos++;

    if (rLength > paramBytes) {
        pos += rLength - paramBytes;
        baJOSE.append(signature.mid(pos, paramBytes));
        pos += paramBytes;
    } else {
        baJOSE.append(QByteArray(paramBytes - rLength, '\0'));
        baJOSE.append(signature.mid(pos, rLength));
        pos += rLength;
    }

    if (signature[pos] != (char)0x2) {
        m_strLastError = "tag int missing";
        return QByteArray();
    }

    int sLength = signature[++pos];

    if (maxParamLength < sLength) {
        m_strLastError = "param to short";
        return QByteArray();
    }

    pos++;

    if (sLength > paramBytes) {
        pos += sLength - paramBytes;
        baJOSE.append(signature.mid(pos, paramBytes));
        pos += paramBytes;
    } else {
        baJOSE.append(QByteArray(paramBytes - sLength, '\0'));
        baJOSE.append(signature.mid(pos, sLength));
        pos += sLength;
    }

    return baJOSE;
}

QByteArray QJWT::joseToDer(QByteArray& signature, QCryptographicHash::Algorithm method)
{
    int paramBytes;

    switch (method) {
    case QCryptographicHash::Sha256:
        paramBytes = 32;
        break;
    case QCryptographicHash::Sha384:
        paramBytes = 48;
        break;
    case QCryptographicHash::Sha512:
        paramBytes = 64;
        break;
    default:
        return QByteArray("hash algo not implemented");
        break;
    }

    if (signature.length() > paramBytes * 2) { // sig-len must be equal to paramBytes*2?
        m_strLastError = "signature is bigger than 2 hashes concatenated together";
        return QByteArray();
    }

    QByteArray r = signature.left(paramBytes);
    while (r.startsWith('\0')) {
        r.remove(0, 1);
    }
    if ((quint8)r[0] >= 0x80) {
        r.insert(0, '\0');
    }

    QByteArray s = signature.right(paramBytes);
    while (s.startsWith('\0')) {
        s.remove(0, 1);
    }
    if ((quint8)s[0] >= 0x80) {
        s.insert(0, '\0');
    }

    int seqLength = 2 + r.length() + 2 + s.length();

    QByteArray baDER;
    int pos = 0;
    baDER[pos] = (char)0x30;
    if (seqLength >= 0x80) {
        baDER[++pos] = (char)0x81;
    }
    baDER[++pos] = (char)seqLength;

    baDER[++pos] = (char)0x02;
    baDER[++pos] = (char)r.length();
    pos++;
    baDER.append(r);

    pos += r.length();

    baDER[pos] = (char)0x02;
    baDER[++pos] = (char)s.length();
    pos++;
    baDER.append(s);

    return baDER;
}
#endif

QStringList QJWT::supportedAlgorithms()
{
    QStringList algs;
    algs << "HS256"
         << "HS384"
         << "HS512";
#ifndef NO_OPENSSL
    algs << "RS256"
         << "RS384"
         << "RS512"
         << "ES256"
         << "ES384"
         << "ES512";
#endif
    return algs;
}

QString QJWT::sign(const QJsonDocument& payload, QString secret, QVariantMap options)
{
    QJWT jwt(payload, std::move(secret), std::move(options));
    if (!jwt.lastError().isEmpty())
        return jwt.lastError();
    return jwt.token();
}
