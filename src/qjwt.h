#ifndef QJWT_H
#define QJWT_H

#include <QObject>
#include <QMessageAuthenticationCode>
#include <QJsonDocument>
#include <QJsonObject>
#include <QVariantMap>

#ifndef NO_OPENSSL
#include <openssl/ssl.h>
#include <openssl/ec.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif  // !OPENSSL_NO_ENGINE
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#endif

class QJWT
{

public:

    /*!
    \brief Constructor.
    \return A new instance of QJWT.

    Creates a default QJWT instance with *HS256 algorithm*, empty *payload*
    and empty *secret*.
    */
    QJWT();
    QJWT(QString token, QString secret, QVariantMap options = QVariantMap());
    QJWT(QJsonDocument payload, QString secret, QVariantMap options = QVariantMap());

    /*!
    \brief Returns the JWT *header* as a QJsonDocument.
    \return JWT *header* as a QJsonDocument.
    */
    QJsonDocument header();

    /*!
    \brief Sets the JWT *header* from a QJsonDocument.
    \param header JWT *header* as a QJsonDocument.
    \return true if the header was set, false if the header was not set.

    This method checks for a valid header format and returns false if the header is invalid.
    */
    bool setHeader(QJsonDocument header);

    /*!
    \brief Returns the JWT *payload* as a QJsonDocument.
    \return JWT *payload* as a QJsonDocument.
    */
    QJsonDocument getPayload();

    /*!
    \brief Sets the JWT *payload* from a QJsonDocument.
    \param payload JWT *payload* as a QJsonDocument.
    \return true if the payload was set, false if the payload was not set.

    This method checks for a valid payload format and returns false if the payload is invalid.
    */
    bool setPayload(QJsonDocument payload);

    /*!
    \brief Returns the JWT *secret* as a QString.
    \return JWT *secret* as a QString.
    */
    QString secret();

    /*!
    \brief Sets the JWT *secret* from a QString.
    \param secret JWT *secret* as a QString.
    \return true if the secret was set, false if the secret was not set.

    This method checks for a valid secret format and returns false if the secret is invalid.
    */
    bool setSecret(QString secret);

    /*!
    \brief Returns the JWT *algorithm* as a QString.
    \return JWT *algorithm* as a QString.
    */
    QString algorithm();

    /*!
    \brief Sets the JWT *algorithm* from a QString.
    \param algorithm JWT *algorithm* as a QString.
    \return true if the algorithm was set, false if the algorithm was not set.

    This method checks for a valid supported algorithm. Valid values are:
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384" and "ES512".

    \sa QJWT::supportedAlgorithms().
    */
    bool setAlgorithm(QString algorithm);

    /*!
    \brief Returns the complete JWT as a QString.
    \return Complete JWT as a QString.

    The token has the form:
    ```
    xxxxx.yyyyy.zzzzz
    ```

    where:

    - *xxxxx* is the *header* enconded in base64.
    - *yyyyy* is the *payload* enconded in base64.
    - *zzzzz* is the *signature* enconded in base64.
    */
    QString token();

    /*!
    \brief Sets the complete JWT as a QString.
    \param token Complete JWT as a QString.
    \return true if the complete JWT was set, false if not set.

    This method checks for a valid JWT format. It overwrites the *header*,
    *payload* , *signature* and *algorithm*. It does **not** overwrite the secret.

    \sa QJWT::token().
    */
    bool setToken(QString token);

    /*!
    \brief Checks validity of current JWT with respect to secret.
    \return true if the JWT is valid with respect to secret, else false.

    Uses the current *secret* to calculate a temporary *signature* and compares it to the
    current signature to check if they are the same. If they are, true is returned, if not then
    false is returned.
    */
    bool isValid();

    /*!
    \brief Returns a list of the supported algorithms.
    \return List of supported algorithms as a QStringList.
    */
    static QStringList supportedAlgorithms();

    /*!
    \brief Creates a token and signs it
    \param payload The payload that will be contained in the token
    \param secret Either secret or private key to sign the token with
    \param options Options for creation and signing the token
    \return Token as string

    This method creates and signs a JSON Web Token.

    The options can be used to add claims to the payload and change the algorithm.
    The secret can be a shared secret (for HMAC based algorithms) or a private key in PEM format.
    The options can contain the following keys and values:
    - alg: (string) The algorithm to sign the token with, see supportedAlgorithms() or README
    - any other key: will be added as claim to the token payload
    */
    static QString sign(QJsonDocument payload, QString secret, QVariantMap options); // returns token or empty

    /*!
    \brief Verifies a token and returns the payload
    \param token The JSON Web Token
    \param secret Either secret or private key to sign the token with
    \param options Options for creation and verifying the token
    \return Payload as QJsonDocument

    This method verifies a JSON Web Token and returns its payload.

    The options can be used to check certain claims and/or allow only specific algorithms.
    The secret can be a shared secret (for HMAC based algorithms) or a public key in PEM format.
    The options can contain the following keys and values:
    - alg: (string) The algorithm to sign the token with, see supportedAlgorithms() or README
    - any other key: will be added as claim to the token payload
    */
    static QJsonDocument verify(QString token, QString secret, QVariantMap options = QVariantMap()); // returns payload or {error: 'bla'}

    /*!
    \brief Sets the complete JWT as a QString.
    \param token Complete JWT as a QString.
    \return true if the complete JWT was set, false if not set.

    This method checks for a valid JWT format. It overwrites the *header*,
    *payload* , *signature* and *algorithm*. It does **not** overwrite the secret.

    \sa QJWT::token().
    */
    QJsonDocument payload();

    /*!
    \brief Sets the complete JWT as a QString.
    \param token Complete JWT as a QString.
    \return true if the complete JWT was set, false if not set.

    This method checks for a valid JWT format. It overwrites the *header*,
    *payload* , *signature* and *algorithm*. It does **not** overwrite the secret.

    \sa QJWT::token().
    */
    QString lastError();

private:
    QByteArray m_baHeader;
    QByteArray m_baPayload;
    QByteArray m_baSignature;
    QByteArray m_baSecret;
    QByteArray m_baAlgorithm;
    QVariantMap m_vmOptions;
    QString m_strLastError;

#ifndef NO_OPENSSL
    QJsonDocument verifySignature(QString token);
    QString signToken(void);
    void init_SSL(void);
    QByteArray getAsymmetricSignature(const QByteArray &message, const QByteArray &key, QCryptographicHash::Algorithm method);
    bool verifyAsymmetricSignature(const QByteArray &message, const QByteArray &signature, const QByteArray &key, QCryptographicHash::Algorithm method);
    QByteArray derToJose(QByteArray &signature, QCryptographicHash::Algorithm method);
    QByteArray joseToDer(QByteArray &signature, QCryptographicHash::Algorithm method);
#endif
};

#endif // QJWT_H
