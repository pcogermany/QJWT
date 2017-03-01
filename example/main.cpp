#include <QCoreApplication>
#include <QFile>
#include <QDebug>

#include <qjwt.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QFile f("private.key");
    f.open(QFile::ReadOnly);
    QByteArray privKey = f.readAll();

    QFile fp("public.pem");
    fp.open(QFile::ReadOnly);
    QByteArray pubKey = fp.readAll();

    QJsonObject permissions_Owner1;
    permissions_Owner1["owner:read"] = "1";
    permissions_Owner1["owner:write"] = "1";

    QJsonObject owner1;
    owner1["1"] = permissions_Owner1;

    QJsonObject payload;
    payload["id"] = 15;
    payload["idMandant"] = 1;
    payload["Username"] = "user";
    payload["Anrede"] = "Herr";
    payload["Vorname"] = "Us";
    payload["Name"] = "Er";
    payload["EMail"] = "user@example.org";
    payload["permissions"] = owner1;
    payload["exp"] =  1487610048;
    payload["iat"] = 1487609748;

    QVariantMap options;
    options["alg"] = "ES256";

    qDebug() << "payload" << payload;

    QString token = QJWT::sign(QJsonDocument(payload), privKey, options);
    qDebug() << "sign" << token;
    QVariantMap opts;
    opts["ignoreExpiration"] = true;
    qDebug() << "verify" << QJWT::verify(token, pubKey, opts);

    return a.exec();
}
