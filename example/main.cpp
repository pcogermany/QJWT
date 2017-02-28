#include <QCoreApplication>
#include <QFile>
#include <QDebug>

#include "qjwt.h"

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
    //QByteArray batoken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbnJlZGUiOiJIZXJyIiwiRU1haWwiOiJ1c2VyQGV4YW1wbGUub3JnIiwiTmFtZSI6IkVyIiwiVXNlcm5hbWUiOiJ1c2VyIiwiVm9ybmFtZSI6IlVzIiwiZXhwIjoxNDg3NjEwMDQ4LCJpYXQiOjE0ODc2MDk3NDgsImlkIjoxNSwiaWRNYW5kYW50IjoxLCJwZXJtaXNzaW9ucyI6eyIxIjp7Im93bmVyOnJlYWQiOiIxIiwib3duZXI6d3JpdGUiOiIxIn19fQ.Df-VfZIX9vrE2hw4CTZRGH_cjEG9JsoQwCykyyke8c6MCEuMEl2rO0Q8K0mqLlK9BbXbSpdJlXW-smWBZlS_0w";
    //qDebug() << "verify 2" << QJWT::verify(batoken, pubKey, opts);

    /*QByteArray ba=QByteArray::fromHex("0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5");
    QByteArray baDER = QJWT::joseToDer(ba, QCryptographicHash::Sha256);
    qDebug() << "JOSE" << ba.toHex();
    qDebug() << "DER" << baDER.toHex();
    qDebug() << "example" << QJWT::verifyAsymmetricSignature("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbnJlZGUiOiJIZXJyIiwiRU1haWwiOiJ1c2VyQGV4YW1wbGUub3JnIiwiTmFtZSI6IkVyIiwiVXNlcm5hbWUiOiJ1c2VyIiwiVm9ybmFtZSI6IlVzIiwiZXhwIjoxNDg3NjEwMDQ4LCJpYXQiOjE0ODc2MDk3NDgsImlkIjoxNSwiaWRNYW5kYW50IjoxLCJwZXJtaXNzaW9ucyI6eyIxIjp7Im93bmVyOnJlYWQiOiIxIiwib3duZXI6d3JpdGUiOiIxIn19fQ", QByteArray::fromHex("304502200dff957d9217f6fac4da1c38093651187fdc8c41bd26ca10c02ca4cb291ef1ce0221008c084b8c125dab3b443c2b49aa2e52bd05b5db4a97499575beb265816654bfd3"), pubKey, QCryptographicHash::Sha256);*/

    /*QByteArray jose = QByteArray::fromBase64("cUkW2WG2Zy4gsUR1x25NxWXFtyyGHCPMKF1oauZIAWSKN2JDJJjvWRFiP5kwRXuUQX64njnNQ3S0PRYIYc1TXg");
    qDebug() << jose.toHex();
    qDebug() << QJWT::joseToDer(jose, QCryptographicHash::Sha256).toHex();*/

    return a.exec();
}
