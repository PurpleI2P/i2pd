#ifndef SIGNATURETYPECOMBOBOXFACTORY_H
#define SIGNATURETYPECOMBOBOXFACTORY_H

#include <QApplication>
#include <QComboBox>
#include <QWidget>
#include "Identity.h"

class SignatureTypeComboBoxFactory
{
    static const QVariant createUserData(const uint16_t sigType) {
        return QVariant::fromValue((uint)sigType);
    }

    static void addItem(QComboBox* signatureTypeCombobox, QString text, const uint16_t sigType) {
        const QVariant userData = createUserData(sigType);
        signatureTypeCombobox->addItem(text, userData);
    }

public:
    static const uint16_t getSigType(const QVariant& var) {
        return (uint16_t)var.toInt();
    }

    static void fillComboBox(QComboBox* signatureTypeCombobox, uint16_t selectedSigType) {
        /*
            <orignal> https://geti2p.net/spec/common-structures#certificate
            <orignal> все коды перечислены
            <Hypnosis> это таблица "The defined Signing Public Key types are:" ?
            <orignal> да

            see also: Identity.h line 55
        */
        int index=0;
        bool foundSelected=false;

        using namespace i2p::data;

        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "DSA_SHA1", 0), SIGNING_KEY_TYPE_DSA_SHA1); //0
        if(selectedSigType==SIGNING_KEY_TYPE_DSA_SHA1){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "ECDSA_SHA256_P256", 0), SIGNING_KEY_TYPE_ECDSA_SHA256_P256); //1
        if(selectedSigType==SIGNING_KEY_TYPE_ECDSA_SHA256_P256){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "ECDSA_SHA384_P384", 0), SIGNING_KEY_TYPE_ECDSA_SHA384_P384); //2
        if(selectedSigType==SIGNING_KEY_TYPE_ECDSA_SHA384_P384){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "ECDSA_SHA512_P521", 0), SIGNING_KEY_TYPE_ECDSA_SHA512_P521); //3
        if(selectedSigType==SIGNING_KEY_TYPE_ECDSA_SHA512_P521){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "RSA_SHA256_2048", 0), SIGNING_KEY_TYPE_RSA_SHA256_2048); //4
        if(selectedSigType==SIGNING_KEY_TYPE_RSA_SHA256_2048){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "RSA_SHA384_3072", 0), SIGNING_KEY_TYPE_RSA_SHA384_3072); //5
        if(selectedSigType==SIGNING_KEY_TYPE_RSA_SHA384_3072){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "RSA_SHA512_4096", 0), SIGNING_KEY_TYPE_RSA_SHA512_4096); //6
        if(selectedSigType==SIGNING_KEY_TYPE_RSA_SHA512_4096){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "EDDSA_SHA512_ED25519", 0), SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519); //7
        if(selectedSigType==SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "EDDSA_SHA512_ED25519PH", 0), SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519ph); //8
        if(selectedSigType==SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519ph){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        // the following signature type should never appear in netid=2
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256", 0), SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256); //9
        if(selectedSigType==SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "GOSTR3410_TC26_A_512_GOSTR3411_512", 0), SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512); //10
        if(selectedSigType==SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        // TODO: remove later
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256_TEST", 0), SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256_TEST); //65281
        if(selectedSigType==SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256_TEST){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        addItem(signatureTypeCombobox, QApplication::translate("signatureTypeCombobox", "GOSTR3410_TC26_A_512_GOSTR3411_512_TEST", 0), SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512_TEST); //65282
        if(selectedSigType==SIGNING_KEY_TYPE_GOSTR3410_TC26_A_512_GOSTR3411_512_TEST){signatureTypeCombobox->setCurrentIndex(index);foundSelected=true;}
        ++index;
        if(!foundSelected){
            addItem(signatureTypeCombobox, QString::number(selectedSigType), selectedSigType); //unknown sigtype
            signatureTypeCombobox->setCurrentIndex(index);
        }
    }

    static QComboBox* createSignatureTypeComboBox(QWidget* parent, uint16_t selectedSigType) {
        QComboBox* signatureTypeCombobox = new QComboBox(parent);
        fillComboBox(signatureTypeCombobox, selectedSigType);
        return signatureTypeCombobox;
    }
};

#endif // SIGNATURETYPECOMBOBOXFACTORY_H
