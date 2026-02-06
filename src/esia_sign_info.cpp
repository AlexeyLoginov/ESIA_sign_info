/*
 ============================================================================
 Name:        esia_sign_info.cpp
 Author:      Aleksej Loginov
 E-mail:      lav.loginov@gmail.com
 Created:     06/02/2026
 Version:     1.0.0
 License:     MIT
 Description: Получение данных сертификата из параметра ЕСИА <client_secret> 
 ============================================================================
*/

#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <map>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// Определяем OID для временных меток
#define szOID_RSA_signingTime "1.2.840.113549.1.9.5"

// Функция для преобразования base64url в обычный base64
std::string Base64UrlToBase64(const std::string& base64url) {
    std::string base64 = base64url;

    // Заменяем URL-safe символы обратно
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');

    // Добавляем padding если необходимо
    size_t padding = base64.length() % 4;
    if (padding == 2) {
        base64 += "==";
    }
    else if (padding == 3) {
        base64 += "=";
    }

    return base64;
}

// Функция для декодирования base64 строки в бинарные данные
std::vector<BYTE> Base64Decode(const std::string& base64) {
    DWORD binarySize = 0;
    std::vector<BYTE> binaryData;

    if (!CryptStringToBinaryA(base64.c_str(), base64.length(),
        CRYPT_STRING_BASE64,
        nullptr, &binarySize, nullptr, nullptr)) {
        throw std::runtime_error("Cannot get binary size from base64");
    }

    binaryData.resize(binarySize);
    if (!CryptStringToBinaryA(base64.c_str(), base64.length(),
        CRYPT_STRING_BASE64,
        binaryData.data(), &binarySize, nullptr, nullptr)) {
        throw std::runtime_error("Cannot decode base64");
    }

    return binaryData;
}

// Функция для преобразования бинарных данных в hex строку
std::string BytesToHex(const std::vector<BYTE>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (BYTE b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Функция для преобразования времени FILETIME в строку
std::string FileTimeToString(const FILETIME& ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) {
        return "Not specified";
    }

    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) {
        return "Invalid time";
    }

    char buffer[100];
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

// Функция для получения имени алгоритма по OID
std::string GetAlgorithmName(const char* pszObjId) {
    if (!pszObjId) return "Unknown";

    std::map<std::string, std::string> algorithms;
    algorithms["1.2.643.7.1.1.1.1"] = "GOST R 34.10-2012 (256 bit)";
    algorithms["1.2.643.7.1.1.1.2"] = "GOST R 34.10-2012 (512 bit)";
    algorithms["1.2.643.2.2.3"] = "GOST R 34.10-2001";
    algorithms["1.2.643.7.1.1.2.2"] = "GOST R 34.11-2012 (256 bit)";
    algorithms["1.2.643.7.1.1.2.3"] = "GOST R 34.11-2012 (512 bit)";
    algorithms["1.2.643.2.2.9"] = "GOST R 34.11-94";
    algorithms["1.2.840.113549.1.1.1"] = "RSA";
    algorithms["1.2.840.113549.1.1.11"] = "SHA256 with RSA";
    algorithms["1.3.14.3.2.26"] = "SHA1";
    algorithms["2.16.840.1.101.3.4.2.1"] = "SHA256";

    std::map<std::string, std::string>::iterator it = algorithms.find(pszObjId);
    if (it != algorithms.end()) {
        return it->second;
    }
    return std::string(pszObjId);
}

// Функция для вывода информации о сертификате
void PrintCertificateInfo(PCCERT_CONTEXT pCertContext, int index) {
    std::cout << "\n=== Certificate #" << index << " ===" << std::endl;

    // Серийный номер
    CERT_INFO* pCertInfo = pCertContext->pCertInfo;
    std::vector<BYTE> serialNumber(
        pCertInfo->SerialNumber.pbData,
        pCertInfo->SerialNumber.pbData + pCertInfo->SerialNumber.cbData
    );
    std::reverse(serialNumber.begin(), serialNumber.end()); // Конвертируем в big-endian
    std::cout << "Serial Number: " << BytesToHex(serialNumber) << std::endl;

    // Издатель
    DWORD issuerSize = CertNameToStrA(pCertContext->dwCertEncodingType,
        &pCertInfo->Issuer,
        CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        nullptr, 0);
    std::string issuer(issuerSize, '\0');
    CertNameToStrA(pCertContext->dwCertEncodingType,
        &pCertInfo->Issuer,
        CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        &issuer[0], issuerSize);
    issuer.resize(issuerSize - 1); // Удаляем терминатор
    std::cout << "Issuer: " << issuer << std::endl;

    // Субъект
    DWORD subjectSize = CertNameToStrA(pCertContext->dwCertEncodingType,
        &pCertInfo->Subject,
        CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        nullptr, 0);
    std::string subject(subjectSize, '\0');
    CertNameToStrA(pCertContext->dwCertEncodingType,
        &pCertInfo->Subject,
        CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        &subject[0], subjectSize);
    subject.resize(subjectSize - 1);
    std::cout << "Subject: " << subject << std::endl;

    // Срок действия
    std::cout << "Valid From: " << FileTimeToString(pCertInfo->NotBefore) << std::endl;
    std::cout << "Valid To: " << FileTimeToString(pCertInfo->NotAfter) << std::endl;

    // Алгоритм подписи
    std::cout << "Signature Algorithm: " << GetAlgorithmName(pCertInfo->SignatureAlgorithm.pszObjId) << std::endl;

    // Алгоритм открытого ключа
    std::cout << "Public Key Algorithm: " << GetAlgorithmName(pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId) << std::endl;
}

// Функция для вывода справки
void PrintHelp() {
    std::cout << "ConsoleCryptoSign_info - Electronic signature analysis tool" << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  ConsoleCryptoSign_info <signature_base64url>" << std::endl;
    std::cout << "  ConsoleCryptoSign_info /?  (help)" << std::endl;
    std::cout << std::endl;
    std::cout << "Example:" << std::endl;
    std::cout << "  ConsoleCryptoSign_info \"MIINlAYJKo...\"" << std::endl;
}

int main(int argc, char* argv[]) {
    // Показать справку если нет параметров или запрошена помощь
    if (argc != 2 || std::string(argv[1]) == "/?" || std::string(argv[1]) == "-help") {
        PrintHelp();
        return 0;
    }

    std::string signatureBase64Url = argv[1];

    try {
        // Преобразуем base64url в обычный base64
        std::string signatureBase64 = Base64UrlToBase64(signatureBase64Url);

        // Декодируем base64 в бинарные данные
        std::vector<BYTE> signatureData = Base64Decode(signatureBase64);

        std::cout << "=== PKCS#7 Electronic Signature Analysis ===" << std::endl;
        std::cout << "Signature size: " << signatureData.size() << " bytes" << std::endl;

        // Парсим структуру PKCS#7
        HCRYPTMSG hMsg = CryptMsgOpenToDecode(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            0,
            NULL,
            NULL,
            NULL
        );

        if (!hMsg) {
            throw std::runtime_error("Cannot open message for decoding");
        }

        // Добавляем данные в сообщение
        if (!CryptMsgUpdate(hMsg, signatureData.data(), signatureData.size(), TRUE)) {
            CryptMsgClose(hMsg);
            throw std::runtime_error("Cannot update message with signature data");
        }

        // Получаем тип сообщения
        DWORD msgType = 0;
        DWORD msgTypeSize = sizeof(msgType);
        if (!CryptMsgGetParam(hMsg, CMSG_TYPE_PARAM, 0, &msgType, &msgTypeSize)) {
            CryptMsgClose(hMsg);
            throw std::runtime_error("Cannot get message type");
        }

        std::cout << "Message type: ";
        switch (msgType) {
        case CMSG_SIGNED:
            std::cout << "PKCS#7 Signed Data";
            break;
        case CMSG_ENVELOPED:
            std::cout << "PKCS#7 Enveloped Data";
            break;
        case CMSG_SIGNED_AND_ENVELOPED:
            std::cout << "PKCS#7 Signed and Enveloped Data";
            break;
        case CMSG_HASHED:
            std::cout << "PKCS#7 Hashed Data";
            break;
        default:
            std::cout << "Unknown (" << msgType << ")";
            break;
        }
        std::cout << std::endl;

        // Получаем информацию о подписи
        DWORD signerCount = 0;
        DWORD signerCountSize = sizeof(signerCount);
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, &signerCount, &signerCountSize)) {
            std::cout << "Number of signers: " << signerCount << std::endl;

            for (DWORD i = 0; i < signerCount; i++) {
                std::cout << "\n--- Signer #" << (i + 1) << " ---" << std::endl;

                // Получаем информацию о подписанте
                DWORD signerInfoSize = 0;
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, NULL, &signerInfoSize)) {
                    continue;
                }

                std::vector<BYTE> signerInfoData(signerInfoSize);
                if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, signerInfoData.data(), &signerInfoSize)) {
                    continue;
                }

                PCMSG_SIGNER_INFO pSignerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(signerInfoData.data());

                // Алгоритм подписи
                std::cout << "Signature Algorithm: " << GetAlgorithmName(pSignerInfo->HashAlgorithm.pszObjId) << std::endl;

                // Алгоритм шифрования
                std::cout << "Encryption Algorithm: " << GetAlgorithmName(pSignerInfo->HashEncryptionAlgorithm.pszObjId) << std::endl;

                // Серийный номер сертификата подписанта
                if (pSignerInfo->Issuer.cbData > 0 && pSignerInfo->SerialNumber.cbData > 0) {
                    std::vector<BYTE> issuerSerial(
                        pSignerInfo->SerialNumber.pbData,
                        pSignerInfo->SerialNumber.pbData + pSignerInfo->SerialNumber.cbData
                    );
                    std::reverse(issuerSerial.begin(), issuerSerial.end());
                    std::cout << "Signer Serial Number: " << BytesToHex(issuerSerial) << std::endl;
                }

                // Время подписания (если есть)
                for (DWORD j = 0; j < pSignerInfo->AuthAttrs.cAttr; j++) {
                    if (strcmp(pSignerInfo->AuthAttrs.rgAttr[j].pszObjId, szOID_RSA_signingTime) == 0) {
                        FILETIME signingTime;
                        DWORD size = sizeof(signingTime);
                        if (CryptDecodeObject(X509_ASN_ENCODING, szOID_RSA_signingTime,
                            pSignerInfo->AuthAttrs.rgAttr[j].rgValue[0].pbData,
                            pSignerInfo->AuthAttrs.rgAttr[j].rgValue[0].cbData,
                            0, &signingTime, &size)) {
                            std::cout << "Signing Time: " << FileTimeToString(signingTime) << std::endl;
                        }
                        break;
                    }
                }
            }
        }

        // Получаем сертификаты из подписи
        DWORD certCount = 0;
        DWORD certCountSize = sizeof(certCount);
        if (CryptMsgGetParam(hMsg, CMSG_CERT_COUNT_PARAM, 0, &certCount, &certCountSize)) {
            std::cout << "\nNumber of certificates in signature: " << certCount << std::endl;

            // Получаем хранилище сертификатов из сообщения
            HCERTSTORE hStore = CertOpenStore(
                CERT_STORE_PROV_MSG,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                NULL,
                0,
                hMsg
            );

            if (hStore) {
                PCCERT_CONTEXT pCertContext = NULL;
                int certIndex = 1;
                while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != NULL) {
                    PrintCertificateInfo(pCertContext, certIndex++);
                }

                CertCloseStore(hStore, 0);
            }
        }

        CryptMsgClose(hMsg);

        std::cout << "\n=== Analysis completed ===" << std::endl;

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}