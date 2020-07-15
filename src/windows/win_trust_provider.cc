/**
 * @file	win_trust_provider.cc
 * @author	Joseph Lee <development@jc-lab.net>
 * @date	2020/07/07
 * @copyright Copyright (C) 2020 jc-lab. All rights reserved.
 */

#include <memory>
#include <jcu_code_verifier/provider.h>

#ifdef _WIN32

#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

namespace jcu {
namespace code_verifier {

class WinTrustProvider : public Provider {
 public:
  static std::basic_string<WCHAR> toWstr(const file::Path &file) {
    std::basic_string<WCHAR> out;
    auto sfile = file.getSystemString();
    if (sizeof(sfile.c_str()[0]) == 1) {
      int nLen = MultiByteToWideChar(CP_ACP, 0, (const char*)sfile.c_str(), sfile.length(), nullptr, 0);
      out.resize(nLen);
      if (nLen > 0) {
        MultiByteToWideChar(CP_ACP, 0, (const char*)sfile.c_str(), sfile.length(), &out[0], nLen);
      }
    } else {
      out.insert(out.end(), sfile.cbegin(), sfile.cend());
    }
    return out;
  }

  class ManagedFileHandle {
   public:
    HANDLE handle;

    ManagedFileHandle() {
      handle = nullptr;
    }

    int open(const std::basic_string<WCHAR> &file) {
      handle = ::CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
      if (!handle || handle == INVALID_HANDLE_VALUE) {
        return (int) ::GetLastError();
      }
      return 0;
    }

    ~ManagedFileHandle() {
      if (this->handle && (this->handle != INVALID_HANDLE_VALUE)) {
        ::CloseHandle(this->handle);
        this->handle = nullptr;
      }
    }

    HANDLE get() const {
      return this->handle;
    }
  };

  std::string name() const override {
    return "WinTrustProvider";
  }

  bool storeCertificateInfo(VerifyContext *ctx, PCCERT_CONTEXT pCertContext) const {
    static const char HEX_CHARS[] = "0123456789abcdef";

    bool fReturn = false;
    LPTSTR szName = nullptr;
    DWORD dwData;

    std::basic_string<TCHAR> temp_str;
    std::string serial_number;
    std::string issuer_name;
    std::string subject_name;

    do {
      dwData = pCertContext->pCertInfo->SerialNumber.cbData;
      for (DWORD n = 0; n < dwData; n++) {
        unsigned char a = pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)];
        serial_number.append(&HEX_CHARS[(a >> 4) & 0xf], 1);
        serial_number.append(&HEX_CHARS[(a >> 0) & 0xf], 1);
      }

      // Get Issuer name size.
      if (!(dwData = CertGetNameString(pCertContext,
                                       CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                       CERT_NAME_ISSUER_FLAG,
                                       nullptr,
                                       nullptr,
                                       0))) {
        _tprintf(_T("CertGetNameString failed.\n"));
        break;
      }

      // Allocate memory for Issuer name.
      szName = (LPTSTR) LocalAlloc(LPTR, dwData * sizeof(TCHAR));
      if (!szName) {
        _tprintf(_T("Unable to allocate memory for issuer name.\n"));
        break;
      }

      // Get Issuer name.
      if (!(CertGetNameString(pCertContext,
                              CERT_NAME_SIMPLE_DISPLAY_TYPE,
                              CERT_NAME_ISSUER_FLAG,
                              nullptr,
                              szName,
                              dwData))) {
        _tprintf(_T("CertGetNameString failed.\n"));
        break;
      }

      temp_str = szName;
      issuer_name = std::string(temp_str.begin(), temp_str.end());
      LocalFree(szName);
      szName = nullptr;

      // Get Subject name size.
      if (!(dwData = CertGetNameString(pCertContext,
                                       CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                       0,
                                       nullptr,
                                       nullptr,
                                       0))) {
        _tprintf(_T("CertGetNameString failed.\n"));
        break;
      }

      // Allocate memory for subject name.
      szName = (LPTSTR) LocalAlloc(LPTR, dwData * sizeof(TCHAR));
      if (!szName) {
        _tprintf(_T("Unable to allocate memory for subject name.\n"));
        break;
      }

      // Get subject name.
      if (!(CertGetNameString(pCertContext,
                              CERT_NAME_SIMPLE_DISPLAY_TYPE,
                              0,
                              nullptr,
                              szName,
                              dwData))) {
        _tprintf(_T("CertGetNameString failed.\n"));
        break;
      }

      temp_str = szName;
      subject_name = std::string(temp_str.begin(), temp_str.end());
      LocalFree(szName);
      szName = nullptr;

      ctx->setCertificateInfo(
          serial_number,
          issuer_name,
          subject_name
      );

      fReturn = true;
    } while (0);

    if (szName != nullptr) LocalFree(szName);

    return fReturn;
  }

  VerifyResult verify(const file::Path &file, VerifyContext *ctx) const override {
    auto sfile = toWstr(file);
    ManagedFileHandle file_handle;
    int rc;

    rc = file_handle.open(sfile);
    if (rc) {
      return {VERIFY_PASS, rc};
    }

    VerifyStatus verify_status = VERIFY_PASS;
    LONG trust_status;
    DWORD trust_detail = 0;

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = nullptr;
    FileData.hFile = file_handle.get();
    FileData.pgKnownSubject = nullptr;

    /*
    wvt_policy_guid specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    GUID wvt_policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA win_trust_data;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&win_trust_data, 0, sizeof(win_trust_data));

    win_trust_data.cbStruct = sizeof(win_trust_data);

    // Use default code signing EKU.
    win_trust_data.pPolicyCallbackData = nullptr;

    // No data to pass to SIP.
    win_trust_data.pSIPClientData = nullptr;

    // Disable WVT UI.
    win_trust_data.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    win_trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    win_trust_data.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    win_trust_data.hWVTStateData = nullptr;

    // Not used.
    win_trust_data.pwszURLReference = nullptr;

    // This is not applicable if there is no UI because it changes
    // the UI to accommodate running applications instead of
    // installing applications.
    win_trust_data.dwUIContext = 0;

    // Set pFile.
    win_trust_data.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID
    // and Wintrust_Data.
    trust_status = WinVerifyTrust(
        nullptr,
        &wvt_policy_guid,
        &win_trust_data);

    switch (trust_status) {
      case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
        verify_status = VERIFY_OK;
        break;

      case TRUST_E_NOSIGNATURE:trust_detail = ::GetLastError();
        // The file was not signed or had a signature
        // that was not valid.

        // Get the reason for no signature.
        if (TRUST_E_NOSIGNATURE == trust_detail ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == trust_detail ||
            TRUST_E_PROVIDER_UNKNOWN == trust_detail) {
          verify_status = VERIFY_PASS;
        } else {
          verify_status = VERIFY_FAIL;
        }

        break;

      case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher
        // is not allowed by the admin or user.
        verify_status = VERIFY_FAIL;
        break;

      case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        verify_status = VERIFY_FAIL;
        break;

      case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        verify_status = VERIFY_FAIL;
        break;

      default:verify_status = VERIFY_FAIL;
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(
        nullptr,
        &wvt_policy_guid,
        &win_trust_data);

    if (trust_status != TRUST_E_NOSIGNATURE && trust_detail != TRUST_E_NOSIGNATURE) {
      HCERTSTORE hStore = nullptr;
      HCRYPTMSG hMsg = nullptr;
      PCCERT_CONTEXT pCertContext = nullptr;
      BOOL fResult;
      DWORD dwEncoding, dwContentType, dwFormatType;
      PCMSG_SIGNER_INFO pSignerInfo = nullptr;
      DWORD dwSignerInfo;
      CERT_INFO cert_info;
      SYSTEMTIME st;

      do {
        // Get message handle and store handle from the signed file.
        fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                                   sfile.c_str(),
                                   CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                   CERT_QUERY_FORMAT_FLAG_BINARY,
                                   0,
                                   &dwEncoding,
                                   &dwContentType,
                                   &dwFormatType,
                                   &hStore,
                                   &hMsg,
                                   nullptr);

        if (!fResult) {
          _tprintf(_T("CryptQueryObject failed with %x\n"), GetLastError());
          break;
        }

        // Get signer information size.
        fResult = CryptMsgGetParam(hMsg,
                                   CMSG_SIGNER_INFO_PARAM,
                                   0,
                                   nullptr,
                                   &dwSignerInfo);
        if (!fResult) {
          _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
          break;
        }

        // Allocate memory for signer information.
        pSignerInfo = (PCMSG_SIGNER_INFO) LocalAlloc(LPTR, dwSignerInfo);
        if (!pSignerInfo) {
          _tprintf(_T("Unable to allocate memory for Signer Info.\n"));
          break;
        }

        // Get Signer Information.
        fResult = CryptMsgGetParam(hMsg,
                                   CMSG_SIGNER_INFO_PARAM,
                                   0,
                                   (PVOID) pSignerInfo,
                                   &dwSignerInfo);
        if (!fResult) {
          _tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
          break;
        }

        // Search for the signer certificate in the temporary
        // certificate store.
        cert_info.Issuer = pSignerInfo->Issuer;
        cert_info.SerialNumber = pSignerInfo->SerialNumber;

        pCertContext = CertFindCertificateInStore(hStore,
                                                  X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                  0,
                                                  CERT_FIND_SUBJECT_CERT,
                                                  (PVOID) &cert_info,
                                                  pCertContext);

        if (pCertContext && ctx) {
          storeCertificateInfo(ctx, pCertContext);
        }
      } while (0);

      if (pSignerInfo != nullptr) LocalFree(pSignerInfo);
      if (pCertContext != nullptr) CertFreeCertificateContext(pCertContext);
      if (hStore != nullptr) CertCloseStore(hStore, 0);
      if (hMsg != nullptr) CryptMsgClose(hMsg);
    }

    return {verify_status, rc};
  }
};

/**
 * get system default provider
 *
 * @return singletone shared object
 */
std::shared_ptr<Provider> systemDefaultProvider() {
  static std::shared_ptr<WinTrustProvider> instance(new WinTrustProvider());
  return instance;
}

} // namespace code_verifier
} // namespace jcu

#endif
