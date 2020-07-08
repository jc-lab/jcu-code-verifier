/**
 * @file	code_verifier.cc
 * @author	Joseph Lee <development@jc-lab.net>
 * @date	2020/07/07
 * @copyright Copyright (C) 2020 jc-lab. All rights reserved.
 */

#include <jcu_code_verifier/code_verifier.h>
#include <jcu_code_verifier/provider.h>

namespace jcu {
namespace code_verifier {

class CodeVerifierImpl : public CodeVerifier {
 private:
  std::list< std::shared_ptr<Provider> > providers_;

 public:
  CodeVerifierImpl(std::list< std::shared_ptr<Provider> > providers) {
    providers_ = std::move(providers);
  }

  bool verify(const file::Path &file, VerifyContext* ctx) const override {
    VerifyStatus status = VERIFY_PASS;
    for(auto it = providers_.cbegin(); (status == VERIFY_PASS) && (it != providers_.cend()); it++) {
      const Provider* p = it->get();
      VerifyResult result = p->verify(file, ctx);
      status = result.verified;
    }
    return status == VERIFY_OK;
  }

  bool verifyEx(std::list<VerifyResultEx> &out, const file::Path &file, VerifyContext *ctx) const override {
    VerifyStatus status = VERIFY_PASS;
    for (auto it = providers_.cbegin(); it != providers_.cend(); it++) {
      const Provider* p = it->get();
      VerifyResult result = p->verify(file, ctx);
      out.emplace_back(VerifyResultEx { result.verified, result.sys_error, p });
      if (status == VERIFY_PASS) {
        status = result.verified;
      }
    }
    return status == VERIFY_OK;
  }
};

CodeVerifier * CodeVerifier::create(std::list<std::shared_ptr<Provider> > providers) {
  return new CodeVerifierImpl(providers);
}

CodeVerifier* CodeVerifier::systemDefault() {
  static std::unique_ptr<CodeVerifier> instance(create({ systemDefaultProvider() }));
  return instance.get();
}

} // namespace code_verifier
} // namespace jcu
