/**
 * @file	code_verifier.h
 * @author	Joseph Lee <development@jc-lab.net>
 * @date	2020/07/07
 * @copyright Copyright (C) 2020 jc-lab.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCU_CODE_VERIFIER_CODE_VERIFIER_H__
#define __JCU_CODE_VERIFIER_CODE_VERIFIER_H__

#include <memory>
#include <list>

#include <jcu-file/path.h>

#include "constants.h"

namespace jcu {
namespace code_verifier {

class Provider;
class VerifyContext;

struct VerifyResultEx : public VerifyResult {
  const Provider *provider;

  VerifyResultEx(VerifyStatus _verified, int _sys_error, const Provider *_provider)
  : VerifyResult(_verified, _sys_error), provider(_provider) {}
};

class CodeVerifier {
 public:
  /**
   * use system default provider
   *
   * @return singletone object pointer
   */
  static CodeVerifier* systemDefault();
  static CodeVerifier* create(std::list<std::shared_ptr<Provider>> providers);

  virtual bool verify(const jcu::file::Path& file, VerifyContext* ctx = nullptr) const = 0;
  virtual bool verifyEx(std::list<VerifyResultEx>& out, const jcu::file::Path& file, VerifyContext* ctx = nullptr) const = 0;
};

/**
 * get system default provider
 *
 * @return singletone shared object
 */
extern std::shared_ptr<Provider> systemDefaultProvider();

} // namespace code_verifier
} // namespace jcu

#endif //__JCU_CODE_VERIFIER_CODE_VERIFIER_H__
