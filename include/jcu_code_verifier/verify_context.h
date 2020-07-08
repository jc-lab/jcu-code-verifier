/**
 * @file	verify_context.h
 * @author	Joseph Lee <development@jc-lab.net>
 * @date	2020/07/07
 * @copyright Copyright (C) 2020 jc-lab.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCU_CODE_VERIFIER_VERIFY_CONTEXT_H__
#define __JCU_CODE_VERIFIER_VERIFY_CONTEXT_H__

#include <string>

namespace jcu {
namespace code_verifier {

class VerifyContext {
 public:
  virtual ~VerifyContext() {}

  virtual void setCertificateInfo(
      const std::string& serial_number,
      const std::string& issuer_name,
      const std::string& subject_name
  ) {}
};

} // namespace code_verifier
} // namespace jcu

#endif //__JCU_CODE_VERIFIER_VERIFY_CONTEXT_H__
