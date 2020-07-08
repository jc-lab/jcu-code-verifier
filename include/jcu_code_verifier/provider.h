/**
 * @file	provider.h
 * @author	Joseph Lee <development@jc-lab.net>
 * @date	2020/07/07
 * @copyright Copyright (C) 2020 jc-lab.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCU_CODE_VERIFIER_PROVIDER_H__
#define __JCU_CODE_VERIFIER_PROVIDER_H__

#include "constants.h"
#include "verify_context.h"

#include <jcu-file/path.h>

namespace jcu {
namespace code_verifier {

class Provider {
 public:
  virtual std::string name() const = 0;
  virtual VerifyResult verify(const jcu::file::Path &file, VerifyContext* ctx) const = 0;
};

} // namespace code_verifier
} // namespace jcu

#endif //__JCU_CODE_VERIFIER_CODE_VERIFIER_H__
