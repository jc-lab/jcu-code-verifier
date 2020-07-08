/**
 * @file	constants.h
 * @author	Joseph Lee <development@jc-lab.net>
 * @date	2020/07/07
 * @copyright Copyright (C) 2020 jc-lab.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCU_CODE_VERIFIER_CONSTANTS_H__
#define __JCU_CODE_VERIFIER_CONSTANTS_H__

namespace jcu {
namespace code_verifier {

enum VerifyStatus {
  /**
   * verify with next provider
   */
  VERIFY_PASS = 0,

  /**
   * success
   */
  VERIFY_OK = 1,

  /**
   * failure
   */
  VERIFY_FAIL = 2,
};

struct VerifyResult {
  VerifyStatus verified;
  int sys_error;

  VerifyResult(VerifyStatus _verified, int _sys_error) : verified(_verified), sys_error(_sys_error) {}
};

} // namespace code_verifier
} // namespace jcu

#endif //__JCU_CODE_VERIFIER_CODE_VERIFIER_H__
