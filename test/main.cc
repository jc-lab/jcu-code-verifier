#include <stdio.h>
#include <test-config.h>

#include <gtest/gtest.h>

#include <jcu_code_verifier/code_verifier.h>
#include <jcu_code_verifier/verify_context.h>

using namespace jcu::code_verifier;

namespace {

class MyVerifyContext : public VerifyContext {
 public:
  std::string serial_number;
  std::string issuer_name;
  std::string subject_name;

  ~MyVerifyContext() override {

  }
  void setCertificateInfo(const std::string &serial_number,
                          const std::string &issuer_name,
                          const std::string &subject_name) override {
    this->serial_number = serial_number;
    this->issuer_name = issuer_name;
    this->subject_name = subject_name;
  }
};

TEST(SystemProviderTest, NonSigned) {
  std::unique_ptr<VerifyContext> verify_context(new MyVerifyContext());
  CodeVerifier *code_verifier = CodeVerifier::systemDefault();
  bool result = code_verifier->verify(jcu::file::Path::newFromUtf8(TEST_FILES_DIR "\\non-signed.exe"), verify_context.get());
  EXPECT_FALSE(result);
}


TEST(SystemProviderTest, PythonSigned) {
  std::unique_ptr<MyVerifyContext> verify_context(new MyVerifyContext());
  CodeVerifier *code_verifier = CodeVerifier::systemDefault();
  bool result = code_verifier->verify(jcu::file::Path::newFromUtf8(TEST_FILES_DIR "\\py-signed.exe"), verify_context.get());
  EXPECT_TRUE(result);

  EXPECT_EQ(verify_context->serial_number, "033ed5eda065d1b8c91dfcf92a6c9bd8");
  EXPECT_EQ(verify_context->issuer_name, "DigiCert SHA2 Assured ID Code Signing CA");
  EXPECT_EQ(verify_context->subject_name, "Python Software Foundation");
}

} // namespace

