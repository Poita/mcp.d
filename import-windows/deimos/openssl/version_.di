module deimos.openssl.version_;

// Minimum OpenSSL 3.0 binding version for Windows, where deimos/openssl's
// preGenerateCommands (posix-only) cannot auto-detect the installed version.
// We require OpenSSL >= 3.0, so "3.0.3" is the correct minimum.
package enum OpenSSLTextVersion = "3.0.3";
