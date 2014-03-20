#!/usr/bin/env ruby

require 'openssl'

KEY_LENGTH      = 4096  # Key size (in bits)
digest_function  = OpenSSL::Digest::SHA256.new # Predetermined signature digest function


# Generate RSA private/public key pairs for both parties...
keypair_snowden = OpenSSL::PKey::RSA.new(KEY_LENGTH)
keypair_mwrc    = OpenSSL::PKey::RSA.new(KEY_LENGTH)

# Public key export for exchange between parties...
pubkey_snowden  = OpenSSL::PKey::RSA.new(keypair_snowden.public_key.to_der)
pubkey_meetup   = OpenSSL::PKey::RSA.new(keypair_mwrc.public_key.to_der)

# Plain text messages...
message_to_snowden  = 'You are a patriot!'
message_to_meetup   = "Russia is really nice this time of year..."

# Generate digital signatures using private keys...
signature_meetup  = keypair_mwrc.sign(digest_function, message_to_snowden)
signature_snowden = keypair_snowden.sign(digest_function, message_to_meetup)

# Encrypt messages using the other party's public key...
encrypted_for_snowden = pubkey_snowden.public_encrypt(message_to_snowden) #from Meetup
encrypted_for_meetup  = pubkey_meetup.public_encrypt(message_to_meetup)   #from Snowden

# Decrypt messages using own private keys...
decrypted_snowden = keypair_snowden.private_decrypt(encrypted_for_snowden)
decrypted_meetup  = keypair_mwrc.private_decrypt(encrypted_for_meetup)


# Signature validation and console output...
if pubkey_meetup.verify(digest_function, signature_meetup, decrypted_snowden)
  puts "Edward Snowden received from @mwrc:"
  puts "\"#{message_to_snowden}\"\n\n"
end

if pubkey_snowden.verify(digest_function, signature_snowden, decrypted_meetup)
  puts "@mwrc received from Edward Snowden:"
  puts "\"#{message_to_meetup}\""
end
