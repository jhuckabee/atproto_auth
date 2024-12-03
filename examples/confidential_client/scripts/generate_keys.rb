# frozen_string_literal: true

require "jose"

# Generate a new EC key using P-256 curve
keypair = JOSE::JWK.generate_key([:ec, "P-256"])

# Get the key as a hash (need to convert from JOSE::Map)
jwk = keypair.to_map.to_h

# Pretty print the JWK to stdout
require "json"
puts JSON.pretty_generate({
                            keys: [jwk]
                          })
