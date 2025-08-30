require 'securerandom'
# - Algorithm Implementation logic -
# We need 2 parties to be instantiated. Parties must agree on a base number and a modulus.
# They can be shared publicly.
# Then party 1 must come up with a secret number to use to generate a number.
# Party 2 will come up with another secret number to also generate the number
# then party 1 and 2 will share their secret numbers to the other.
# then they will use that number to generate another number.
# that final number would be the same for both parties.
# Now that the secret has been shared across the two parties, the final number can be used as a handshake / encryption key etc .


def mod_expo(base, exponent, modulus)
  result = 1
  base %= modulus
  while exponent > 0
    result = (result * base) % modulus if exponent.odd?
    base = (base * base) % modulus
    exponent >>= 1
  end
  result
end

# Abstract base class for DH parties
class PartyBase
  attr_reader :name, :modulus, :base, :secret, :public_key

  def initialize(name:, modulus:, base:)
    @name = name
    @modulus = modulus
    @base = base
    @secret = nil
    @public_key = nil
  end

  # Abstract hook: subclasses must choose a private secret in [2, p-2]
  def pick_secret
    raise NotImplementedError, "#{self.class} must implement #pick_secret"
  end

  def derive_public_key
    raise "Secret not set for #{name}" unless @secret
    @public_key = mod_expo(@base, @secret, @modulus)
  end

  def compute_shared_secret(peer_public)
    raise "Secret not set for #{name}" unless @secret
    mod_expo(peer_public, @secret, @modulus)
  end
end

# Concrete parties using secure random secrets
class PartyA < PartyBase
  def pick_secret
    @secret = 2 + SecureRandom.random_number(@modulus - 3)
  end
end

class PartyB < PartyBase
  def pick_secret
    @secret = 2 + SecureRandom.random_number(@modulus - 3)
  end
end

# Orchestrates a DH exchange between two parties
class DiffieHellmanSession
  attr_reader :modulus, :base, :party1, :party2, :shared_secret

  def initialize(modulus:, base:, party1_class: PartyA, party2_class: PartyB)
    @modulus = modulus
    @base = base
    @party1 = party1_class.new(name: "Party1", modulus: modulus, base: base)
    @party2 = party2_class.new(name: "Party2", modulus: modulus, base: base)
    @shared_secret = nil
  end

  def run
    # Step 1: each party picks a private secret
    @party1.pick_secret
    @party2.pick_secret

    # Step 2: compute public keys
    @party1.derive_public_key
    @party2.derive_public_key

    # Step 3: exchange publics and compute shared secret
    s1 = @party1.compute_shared_secret(@party2.public_key)
    s2 = @party2.compute_shared_secret(@party1.public_key)

    raise "Shared secrets do not match" unless s1 == s2
    @shared_secret = s1
  end
end

