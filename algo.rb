def mod_expo(base, exponent, mod)
  result = 1
  base %= modulus # Ensure base is within the modulus range from the start

  while exponent > 0
    # If exponent is odd, multiply result by current base and take modulo
    if exponent.odd?
      result = (result * base) % modulus
    end

    # Square the base and take modulo
    base = (base * base) % modulus
    
    # Divide the exponent by 2 (integer division)
    exponent /= 2
  end

  return result
end

# We need 2 parties to be instantiated. Parties must agree on a base number and a modulus. 
# They can be shared publicly. 
# Then party 1 must come up with a secret number to use to generate a number.
# Party 2 will come up with another secret number to also generate the number
# then party 1 and 2 will share their secret numbers to the other.
# then they will use that number to generate another number.
# that final number would be the same for both parties.
# Now that the secret has been shared across the two parties, the final number can be used as a handshake / encryption key etc .


