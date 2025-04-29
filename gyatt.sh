#!/bin/bash
# Usage: ./parse_secretsdump.sh <secretsdump_output.txt>

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <secretsdump_output.txt>"
  exit 1
fi

input="$1"

# Empty output files
> users.txt
> ntlm_hashes.txt
> cleartext_passwords.txt

while IFS= read -r line; do
  # SAM hashes (username:RID:LM:NT)
  if [[ "$line" =~ ^([a-zA-Z0-9\$\.\-]+):[0-9]+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}): ]]; then
    user="${BASH_REMATCH[1]}"
    lmhash="${BASH_REMATCH[2]}"
    nthash="${BASH_REMATCH[3]}"
    echo "$user" >> users.txt
    echo "$lmhash:$nthash" >> ntlm_hashes.txt
  fi

  # Cached credentials (DCC2 format)
  if [[ "$line" =~ ^([A-Z0-9]+)\\/([a-zA-Z0-9\.\-]+):\$DCC2.*#([a-zA-Z0-9\.\-]+)#([a-fA-F0-9]{32}): ]]; then
    user="${BASH_REMATCH[2]}"
    hash="${BASH_REMATCH[4]}"
    echo "$user" >> users.txt
    echo "$hash" >> ntlm_hashes.txt
  fi

  # Machine account hash format (LSA secrets)
  if [[ "$line" =~ ^.*:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}::: ]]; then
    lmhash=$(echo "$line" | cut -d ':' -f3)
    nthash=$(echo "$line" | cut -d ':' -f4)
    echo "$lmhash:$nthash" >> ntlm_hashes.txt
  fi

  # Cleartext passwords (username:password)
  if [[ "$line" =~ ^.*\\([a-zA-Z0-9\.\-]+):(.*)$ ]]; then
    password="${BASH_REMATCH[2]}"
    echo "$password" >> cleartext_passwords.txt
  fi

  # DefaultPassword (non-domain)
  if [[ "$line" =~ ^DefaultPassword[:\ ]+(.+)$ ]]; then
    password="${BASH_REMATCH[1]}"
    echo "$password" >> cleartext_passwords.txt
  fi

done < "$input"

# Deduplicate results
sort -u users.txt -o users.txt
sort -u ntlm_hashes.txt -o ntlm_hashes.txt
sort -u cleartext_passwords.txt -o cleartext_passwords.txt

echo "[+] users.txt"
echo "[+] ntlm_hashes.txt"
echo "[+] cleartext_passwords.txt"
