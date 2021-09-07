filename_regex = [
   # Databases
   "\.backup$",
   "\.bak$",
   "\.sql$",
   # Worksheets
   "\.csv$",
   "\.xlsx$",
   "\.xls$",
   # conf
   "\.conf$",
   "\.env$",
   "\.p12$",
   "\.pfx$",
   "\.pkcs12$",
   "\.pem$",
   "_rsa$",
   "_dsa$",
   "]_ed25519$",
   "_ecdsa$",
   "\.jks$",
   # bash/zsh rc file:
   "^\.?(bash|zsh)?rc$",
   # bash/zsh profile:
   "^\.?(bash|zsh)_profile$",
   # bash/zsh aliases file:
   "^\.?(bash|zsh)_aliases$",
   # credential(s) file:
   "^\.credential(s)?$",
   # Github Enterprise file:
   "^\.githubenterprise$",
   # Apple Keychain file:
   "^\.*keychain$",
   # Keystore/Keyring file:
   "^key(store|ring)$",
   # Keepass secret file
   "^\.*kdb",
]

pii_regex = {
   "'First name' found:": "*first name$",
   "'Last name' found:": "*last name$",
   "Email address": "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])",
}

