#compdef docseal

_docseal() {
  local -a commands
  commands=(
    "encrypt:encrypt a file"
    "decrypt:decrypt a file"
  )

  _arguments -C \
    "1:command:->cmds" \
    "*::arg:->args"

  case $state in
    cmds)
      _describe "command" commands
      ;;
    args)
      case $words[2] in
        encrypt)
          _arguments \
            "--out[output file path or directory]:path:_files" \
            "--force[overwrite output if exists]" \
            "--allow-large[allow files >200MB]" \
            "--password[password (discouraged)]:password:" \
            "--password-file[read password from a file]:file:_files" \
            "--keep-original[keep original after success]" \
            "--delete-original[delete original after success]" \
            "--i-understand[confirm original deletion]" \
            "--debug[show stack traces]" \
            "--algo[select AEAD algorithm]:algo:(auto xchacha20-poly1305 chacha20-poly1305 aes-256-gcm)" \
            "--kdf[select KDF]:kdf:(auto argon2id scrypt)" \
            "-h[show help]" \
            "--help[show help]"
          ;;
        decrypt)
          _arguments \
            "--out[output file path or directory]:path:_files" \
            "--force[overwrite output if exists]" \
            "--allow-large[allow files >200MB]" \
            "--password[password (discouraged)]:password:" \
            "--password-file[read password from a file]:file:_files" \
            "--keep-original[keep original after success]" \
            "--delete-original[delete original after success]" \
            "--i-understand[confirm original deletion]" \
            "--debug[show stack traces]" \
            "-h[show help]" \
            "--help[show help]"
          ;;
      esac
      ;;
  esac
}

_docseal
