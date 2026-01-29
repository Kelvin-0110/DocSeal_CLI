_docseal_completions() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  local commands="encrypt decrypt"
  local common_opts="--out --force --allow-large --password --password-file --keep-original --delete-original --i-understand --debug -h --help"
  local enc_opts="--algo --kdf"

  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${commands} -h --help" -- "$cur") )
    return 0
  fi

  local cmd="${COMP_WORDS[1]}"
  if [[ "$cmd" == "encrypt" ]]; then
    COMPREPLY=( $(compgen -W "${common_opts} ${enc_opts}" -- "$cur") )
  elif [[ "$cmd" == "decrypt" ]]; then
    COMPREPLY=( $(compgen -W "${common_opts}" -- "$cur") )
  else
    COMPREPLY=( $(compgen -W "${commands} ${common_opts}" -- "$cur") )
  fi
}

complete -F _docseal_completions docseal
