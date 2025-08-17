#!/usr/bin/env bash

while [[ "$#" != "0" ]]; do
  if [[ "$1" == "--" ]]; then
    shift
    break
  fi
  shift
done

if [[ -z "$1" ]]; then
  echo "Usage: $0 -- <command> [args...]"
  exit 1
fi

cmd="$(printf "%s" "$1" | xxd -ps)"
shift
for arg do
  cmd+=":$(printf "%s" "$arg" | xxd -ps)"
done

curl -N -s http://localhost:5567 -X POST -d "$cmd" | while IFS= read -r line; do
  if [[ "$line" =~ STDOUT:.* ]]; then
    printf "%s\n" "$(echo -n $line | sed 's/STDOUT://' | xxd -r -ps)"
  elif [[ "$line" =~ STDERR:.* ]]; then
    printf "%s\n" "$(echo -n $line | sed 's/STDERR://' | xxd -r -ps)" >&2
  elif [[ "$line" =~ CODE:.* ]]; then
    exit "$(echo -n $line | sed 's/CODE://' | xxd -r -ps)"
  fi
done
