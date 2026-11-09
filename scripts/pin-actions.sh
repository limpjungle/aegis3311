#!/usr/bin/env bash
# Закрепляет action по SHA: pin-actions.sh owner/repo vX.Y.Z -> owner/repo@<40 hex> # vX.Y.Z
# Аннотированный тег разыменовывается до коммита. Только чтение (gh api GET); файлы не меняет.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "использование: $0 owner/repo vX.Y.Z" >&2
  exit 2
fi
r="$1"
t="$2"
if ! [[ "$r" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || ! [[ "$t" =~ ^v[0-9][A-Za-z0-9._-]*$ ]]; then
  echo "некорректный репозиторий или тег" >&2
  exit 2
fi

sha="$(gh api "repos/$r/git/ref/tags/$t" --jq .object.sha)"
typ="$(gh api "repos/$r/git/ref/tags/$t" --jq .object.type)"
if [ "$typ" = "tag" ]; then
  sha="$(gh api "repos/$r/git/tags/$sha" --jq .object.sha)"
fi
if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "не удалось получить SHA коммита" >&2
  exit 1
fi
echo "$r@$sha # $t"
