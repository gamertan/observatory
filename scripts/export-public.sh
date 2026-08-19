#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
usage(){ echo "Usage: export-public.sh --destination ABSOLUTE-PATH" >&2; }
destination=
while [[ $# -gt 0 ]]; do
	case $1 in
	--destination) destination=$2; shift 2 ;;
	*) usage; exit 2 ;;
	esac
done
[[ $destination == /* && $destination != / && ! -e $destination ]] || { usage; exit 2; }
destination=$(realpath -m "$destination"); root=$(realpath -e "$root")
case $destination/ in "$root"/*) echo "destination must be outside the private worktree" >&2; exit 1;; esac
git_dir_raw=$(git -C "$root" rev-parse --git-dir)
common_dir_raw=$(git -C "$root" rev-parse --git-common-dir)
[[ $git_dir_raw == /* ]] || git_dir_raw=$root/$git_dir_raw
[[ $common_dir_raw == /* ]] || common_dir_raw=$root/$common_dir_raw
git_dir=$(realpath -e "$git_dir_raw")
common_dir=$(realpath -e "$common_dir_raw")
case $destination/ in "$git_dir"/*|"$common_dir"/*) echo "destination must be outside Git metadata" >&2; exit 1;; esac
[[ -z $(git -C "$root" status --porcelain=v1 --untracked-files=all) ]] || { echo "private worktree is not clean" >&2; exit 1; }
commit=$(git -C "$root" rev-parse HEAD)
tree=$(git -C "$root" rev-parse HEAD^{tree})
remote=$(git -C "$root" ls-remote --exit-code origin refs/heads/main | awk 'NR==1{print $1}')
[[ $remote == "$commit" ]] || { echo "private HEAD is not exact pushed origin/main" >&2; exit 1; }
allow=$root/scripts/public-snapshot.allow
LC_ALL=C sort -c "$allow"
[[ $(LC_ALL=C sort "$allow" | uniq -d | wc -l) -eq 0 ]]
mapfile -t files <"$allow"
[[ ${#files[@]} -gt 0 ]]
for file in "${files[@]}"; do
	[[ -n $file && $file != /* && $file != *..* && $file != .gitea/* && $file != .github/* ]]
	git -C "$root" cat-file -e "$commit:$file"
done
parent=$(dirname "$destination")
mkdir -p "$parent"
stage=$(mktemp -d "$parent/.observatory-public.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
git -C "$root" archive "$commit" -- "${files[@]}" | tar -xf - -C "$stage"
while IFS= read -r file; do
	relative=${file#"$stage"/}
	cmp "$file" "$root/$relative"
done < <(find "$stage" -type f -print | LC_ALL=C sort)
epoch=$(git -C "$root" show -s --format=%ct "$commit")
printf '{"schema_version":1,"source_commit":"%s","source_tree":"%s","source_date_epoch":%s,"file_count":%d}\n' "$commit" "$tree" "$epoch" "${#files[@]}" >"$stage/PUBLIC-SNAPSHOT.json"
(cd "$stage" && sha256sum PUBLIC-SNAPSHOT.json >PUBLIC-SNAPSHOT.sha256)
if (cd "$stage" && rg -n --hidden --glob '!.git/**' --glob '!PUBLIC-SNAPSHOT.json' --glob '!scripts/export-public.sh' '/home/cole|/tmp/gamertan-observatory-identity|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|gitea-api\.token|observatory-dev\.git|192\.168\.' .); then
	echo "private material found" >&2
	exit 1
fi
mv "$stage" "$destination"
trap - EXIT
printf 'destination=%s\nsource_commit=%s\nsource_tree=%s\n' "$destination" "$commit" "$tree"
